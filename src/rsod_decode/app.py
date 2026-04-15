"""Flask API for the RSOD debugger web UI.

Sessions persist via SQLite at `~/.rsod-debug/sessions.db`; the
in-memory `_sessions` dict acts as a hot cache. On cache miss,
`/api/session/<id>` hydrates from disk by re-running
`service.run_analysis` against the stored inputs.
"""
from __future__ import annotations

import io
import json
import shutil
import tempfile
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request, send_file
from werkzeug.utils import secure_filename


# Export/import bundle format version — bumped when metadata.json
# gains required fields that older importers don't know about.
BUNDLE_SCHEMA_VERSION = 1

# Hard cap on the total uncompressed size of a /api/import bundle.
# Primary guard against zip bombs. Set well above realistic symbol
# bundles (PE + PDB + rsod is ~10-40 MB) but far below a fork bomb.
BUNDLE_MAX_UNCOMPRESSED = 500 * 1024 * 1024  # 500 MiB

from . import data_dir as _data_dir, storage
from .models import SymbolSource, clean_path, binary_for_frame, find_source_file
from .corefile import write_corefile
from .gdb_bridge import GdbSession
from .pdb_routing import _pair_map_with_pe, _pop_pdb_for
from .serializers import (
    _RE_MEM_LOC, _build_frame_ctx, _var_to_dict,
    crash_info_to_dict, binary_for_session, frame_to_dict, registers_to_dict,
)
from .service import (
    AnalysisContext, advance_past_brace_line,
    reinit_backend as _service_reinit_backend,
    resolve_frame_vars, run_analysis,
)
from .session import (
    Session, delete_session as _delete_session,
    gdb_available, get_session, lldb_available,
    pop_session, store_session,
)
from .symbols import SymbolLoadError, is_pe, load_symbols


def _get_session(session_id: str) -> tuple[Session, None] | tuple[None, tuple]:
    """Look up a session, falling back to SQLite hydration on miss.

    Returns (session, None) on hit, (None, 404-response) otherwise.
    Hydration replays `service.run_analysis` against the stored
    inputs so permalinks and evicted sessions come back transparently.
    """
    session = get_session(session_id)
    if session is not None:
        return session, None
    app = _flask_app()
    try:
        session = _hydrate_session(app, session_id)
    except FileNotFoundError as e:
        return None, (jsonify(error=str(e)), 410)
    if session is None:
        return None, (jsonify(error='session not found'), 404)
    store_session(session)
    return session, None


def _flask_app() -> Flask:
    """Return the current Flask app (within request context)."""
    from flask import current_app
    return current_app._get_current_object()  # type: ignore[attr-defined]


# =============================================================================
# Shared upload / analysis / persistence pipeline
# =============================================================================

def _copy_uploads_to_disk(
    files_dir: Path, rsod_file, sym_file, extra_files: list,
) -> tuple[Path, list[Path], str]:
    """Copy a POST /api/session upload into `files_dir`.

    Returns (primary_path, extra_paths, rsod_text). Raises on I/O
    error — the caller is responsible for rolling back the directory.
    """
    files_dir.mkdir(parents=True, exist_ok=True)
    rsod_path = files_dir / 'rsod.txt'
    rsod_file.save(str(rsod_path))
    primary = files_dir / secure_filename(sym_file.filename or 'symbols')
    sym_file.save(str(primary))
    extras: list[Path] = []
    for f in extra_files:
        p = files_dir / secure_filename(f.filename or 'extra')
        f.save(str(p))
        extras.append(p)
    rsod_text = rsod_path.read_text(encoding='utf-8', errors='replace')
    return primary, extras, rsod_text


def _analyze_from_disk(
    app: Flask,
    *,
    rsod_text: str,
    primary_path: Path,
    extra_paths: list[Path],
    base_override: int | None,
    dwarf_prefix: str | None,
) -> tuple[AnalysisContext, Path | None, Path | None, list[Path]]:
    """Run symbol loading + analysis on already-persisted files.

    Returns `(ctx, companion_path, pdb_path, remaining_extras)`. The
    three path return values reflect how `_pair_map_with_pe` and
    `_pop_pdb_for` classified the input set, so the caller can
    persist a matching session_files row for each.
    """
    companion, remaining_extras = _pair_map_with_pe(primary_path, extra_paths)
    pe_for_pdb = companion if companion and is_pe(companion) else (
        primary_path if is_pe(primary_path) else None)
    pdb_path: Path | None = None
    if pe_for_pdb is not None:
        pdb_path, remaining_extras = _pop_pdb_for(
            pe_for_pdb.stem, remaining_extras)

    source = load_symbols(
        primary_path,
        dwarf_prefix=dwarf_prefix,
        repo_root=app.config.get('REPO_ROOT'),
        companion_path=companion,
        pdb_path=pdb_path if companion is None else None)

    extra_sources: dict[str, SymbolSource] = {}
    for p in remaining_extras:
        s = load_symbols(
            p, dwarf_prefix=dwarf_prefix,
            repo_root=app.config.get('REPO_ROOT'))
        extra_sources[p.stem.lower()] = s

    # NOTE: temp_dir is deliberately None. `evict_from_memory` wipes
    # `session.temp_dir` on eviction — setting it to the persistent
    # files dir here would nuke `~/.rsod-debug/files/<id>/` on LRU
    # rollover. Short-lived artifacts (GDB terminal corefile) get
    # their own `tempfile.mkdtemp()` in the WS handler on demand.
    ctx = run_analysis(
        rsod_text, source, extra_sources,
        base_override=base_override,
        symbol_search_paths=app.config.get('SYMBOL_SEARCH_PATHS'),
        temp_dir=None,
        elf_path=primary_path,
        pe_path=pe_for_pdb,
        pdb_path=pdb_path,
        backend='auto',
        source_roots=_source_search_roots(app),
    )
    return ctx, companion, pdb_path, remaining_extras


def persist_session(
    *,
    session_id: str,
    created_at: str,
    ctx: AnalysisContext,
    rsod_text: str,
    primary_path: Path,
    companion_path: Path | None,
    pdb_path: Path | None,
    remaining_extras: list[Path],
    base_override: int | None,
    dwarf_prefix: str | None,
    imported_from: str | None = None,
) -> None:
    """Insert one row + session_files entries for a freshly-uploaded session.

    Callers must have already copied the files into
    `data_dir.session_files_dir_for(session_id)` — only filenames
    (basenames relative to that dir) are stored in `session_files`.
    Used by both the HTTP upload handler and the CLI pre-load path.
    `imported_from` is set by POST /api/import to preserve the
    original session id from the bundle as provenance.
    """
    ci = ctx.result.crash_info
    files: list[storage.FileEntry] = [
        storage.FileEntry(
            filename=primary_path.name, file_type='primary',
            rel_path=primary_path.name),
    ]
    if companion_path is not None:
        files.append(storage.FileEntry(
            filename=companion_path.name, file_type='companion',
            rel_path=companion_path.name))
    if pdb_path is not None:
        files.append(storage.FileEntry(
            filename=pdb_path.name, file_type='pdb',
            rel_path=pdb_path.name))
    for p in remaining_extras:
        files.append(storage.FileEntry(
            filename=p.name, file_type='extra', rel_path=p.name))

    image_name = ci.image_name or primary_path.stem
    storage.save_session(
        session_id=session_id,
        created_at=created_at,
        rsod_text=rsod_text,
        rsod_format=ctx.result.rsod_format or '',
        image_name=image_name,
        image_base=ctx.image_base,
        exception_desc=ci.exception_desc or '',
        crash_pc=ci.crash_pc,
        crash_symbol=ci.crash_symbol or '',
        frame_count=len(ctx.result.frames),
        backend=ctx.backend,
        base_override=base_override,
        dwarf_prefix=dwarf_prefix,
        files=files,
        imported_from=imported_from,
    )


class _BundleError(ValueError):
    """Raised on a malformed or unsafe /api/import upload."""


def _extract_bundle(stream, files_dir: Path) -> dict:
    """Unpack an /api/import zip into `files_dir`, returning metadata.

    Safety guards (applied BEFORE any disk write):
    - Members must be regular files — reject dirs, symlinks, devices
      (zipfile's external_attr upper bits expose the POSIX mode).
    - Member names must be flat basenames — no directory separators,
      no absolute paths, no `..` traversal, no empty/control chars.
    - Total uncompressed size is capped at BUNDLE_MAX_UNCOMPRESSED to
      shut down zip-bomb amplification before the extract loop runs.
    - metadata.json must be present and parse as a dict with an
      integer `schema_version` this server understands.
    """
    files_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(stream) as zf:
        infos = zf.infolist()
        total = 0
        for info in infos:
            name = info.filename
            if not name or name != name.strip():
                raise _BundleError(f'suspicious member name: {name!r}')
            if name.endswith('/') or info.is_dir():
                raise _BundleError(f'bundles must be flat (got dir: {name})')
            # Reject anything that isn't a bare basename.
            if '/' in name or '\\' in name or name in ('.', '..') \
                    or Path(name).is_absolute():
                raise _BundleError(f'unsafe path in bundle: {name!r}')
            # Symlink detection via POSIX mode bits in external_attr.
            mode = (info.external_attr >> 16) & 0xF000
            if mode == 0xA000:  # S_IFLNK
                raise _BundleError(f'symlink not allowed in bundle: {name}')
            if info.file_size < 0:
                raise _BundleError(f'negative size: {name}')
            total += info.file_size
            if total > BUNDLE_MAX_UNCOMPRESSED:
                raise _BundleError(
                    f'bundle exceeds {BUNDLE_MAX_UNCOMPRESSED // (1024 * 1024)} '
                    'MiB uncompressed cap')

        metadata_raw: bytes | None = None
        for info in infos:
            dst = files_dir / info.filename
            with zf.open(info) as src_fp, dst.open('wb') as dst_fp:
                shutil.copyfileobj(src_fp, dst_fp)
            if info.filename == 'metadata.json':
                metadata_raw = dst.read_bytes()

    if metadata_raw is None:
        raise _BundleError('bundle missing metadata.json')
    try:
        metadata = json.loads(metadata_raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise _BundleError(f'metadata.json not valid JSON: {e}') from e
    if not isinstance(metadata, dict):
        raise _BundleError('metadata.json must be a JSON object')
    schema = metadata.get('schema_version')
    if not isinstance(schema, int):
        raise _BundleError('metadata.json missing integer schema_version')
    if schema > BUNDLE_SCHEMA_VERSION:
        raise _BundleError(
            f'bundle schema_version {schema} newer than supported '
            f'{BUNDLE_SCHEMA_VERSION}')
    return metadata


def _staging_dir() -> Path:
    """Return a fresh scratch dir for in-flight uploads.

    Uploads land here first so we can compute the content hash — and
    thus the canonical session id — before choosing a final location.
    Staging dirs live under `files/.staging/` so the top level of
    `files/` contains only real session ids.
    """
    root = _data_dir.session_files_dir() / '.staging'
    root.mkdir(parents=True, exist_ok=True)
    d = root / uuid.uuid4().hex
    return d


def _try_resolve_existing(app: Flask, session_id: str) -> Session | None:
    """Return the live Session for `session_id` if it's healthy on disk.

    Used by the dedup fast path in /api/session and /api/import: if
    the content hash already has a DB row AND a files dir AND
    hydration still works, the caller discards its fresh copy and
    returns the existing session. Any one of those checks failing
    falls through to the fresh-upload path.
    """
    files_dir = _data_dir.session_files_dir_for(session_id)
    if not storage.session_exists(session_id) or not files_dir.exists():
        return None
    existing = get_session(session_id)
    if existing is not None:
        return existing
    try:
        existing = _hydrate_session(app, session_id)
    except FileNotFoundError:
        return None
    if existing is not None:
        store_session(existing)
    return existing


def _promote_staging(
    staging_dir: Path, session_id: str,
) -> Path:
    """Rename `staging_dir` to its content-hash final location.

    Cleans up stale fragments (orphan DB row, orphan files dir) before
    the rename so the move is always into an empty slot. Returns the
    final dir. Caller must handle rollback on any exception raised
    AFTER this function returns — by the time we're done, the staging
    dir is gone.
    """
    storage.delete_session(session_id)  # no-op when absent
    final_dir = _data_dir.session_files_dir_for(session_id)
    if final_dir.exists():
        shutil.rmtree(final_dir)
    staging_dir.rename(final_dir)
    return final_dir


def _hydrate_session(app: Flask, session_id: str) -> Session | None:
    """Reconstruct a Session from SQLite + on-disk files.

    Returns None if no row exists. Raises `FileNotFoundError` if the
    row exists but the files dir has been partially removed out of
    band.
    """
    inputs = storage.hydrate_inputs(session_id)
    if inputs is None:
        return None

    extras = list(inputs.extra_paths)
    # hydrate_inputs already split companion/pdb; rebuild the flat list
    # that _analyze_from_disk re-classifies — it's idempotent because
    # the classifier is a pure function of the file names.
    if inputs.companion_path is not None:
        extras.append(inputs.companion_path)
    if inputs.pdb_path is not None:
        extras.append(inputs.pdb_path)

    ctx, _, _, _ = _analyze_from_disk(
        app,
        rsod_text=inputs.rsod_text,
        primary_path=inputs.primary_path,
        extra_paths=extras,
        base_override=inputs.base_override,
        dwarf_prefix=inputs.dwarf_prefix or app.config.get('DWARF_PREFIX'),
    )
    return Session.from_analysis_context(
        ctx, session_id, created_at=inputs.created_at)


def _source_search_roots(app: Flask) -> list[Path]:
    """Return the ordered list of source-tree roots to feed to
    `find_source_file` / `advance_past_brace_line`. Mirrors the
    order used by `/api/source`: REPO_ROOT first, then each
    `--source-path` the operator configured.
    """
    roots: list[Path] = []
    repo_root = app.config.get('REPO_ROOT')
    if repo_root is not None:
        roots.append(repo_root)
    roots.extend(app.config.get('SOURCE_PATHS') or [])
    return roots


# =============================================================================
# Flask app factory
# =============================================================================

def create_app(repo_root: Path | None = None,
               dwarf_prefix: str | None = None,
               symbol_search_paths: list[Path] | None = None,
               source_paths: list[Path] | None = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB
    app.config['REPO_ROOT'] = repo_root
    app.config['DWARF_PREFIX'] = dwarf_prefix
    app.config['SYMBOL_SEARCH_PATHS'] = symbol_search_paths
    app.config['SOURCE_PATHS'] = source_paths or []

    # Initialize persistent session store. Idempotent: creates
    # ~/.rsod-debug/sessions.db (or $RSOD_DATA_DIR) on first run,
    # runs migrations on subsequent runs.
    storage.init_db()

    # -----------------------------------------------------------------
    # POST /api/session — upload RSOD + symbols, create session
    # -----------------------------------------------------------------
    @app.post('/api/session')
    def create_session():
        if 'rsod_log' not in request.files:
            return jsonify(error='rsod_log file required'), 400
        if 'symbol_file' not in request.files:
            return jsonify(error='symbol_file required'), 400

        base_override: int | None = None
        base_str = request.form.get('base')
        if base_str:
            try:
                base_override = int(base_str, 16)
            except ValueError:
                return jsonify(error=f'invalid base address: {base_str}'), 400

        # Stage uploads first so we can compute the content hash and
        # the final session id. Dedup happens BEFORE we waste work
        # re-running run_analysis on inputs we've already persisted.
        staging_dir = _staging_dir()
        try:
            primary_path, extra_paths, rsod_text = _copy_uploads_to_disk(
                staging_dir,
                request.files['rsod_log'],
                request.files['symbol_file'],
                request.files.getlist('extra_symbols[]'),
            )
        except OSError as e:
            shutil.rmtree(staging_dir, ignore_errors=True)
            return jsonify(error=f'upload failed: {e}'), 500

        session_id = storage.compute_session_id(staging_dir)

        # Dedup fast path: same content hash as an existing healthy
        # session → discard staging, return the existing session.
        existing = _try_resolve_existing(app, session_id)
        if existing is not None:
            shutil.rmtree(staging_dir, ignore_errors=True)
            return jsonify(
                session_id=session_id,
                crash_summary=crash_info_to_dict(existing.result.crash_info),
                frame_count=len(existing.result.frames),
                deduplicated=True,
            ), 200

        # Fresh session — promote staging to the canonical files dir.
        try:
            files_dir = _promote_staging(staging_dir, session_id)
        except OSError as e:
            shutil.rmtree(staging_dir, ignore_errors=True)
            # Rename race with a concurrent upload of identical
            # content: the other request won, dedup-resolve instead.
            existing = _try_resolve_existing(app, session_id)
            if existing is not None:
                return jsonify(
                    session_id=session_id,
                    crash_summary=crash_info_to_dict(existing.result.crash_info),
                    frame_count=len(existing.result.frames),
                    deduplicated=True,
                ), 200
            return jsonify(error=f'promote failed: {e}'), 500

        # Paths in staging_dir became invalid on rename — rebuild.
        primary_path = files_dir / primary_path.name
        extra_paths = [files_dir / p.name for p in extra_paths]

        def _rollback() -> None:
            shutil.rmtree(files_dir, ignore_errors=True)

        try:
            ctx, companion, pdb_path, remaining_extras = _analyze_from_disk(
                app,
                rsod_text=rsod_text,
                primary_path=primary_path,
                extra_paths=extra_paths,
                base_override=base_override,
                dwarf_prefix=app.config.get('DWARF_PREFIX'),
            )
        except SymbolLoadError as e:
            _rollback()
            return jsonify(error=str(e)), 400
        except Exception:
            _rollback()
            raise

        created_at = datetime.now(timezone.utc).isoformat()
        try:
            persist_session(
                session_id=session_id, created_at=created_at, ctx=ctx,
                rsod_text=rsod_text,
                primary_path=primary_path, companion_path=companion,
                pdb_path=pdb_path, remaining_extras=remaining_extras,
                base_override=base_override,
                dwarf_prefix=app.config.get('DWARF_PREFIX'),
            )
        except Exception:
            _rollback()
            raise

        session = Session.from_analysis_context(
            ctx, session_id, created_at=created_at)
        store_session(session)

        return jsonify(
            session_id=session_id,
            crash_summary=crash_info_to_dict(ctx.result.crash_info),
            frame_count=len(ctx.result.frames),
        ), 201

    # -----------------------------------------------------------------
    # GET /api/session/<id> — get crash summary + frames + registers
    # -----------------------------------------------------------------
    @app.get('/api/session/<session_id>')
    def get_session_route(session_id: str):
        session, err = _get_session(session_id)
        if err:
            return err
        r = session.result
        return jsonify(
            crash_summary=crash_info_to_dict(r.crash_info),
            frames=[frame_to_dict(f) for f in r.frames],
            registers=registers_to_dict(r.crash_info.registers),
            v_registers=r.crash_info.v_registers,
            format=r.rsod_format,
            call_verified={str(k): v for k, v in r.call_verified.items()},
            rsod_text=session.rsod_text,
            backend=session.backend,
            # gdb_available reflects per-session usability: GDB is
            # ELF-only so a PE-based session (pe_path set) reports
            # False even when gdb is installed globally.
            gdb_available=gdb_available() and session.pe_path is None,
            lldb_available=lldb_available(),
            modules=r.modules,
            lbr=r.crash_info.lbr,
        )

    # -----------------------------------------------------------------
    # GET /api/frame/<session_id>/<frame_index> — params + locals
    # -----------------------------------------------------------------
    @app.get('/api/frame/<session_id>/<int:frame_index>')
    def get_frame(session_id: str, frame_index: int):
        session, err = _get_session(session_id)
        if err:
            return err
        if frame_index < 0 or frame_index >= len(session.result.frames):
            return jsonify(error='frame index out of range'), 404

        # Return cached response (static crash data never changes)
        if frame_index in session.frame_cache:
            return jsonify(session.frame_cache[frame_index])

        frame = session.result.frames[frame_index]
        result: dict = frame_to_dict(frame)

        # Shared pipeline: raw params/locals/globals from the active
        # backend, with tail-call recovered values merged at the
        # VarInfo level. `service.resolve_frame_vars` owns all the
        # backend-selection + merge + globals-evaluation logic that
        # used to live inline here.
        params, locals_, globals_ = resolve_frame_vars(
            session.as_analysis_context(), frame_index)

        img_base = session.img_base
        ctx = _build_frame_ctx(frame, session, img_base)
        result['params'] = [_var_to_dict(v, ctx) for v in params]
        result['locals'] = [_var_to_dict(v, ctx) for v in locals_]
        result['globals'] = [_var_to_dict(v, ctx) for v in globals_]

        # Infer unresolved params from ancestor frames (pyelftools only).
        # GDB/LLDB backends resolve entry_values themselves, so skip the
        # cross-frame walk when a richer backend is active. This remains
        # web-only because the CLI doesn't render the drill-down that
        # this fallback improves.
        if session.backend not in ('gdb', 'lldb') \
                and not frame.is_synthetic and frame.address:
            for p in result['params']:
                if p['value'] is not None:
                    continue
                if _RE_MEM_LOC.match(p['location']):
                    continue
                for anc_idx in range(frame_index + 1,
                                     len(session.result.frames)):
                    anc = session.result.frames[anc_idx]
                    anc_binary = binary_for_frame(
                        anc, session.source, session.extra_sources)
                    if not anc_binary or not anc.address:
                        continue
                    anc_pc = anc.address
                    if not anc.is_crash_frame and anc.call_addr:
                        anc_pc = anc.call_addr - 1
                    anc_ctx = _build_frame_ctx(anc, session, img_base)
                    for var in (*anc_binary.get_params(anc_pc),
                                *anc_binary.get_locals(anc_pc)):
                        if var.name != p['name']:
                            continue
                        d = _var_to_dict(var, anc_ctx)
                        if d['value'] is None:
                            continue
                        p['value'] = d['value']
                        if p['is_expandable'] and p['expand_addr'] is None:
                            p['expand_addr'] = d['value']
                        break
                    if p['value'] is not None:
                        break

        result['call_verified'] = session.result.call_verified.get(frame.address)
        if frame.frame_registers:
            result['frame_registers'] = registers_to_dict(frame.frame_registers)
        session.frame_cache[frame_index] = result
        return jsonify(result)

    # -----------------------------------------------------------------
    # GET /api/expand/<session_id>/<frame_index> — expand variable type
    # -----------------------------------------------------------------
    @app.get('/api/expand/<session_id>/<int:frame_index>')
    def expand_var(session_id: str, frame_index: int):
        session, err = _get_session(session_id)
        if err:
            return err
        if frame_index < 0 or frame_index >= len(session.result.frames):
            return jsonify(error='frame index out of range'), 404

        addr = request.args.get('addr', type=lambda x: int(x, 16))
        type_offset = request.args.get('type_offset', type=int)
        cu_offset = request.args.get('cu_offset', type=int)
        var_key = request.args.get('var_key', type=str, default='')
        if addr is None or (not var_key and (type_offset is None or cu_offset is None)):
            return jsonify(error='addr required, plus type_offset+cu_offset or var_key'), 400
        offset = request.args.get('offset', default=0, type=int)
        count = request.args.get('count', default=32, type=int)

        frame = session.result.frames[frame_index]
        binary = binary_for_session(session, frame)
        if not binary:
            return jsonify(fields=[], total_count=0)

        # GDB backend: use var_key for expansion
        if var_key:
            fields, total_count = binary.expand_type(
                var_key, addr,
                session.result.stack_base, session.result.stack_mem,
                session.img_base, offset, count)
            return jsonify(fields=fields, total_count=total_count)

        # pyelftools backend: use type DIE
        type_die = binary.get_type_die(cu_offset, type_offset)
        if not type_die:
            return jsonify(fields=[], total_count=0)

        fields, total_count = binary.expand_type(
            type_die, addr,
            session.result.stack_base, session.result.stack_mem,
            session.img_base, offset, count)
        return jsonify(fields=fields, total_count=total_count)

    # -----------------------------------------------------------------
    # GET /api/memory/<session_id> — raw memory read (hex dump)
    # -----------------------------------------------------------------
    @app.get('/api/memory/<session_id>')
    def get_memory(session_id: str):
        session, err = _get_session(session_id)
        if err:
            return err

        addr = request.args.get('addr', type=lambda x: int(x, 16))
        size = min(request.args.get('size', default=256, type=int), 4096)
        if addr is None:
            return jsonify(error='addr required'), 400

        # Pick a backend for memory reads (frame-independent)
        binary = None
        if session.backend == 'lldb' and session.lldb_dwarf:
            binary = session.lldb_dwarf
        elif session.backend == 'gdb' and session.gdb_dwarf:
            binary = session.gdb_dwarf
        elif session.source.binary:
            binary = session.source.binary
        if not binary:
            return jsonify(address=addr, bytes=[])

        sb = session.result.stack_base
        sm = session.result.stack_mem
        ib = session.img_base

        # GDB backend: use read_memory_partial for per-byte N/A handling
        if hasattr(binary, 'read_memory_partial'):
            result_bytes = binary.read_memory_partial(addr, size, sb, sm, ib)
            return jsonify(address=addr, bytes=result_bytes)

        # pyelftools: try full-block read first
        data = binary.read_memory(addr, size, sb, sm, ib)
        if data is not None:
            return jsonify(address=addr, bytes=list(data))

        # Fall back to 16-byte chunk reads for boundary cases
        result_bytes: list[int | None] = []
        for off in range(0, size, 16):
            chunk_size = min(16, size - off)
            chunk = binary.read_memory(addr + off, chunk_size, sb, sm, ib)
            if chunk:
                result_bytes.extend(chunk)
            else:
                result_bytes.extend([None] * chunk_size)

        return jsonify(address=addr, bytes=result_bytes)

    # -----------------------------------------------------------------
    # POST /api/eval/<session_id>/<frame_index> — evaluate expression
    # -----------------------------------------------------------------
    @app.post('/api/eval/<session_id>/<int:frame_index>')
    def eval_expression(session_id: str, frame_index: int):
        session, err = _get_session(session_id)
        if err:
            return err
        if frame_index < 0 or frame_index >= len(session.result.frames):
            return jsonify(error='frame index out of range'), 404

        if session.backend not in ('gdb', 'lldb'):
            return jsonify(
                error='Expression evaluation requires GDB or LLDB backend'), 400

        data = request.get_json(silent=True) or {}
        expr = data.get('expr', '').strip()
        if not expr:
            return jsonify(error='expr required'), 400

        frame = session.result.frames[frame_index]
        if session.backend == 'lldb' and session.lldb_dwarf:
            from .lldb_backend import LldbBackend
            if isinstance(session.lldb_dwarf, LldbBackend):
                result = session.lldb_dwarf.evaluate_expression(
                    frame.address, expr)
                return jsonify(result)
        if session.backend == 'gdb' and session.gdb_dwarf:
            from .gdb_backend import GdbBackend
            if isinstance(session.gdb_dwarf, GdbBackend):
                result = session.gdb_dwarf.evaluate_expression(
                    frame.address, expr)
                return jsonify(result)

        return jsonify(error='Backend not available'), 400

    # -----------------------------------------------------------------
    # GET /api/regions/<session_id> — known memory regions
    # -----------------------------------------------------------------
    @app.get('/api/regions/<session_id>')
    def get_regions(session_id: str):
        session, err = _get_session(session_id)
        if err:
            return err

        regions: list[dict] = []
        sb = session.result.stack_base
        sm = session.result.stack_mem
        if sm:
            regions.append({
                'name': 'Stack dump',
                'start': sb,
                'size': len(sm),
            })

        # Binary sections at runtime addresses (ELF/DWARF or PE)
        ib = session.img_base
        if session.source.binary:
            for sec_addr, sec_data in session.source.binary._sections:
                rt_start = sec_addr + ib
                regions.append({
                    'name': session.source.binary._section_names.get(
                        sec_addr, f'0x{sec_addr:X}'),
                    'start': rt_start,
                    'size': len(sec_data),
                })

        regions.sort(key=lambda r: r['start'])
        return jsonify(regions=regions)

    # -----------------------------------------------------------------
    # GET /api/disasm/<session_id>/<frame_index> — disassembly
    # -----------------------------------------------------------------
    @app.get('/api/disasm/<session_id>/<int:frame_index>')
    def get_disasm(session_id: str, frame_index: int):
        session, err = _get_session(session_id)
        if err:
            return err
        if frame_index < 0 or frame_index >= len(session.result.frames):
            return jsonify(error='frame index out of range'), 404

        frame = session.result.frames[frame_index]
        binary = binary_for_session(session, frame)
        # For crash / synthetic frames, highlight `frame.address`
        # directly — it's the faulting PC (crash frame) or the
        # tail-call jmp (synthetic frame) and in both cases the
        # user wants to see THAT instruction. For non-crash frames
        # `frame.address` is the return address (instruction AFTER
        # the call) and highlighting it gives a confusing "we're
        # in the function epilogue / closing brace" picture. Ask
        # the richer backend to find the CALL instruction whose
        # return address matches, and highlight that instead — it
        # lines up with what the Source tab shows (the call site).
        target_addr = frame.address or frame.call_addr
        if (binary is not None and frame.address
                and not frame.is_crash_frame and not frame.is_synthetic):
            from .lldb_backend import LldbBackend
            if isinstance(binary, LldbBackend):
                call_site = binary.call_site_addr_for_return(frame.address)
                if call_site is not None:
                    target_addr = call_site
        if not binary or not target_addr:
            return jsonify(instructions=[])

        context = min(request.args.get('context', 24, type=int), 200)
        insns = binary.disassemble_around(target_addr, context)
        src_map = binary.source_lines_for_addrs([a for a, _, _ in insns])

        # Normalize per-instruction source annotations so the
        # Disasm tab's grey line-header text matches whatever the
        # Source tab is highlighting. Without this step an
        # instruction sitting at the function entry would show
        # "psaentry.c:272" (the `{`) while the Source tab shows
        # line 273 (the first real statement) — the exact drift
        # the regression tests now pin against.
        roots = _source_search_roots(app)
        if roots:
            advance_cache: dict[str, str] = {}

            def _advance(src: str) -> str:
                if not src:
                    return src
                cached = advance_cache.get(src)
                if cached is not None:
                    return cached
                adjusted = advance_past_brace_line(src, roots)
                advance_cache[src] = adjusted
                return adjusted

            src_map = {a: _advance(s) for a, s in src_map.items()}

        instructions = []
        for addr, mnemonic, op_str in insns:
            instructions.append({
                'address': addr,
                'mnemonic': mnemonic,
                'op_str': op_str,
                'is_target': addr == target_addr,
                'source_line': src_map.get(addr, ''),
            })
        return jsonify(instructions=instructions)

    # -----------------------------------------------------------------
    # GET /api/source/<session_id>/<frame_index> — source context
    # -----------------------------------------------------------------
    @app.get('/api/source/<session_id>/<int:frame_index>')
    def get_source(session_id: str, frame_index: int):
        session, err = _get_session(session_id)
        if err:
            return err
        if frame_index < 0 or frame_index >= len(session.result.frames):
            return jsonify(error='frame index out of range'), 404

        frame = session.result.frames[frame_index]
        if not frame.source_loc or ':' not in frame.source_loc:
            return jsonify(file='', target_line=0, lines=[])

        file_part, line_part = frame.source_loc.rsplit(':', 1)
        try:
            target_line = int(line_part)
        except ValueError:
            return jsonify(file='', target_line=0, lines=[])

        context = min(request.args.get('context', 5, type=int), 50)

        # Direct path lookup: try absolute path first (common for Linux
        # builds where DWARF holds real on-disk paths), then fall back
        # to multi-root filename search. The search order is the
        # server's REPO_ROOT followed by every `--source-path` the
        # operator configured — this is how out-of-tree checkouts
        # like axl-sdk or the Dell EPSA source mirror get picked up.
        abs_path = Path(file_part)
        if abs_path.is_absolute() and abs_path.is_file():
            src_path = abs_path
        else:
            roots: list[Path] = []
            repo_root = (app.config['REPO_ROOT']
                         or Path(__file__).resolve().parents[2])
            if repo_root is not None:
                roots.append(repo_root)
            roots.extend(app.config.get('SOURCE_PATHS') or [])
            src_path = find_source_file(roots, file_part, target_line)
        if not src_path:
            return jsonify(file=file_part, target_line=target_line, lines=[])

        try:
            all_lines = src_path.read_text(
                encoding='utf-8', errors='replace').splitlines()
        except OSError:
            return jsonify(file=file_part, target_line=target_line, lines=[])

        start = max(0, target_line - context - 1)
        end = min(len(all_lines), target_line + context)

        result_lines = []
        for i in range(start, end):
            lineno = i + 1
            result_lines.append({
                'number': lineno,
                'text': all_lines[i],
                'is_target': lineno == target_line,
            })
        return jsonify(
            file=file_part,
            target_line=target_line,
            lines=result_lines,
        )

    # -----------------------------------------------------------------
    # POST /api/resolve/<session_id> — resolve arbitrary address
    # -----------------------------------------------------------------
    @app.post('/api/resolve/<session_id>')
    def resolve_address(session_id: str):
        session, err = _get_session(session_id)
        if err:
            return err

        data = request.get_json(silent=True) or {}
        addr_str = data.get('address', '')
        try:
            addr = int(addr_str, 16) if isinstance(addr_str, str) else int(addr_str)
        except (ValueError, TypeError):
            return jsonify(error=f'invalid address: {addr_str}'), 400

        table = session.source.table
        result = table.lookup(addr)
        if not result:
            return jsonify(error='address not in image'), 404

        sym, offset = result
        response: dict = {
            'symbol': sym.name,
            'offset': offset,
            'object_file': sym.object_file,
            'is_function': sym.is_function,
        }

        # Source location from DWARF (if available)
        binary = session.source.binary
        if binary:
            addr_info = binary.resolve_address(addr)
            if addr_info:
                response['source_loc'] = clean_path(addr_info.source_loc) if addr_info.source_loc else ''
                response['function'] = addr_info.function

        return jsonify(response)

    # -----------------------------------------------------------------
    # POST /api/backend/<session_id> — switch DWARF backend
    # -----------------------------------------------------------------
    @app.post('/api/backend/<session_id>')
    def switch_backend(session_id: str):
        session, err = _get_session(session_id)
        if err:
            return err

        data = request.get_json(silent=True) or {}
        target = data.get('backend', '')

        ctx = session.as_analysis_context()
        fail = _service_reinit_backend(
            ctx, target, source_roots=_source_search_roots(app))
        if fail:
            return jsonify(error=fail), 400

        # Sync mutated fields back to the session.
        session.lldb_dwarf = ctx.lldb_backend
        session.gdb_dwarf = ctx.gdb_backend
        session.backend = ctx.backend
        session.frame_cache.clear()
        return jsonify(backend=session.backend)

    # -----------------------------------------------------------------
    # GET /api/history — list recent sessions (SQLite-backed)
    # -----------------------------------------------------------------
    @app.get('/api/history')
    def get_history():
        limit = min(request.args.get('limit', default=100, type=int), 500)
        before = request.args.get('before', type=str)
        rows = storage.list_sessions(limit=limit, before=before)
        return jsonify(sessions=[{
            'id': r.id,
            'created_at': r.created_at,
            'image_name': r.image_name,
            'exception_desc': r.exception_desc,
            'crash_pc': r.crash_pc,
            'crash_symbol': r.crash_symbol,
            'frame_count': r.frame_count,
            'backend': r.backend,
            'imported_from': r.imported_from,
        } for r in rows])

    # -----------------------------------------------------------------
    # GET /api/export/<id> — download a session bundle (.rsod.zip)
    # -----------------------------------------------------------------
    @app.get('/api/export/<session_id>')
    def export_session(session_id: str):
        inputs = storage.hydrate_inputs(session_id)
        if inputs is None:
            return jsonify(error='session not found'), 404

        files_dir = _data_dir.session_files_dir_for(session_id)
        metadata = {
            'schema_version': BUNDLE_SCHEMA_VERSION,
            'session_id': session_id,
            'created_at': inputs.created_at,
            'rsod_filename': 'rsod.txt',
            'primary_filename': inputs.primary_path.name,
            'companion_filename': (
                inputs.companion_path.name if inputs.companion_path else None),
            'pdb_filename': (
                inputs.pdb_path.name if inputs.pdb_path else None),
            'extra_filenames': [p.name for p in inputs.extra_paths],
            'base_override': inputs.base_override,
            'dwarf_prefix': inputs.dwarf_prefix,
        }

        buf = io.BytesIO()
        with zipfile.ZipFile(
            buf, 'w', compression=zipfile.ZIP_DEFLATED,
        ) as zf:
            zf.writestr(
                'metadata.json',
                json.dumps(metadata, indent=2, sort_keys=True))
            # Every file in the session's files dir goes into the
            # bundle verbatim — including rsod.txt read from disk, so
            # the raw bytes survive the round trip. Re-encoding from
            # inputs.rsod_text would lose any non-UTF-8 sequences in
            # the original capture and change the content hash on
            # import. rel_path is always a flat basename under
            # files_dir (the upload path never creates subdirs).
            for item in files_dir.iterdir():
                if not item.is_file():
                    continue
                zf.write(item, arcname=item.name)
        buf.seek(0)

        date_part = (inputs.created_at or '').split('T', 1)[0] or 'unknown'
        short_id = session_id[:8]
        filename = f'crash-{date_part}-{short_id}.rsod.zip'
        return send_file(
            buf, mimetype='application/zip',
            as_attachment=True, download_name=filename)

    # -----------------------------------------------------------------
    # POST /api/import — unpack a bundle, create a new session
    # -----------------------------------------------------------------
    @app.post('/api/import')
    def import_session():
        upload = request.files.get('file')
        if upload is None:
            return jsonify(error='file upload (zip bundle) required'), 400

        # Extract into staging, hash, then either dedup or promote.
        # Same pattern as /api/session, different source of files.
        staging_dir = _staging_dir()
        try:
            metadata = _extract_bundle(upload.stream, staging_dir)
        except _BundleError as e:
            shutil.rmtree(staging_dir, ignore_errors=True)
            return jsonify(error=str(e)), 400
        except zipfile.BadZipFile:
            shutil.rmtree(staging_dir, ignore_errors=True)
            return jsonify(error='not a valid zip archive'), 400
        except OSError as e:
            shutil.rmtree(staging_dir, ignore_errors=True)
            return jsonify(error=f'bundle extraction failed: {e}'), 500

        if not (staging_dir / 'rsod.txt').exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
            return jsonify(error='bundle missing rsod.txt'), 400
        primary_name = metadata.get('primary_filename') or ''
        if not primary_name or not (staging_dir / primary_name).exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
            return jsonify(
                error=f'bundle missing primary symbol file {primary_name!r}'), 400

        # Drop metadata.json BEFORE hashing — it's not part of the
        # canonical input set, and keeping it in the hash would make
        # the id depend on who exported the bundle (created_at,
        # metadata schema_version, etc.) instead of on the crash
        # inputs themselves.
        try:
            (staging_dir / 'metadata.json').unlink()
        except FileNotFoundError:
            pass

        session_id = storage.compute_session_id(staging_dir)
        bundle_original_id = metadata.get('session_id')

        existing = _try_resolve_existing(app, session_id)
        if existing is not None:
            shutil.rmtree(staging_dir, ignore_errors=True)
            return jsonify(
                session_id=session_id,
                imported_from=bundle_original_id,
                crash_summary=crash_info_to_dict(existing.result.crash_info),
                frame_count=len(existing.result.frames),
                deduplicated=True,
            ), 200

        try:
            files_dir = _promote_staging(staging_dir, session_id)
        except OSError as e:
            shutil.rmtree(staging_dir, ignore_errors=True)
            return jsonify(error=f'promote failed: {e}'), 500

        def _rollback() -> None:
            shutil.rmtree(files_dir, ignore_errors=True)

        # Reconstruct the "extras" list _analyze_from_disk expects.
        primary_path = files_dir / primary_name
        extras: list[Path] = []
        for name_field in ('companion_filename', 'pdb_filename'):
            name = metadata.get(name_field)
            if name:
                p = files_dir / name
                if not p.exists():
                    _rollback()
                    return jsonify(error=f'bundle missing {name}'), 400
                extras.append(p)
        for name in metadata.get('extra_filenames') or []:
            p = files_dir / name
            if not p.exists():
                _rollback()
                return jsonify(error=f'bundle missing {name}'), 400
            extras.append(p)

        rsod_text = (files_dir / 'rsod.txt').read_text(
            encoding='utf-8', errors='replace')

        try:
            ctx, companion, pdb_path, remaining_extras = _analyze_from_disk(
                app,
                rsod_text=rsod_text,
                primary_path=primary_path,
                extra_paths=extras,
                base_override=metadata.get('base_override'),
                dwarf_prefix=metadata.get('dwarf_prefix')
                    or app.config.get('DWARF_PREFIX'),
            )
        except SymbolLoadError as e:
            _rollback()
            return jsonify(error=str(e)), 400
        except Exception:
            _rollback()
            raise

        created_at = datetime.now(timezone.utc).isoformat()
        try:
            persist_session(
                session_id=session_id, created_at=created_at, ctx=ctx,
                rsod_text=rsod_text,
                primary_path=primary_path, companion_path=companion,
                pdb_path=pdb_path, remaining_extras=remaining_extras,
                base_override=metadata.get('base_override'),
                dwarf_prefix=metadata.get('dwarf_prefix'),
                imported_from=bundle_original_id,
            )
        except Exception:
            _rollback()
            raise

        session = Session.from_analysis_context(
            ctx, session_id, created_at=created_at)
        store_session(session)

        return jsonify(
            session_id=session_id,
            imported_from=bundle_original_id,
            crash_summary=crash_info_to_dict(ctx.result.crash_info),
            frame_count=len(ctx.result.frames),
        ), 201

    # -----------------------------------------------------------------
    # DELETE /api/session/<id> — drop in-memory + SQLite + files dir
    # -----------------------------------------------------------------
    @app.delete('/api/session/<session_id>')
    def delete_session_route(session_id: str):
        session = pop_session(session_id)
        if session is not None:
            _delete_session(session)
            return jsonify(deleted=True)
        # Session may only exist on disk (evicted or cross-restart).
        if storage.delete_session(session_id):
            return jsonify(deleted=True)
        return jsonify(error='session not found'), 404

    # -----------------------------------------------------------------
    # WebSocket /ws/gdb/<session_id> — GDB terminal bridge
    # -----------------------------------------------------------------
    try:
        from flask_sock import Sock
        sock = Sock(app)

        @sock.route('/ws/gdb/<session_id>')
        def gdb_terminal(ws, session_id: str):
            session = get_session(session_id)
            if not session:
                ws.close(reason='session not found')
                return

            # Launch GDB on first connection (lazy)
            if not session.gdb and session.elf_path:
                core_dir = session.temp_dir or Path(tempfile.mkdtemp())
                if not session.temp_dir:
                    session.temp_dir = core_dir
                core_path = core_dir / 'crash.core'
                frame_data = [(f.frame_fp, f.address)
                              for f in session.result.frames]
                write_corefile(
                    session.result.crash_info.registers,
                    session.result.crash_info.crash_pc,
                    session.result.stack_base,
                    session.result.stack_mem,
                    session.elf_path,
                    core_path,
                    image_base=session.img_base,
                    frames=frame_data,
                )
                session.gdb = GdbSession(
                    session.elf_path, core_path, session.img_base)

            if not session.gdb:
                ws.close(reason='GDB not available')
                return

            gdb = session.gdb
            import json as _json
            from simple_websocket import ConnectionClosed
            try:
                while gdb.alive:
                    # Read GDB output → send to browser
                    output = gdb.read(timeout=0.05)
                    if output:
                        ws.send(output)

                    # Read browser input → send to GDB
                    # receive returns None on timeout, raises
                    # ConnectionClosed when the client disconnects.
                    data = ws.receive(timeout=0.05)
                    if data is None:
                        continue

                    if isinstance(data, str):
                        data = data.encode()

                    # Control messages: first byte 0x01
                    if len(data) > 1 and data[0] == 0x01:
                        try:
                            msg = _json.loads(data[1:])
                            if msg.get('type') == 'frame_select':
                                gdb.send_command(f'frame {msg["index"]}')
                            elif msg.get('type') == 'resize':
                                gdb.resize(msg.get('rows', 24),
                                           msg.get('cols', 80))
                        except (ValueError, KeyError):
                            pass
                    else:
                        gdb.write(data)
            except ConnectionClosed:
                pass

        @sock.route('/ws/lldb/<session_id>')
        def lldb_terminal(ws, session_id: str):
            session = get_session(session_id)
            if not session:
                ws.close(reason='session not found')
                return
            if not lldb_available():
                ws.close(reason='lldb Python module not available')
                return

            from .lldb_bridge import LldbConsole
            shared_debugger = None
            if session.lldb_dwarf is not None:
                shared_debugger = getattr(
                    session.lldb_dwarf, '_debugger', None)
            try:
                console = LldbConsole(debugger=shared_debugger)
            except RuntimeError as e:
                ws.close(reason=str(e))
                return

            from simple_websocket import ConnectionClosed
            try:
                ws.send(console.banner())
                while True:
                    data = ws.receive(timeout=60)
                    if data is None:
                        continue
                    if isinstance(data, str):
                        data = data.encode('utf-8')
                    # Ignore control frames (resize etc.) — LLDB is
                    # in-process and doesn't care about terminal size.
                    if len(data) >= 1 and data[0] == 0x01:
                        continue
                    out = console.handle_input(data)
                    if out:
                        ws.send(out)
            except ConnectionClosed:
                pass
            finally:
                console.close()
    except ImportError:
        pass  # flask-sock not installed, terminal bridges disabled

    return app



# =============================================================================
# Standalone server
# =============================================================================

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)
