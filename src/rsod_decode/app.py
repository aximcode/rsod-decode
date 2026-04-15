"""Flask API for the RSOD debugger web UI.

Phase 1: In-memory session storage, file uploads to temp dir.
"""
from __future__ import annotations

import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request
from werkzeug.utils import secure_filename

from .models import SymbolSource, clean_path, binary_for_frame, find_source_file
from .corefile import write_corefile
from .decoder import analyze_rsod
from .gdb_bridge import GdbSession
from .serializers import (
    _RE_MEM_LOC, _build_frame_ctx, _var_to_dict,
    crash_info_to_dict, binary_for_session, frame_to_dict, registers_to_dict,
)
from .session import (
    Session, cleanup_session, gdb_available, get_session, lldb_available,
    pop_session, register_session, store_session,
)
from .symbols import SymbolLoadError, is_pe, load_symbols


def _pair_map_with_pe(
    primary: Path, extras: list[Path],
) -> tuple[Path | None, list[Path]]:
    """Return (companion, filtered_extras) if primary has a paired PE/.map
    companion in extras, else (None, extras) unchanged.

    MSVC EPSA commonly names the map file `psa.efi.map`, so we also match
    by full-name suffix in addition to stem equality.
    """
    prim_name = primary.name.lower()
    prim_stem = primary.stem.lower()
    prim_is_pe = is_pe(primary)
    prim_is_map = prim_name.endswith('.map')
    if not (prim_is_pe or prim_is_map):
        return None, extras

    for i, ex in enumerate(extras):
        ex_name = ex.name.lower()
        ex_stem = ex.stem.lower()
        ex_is_pe = is_pe(ex)
        ex_is_map = ex_name.endswith('.map')
        same_stem = ex_stem == prim_stem
        map_for_pe = ex_name == f"{prim_name}.map"  # psa.efi + psa.efi.map
        pe_for_map = prim_name == f"{ex_name}.map"  # psa.efi.map + psa.efi
        if prim_is_pe and ex_is_map and (same_stem or map_for_pe):
            return ex, extras[:i] + extras[i + 1:]
        if prim_is_map and ex_is_pe and (same_stem or pe_for_map):
            return ex, extras[:i] + extras[i + 1:]
    return None, extras


def _pop_pdb_for(stem: str, extras: list[Path]) -> tuple[Path | None, list[Path]]:
    """Pull a `<stem>.pdb` out of extras if one is present.

    Returned (pdb, remaining). Stem match is case-insensitive, and we
    strip one trailing extension from each candidate so `psa.efi.pdb`
    pairs with `psa.efi` as well as `psa.pdb` pairing with `psa`.
    """
    stem_l = stem.lower()
    for i, ex in enumerate(extras):
        if ex.name.lower().endswith('.pdb') and \
                ex.stem.lower() == stem_l:
            return ex, extras[:i] + extras[i + 1:]
    return None, extras


def _get_session(session_id: str) -> tuple[Session, None] | tuple[None, tuple]:
    """Look up a session by ID, returning (session, None) or (None, 404-response)."""
    session = get_session(session_id)
    if session is None:
        return None, (jsonify(error='session not found'), 404)
    return session, None


def _backfill_source_loc_from_richer_backend(session: Session) -> None:
    """Fill missing per-frame `source_loc` via the session's richer backend.

    The decoder's source_loc resolution pass only sees the static
    pyelftools / PEBinary surface — for PE+PDB sessions it returns
    nothing because PEBinary stubs `resolve_addresses`. Once the
    richer LLDB (or GDB) backend is attached to the session we can
    re-run the lookup for any frames that are still missing a
    source_loc and populate them from line-table-aware data.

    Crash frames key off `frame.address`; non-crash frames key off
    `frame.call_addr - 1` to land inside the caller's location-list
    range instead of the return address (which falls in an entry_value
    range that resolves to the callee). This mirrors the lookup_pc
    convention used by `get_frame`.
    """
    backend = session.lldb_dwarf or session.gdb_dwarf
    if backend is None:
        return
    for f in session.result.frames:
        if f.source_loc:
            continue
        if f.is_crash_frame:
            target = f.address
        else:
            target = (f.call_addr - 1) if f.call_addr else None
        if not target:
            continue
        info = backend.resolve_address(target)
        if info is None:
            continue
        if info.source_loc and not f.source_loc:
            f.source_loc = info.source_loc


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

    # -----------------------------------------------------------------
    # POST /api/session — upload RSOD + symbols, create session
    # -----------------------------------------------------------------
    @app.post('/api/session')
    def create_session():
        if 'rsod_log' not in request.files:
            return jsonify(error='rsod_log file required'), 400
        if 'symbol_file' not in request.files:
            return jsonify(error='symbol_file required'), 400

        rsod_file = request.files['rsod_log']
        sym_file = request.files['symbol_file']

        # Save uploads to temp dir with sanitized filenames
        temp_dir = Path(tempfile.mkdtemp(prefix='rsod-'))
        rsod_path = temp_dir / secure_filename(rsod_file.filename or 'rsod.txt')
        sym_path = temp_dir / secure_filename(sym_file.filename or 'symbols')
        rsod_file.save(str(rsod_path))
        sym_file.save(str(sym_path))

        # Save extra symbol files
        extra_paths: list[Path] = []
        for f in request.files.getlist('extra_symbols[]'):
            p = temp_dir / secure_filename(f.filename or 'extra')
            f.save(str(p))
            extra_paths.append(p)

        # Detect a MAP+EFI pair for MSVC builds: if the primary or one of
        # the extras is the PE companion of the other, fold it into the
        # loader as companion_path instead of treating it as a separate
        # module. Also pick up a matching .pdb for PDB-backed LLDB.
        companion, extra_paths = _pair_map_with_pe(sym_path, extra_paths)
        pe_for_pdb = companion if companion and is_pe(companion) else (
            sym_path if is_pe(sym_path) else None)
        pdb_path: Path | None = None
        if pe_for_pdb is not None:
            pdb_path, extra_paths = _pop_pdb_for(
                pe_for_pdb.stem, extra_paths)

        # Load symbols. When we have a .efi primary + .pdb but no .map,
        # load_symbols() will derive the symbol table from the PDB via
        # a short-lived LLDB session.
        try:
            source = load_symbols(
                sym_path,
                dwarf_prefix=app.config['DWARF_PREFIX'],
                repo_root=app.config['REPO_ROOT'],
                companion_path=companion,
                pdb_path=pdb_path if companion is None else None)
        except SymbolLoadError as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return jsonify(error=str(e)), 400

        extra_sources: dict[str, SymbolSource] = {}
        for p in extra_paths:
            try:
                s = load_symbols(p,
                                 dwarf_prefix=app.config['DWARF_PREFIX'],
                                 repo_root=app.config['REPO_ROOT'])
            except SymbolLoadError as e:
                shutil.rmtree(temp_dir, ignore_errors=True)
                return jsonify(error=str(e)), 400
            extra_sources[p.stem.lower()] = s

        # Read RSOD text
        rsod_text = rsod_path.read_text(encoding='utf-8', errors='replace')

        # Base override from form data
        base_override = None
        base_str = request.form.get('base')
        if base_str:
            try:
                base_override = int(base_str, 16)
            except ValueError:
                shutil.rmtree(temp_dir, ignore_errors=True)
                return jsonify(error=f'invalid base address: {base_str}'), 400

        # Analyze using the shared core
        analysis = analyze_rsod(rsod_text, source, extra_sources, base_override,
                               symbol_search_paths=app.config['SYMBOL_SEARCH_PATHS'])

        # Store session
        session_id = uuid.uuid4().hex[:12]
        session = Session(
            id=session_id,
            result=analysis,
            source=source,
            extra_sources=extra_sources,
            rsod_text=rsod_text,
            created_at=datetime.now(timezone.utc).isoformat(),
            temp_dir=temp_dir,
            elf_path=sym_path,
            pe_path=pe_for_pdb,
            pdb_path=pdb_path,
        )

        # Auto-initialize a richer backend if available. Preference
        # order: lldb (ELF corefile or PE+PDB) → gdb (ELF only) →
        # pyelftools. PE+PDB needs both .efi and .pdb; plain PE sessions
        # without a PDB silently fall back to pyelftools/PEBinary.
        frame_data = [(f.frame_fp, f.address) for f in analysis.frames]
        if lldb_available():
            try:
                from .lldb_backend import LldbBackend
                if pe_for_pdb is not None and pdb_path is not None:
                    session.lldb_dwarf = LldbBackend.from_pe_pdb(
                        pe_for_pdb, pdb_path,
                        analysis.crash_info.registers,
                        analysis.crash_info.crash_pc,
                        analysis.stack_base, analysis.stack_mem,
                        session.img_base, frames=frame_data)
                    session.backend = 'lldb'
                elif pe_for_pdb is None:
                    session.lldb_dwarf = LldbBackend(
                        sym_path, analysis.crash_info.registers,
                        analysis.crash_info.crash_pc,
                        analysis.stack_base, analysis.stack_mem,
                        session.img_base, frames=frame_data)
                    session.backend = 'lldb'
            except Exception:
                pass
        # GDB can only target ELF+DWARF; PE sessions are guaranteed to
        # fail inside write_corefile/add-symbol-file, so don't even try.
        if session.backend == 'pyelftools' and gdb_available() \
                and pe_for_pdb is None:
            try:
                from .gdb_backend import GdbBackend
                session.gdb_dwarf = GdbBackend(
                    sym_path, analysis.crash_info.registers,
                    analysis.crash_info.crash_pc,
                    analysis.stack_base, analysis.stack_mem,
                    session.img_base, frames=frame_data)
                session.backend = 'gdb'
            except Exception:
                pass

        # PE+PDB source_loc backfill. The decoder's re-resolve pass in
        # `analyze_rsod` uses `binary_for_frame` which returns the
        # static PEBinary for psa_x64.efi — PEBinary has no line info.
        # Once the richer LLDB backend is attached, walk the frames
        # and populate missing `source_loc` entries from the PDB.
        _backfill_source_loc_from_richer_backend(session)

        store_session(session)

        return jsonify(
            session_id=session_id,
            crash_summary=crash_info_to_dict(analysis.crash_info),
            frame_count=len(analysis.frames),
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

        binary = binary_for_session(session, frame)
        img_base = session.img_base
        if binary and frame.address:
            ctx = _build_frame_ctx(frame, session, img_base)
            # For non-crash frames, use call_addr - 1 for DWARF location
            # lookup.  The return address lands in DW_OP_entry_value ranges
            # (unresolvable for caller-saved regs).  Subtracting 1 from the
            # call instruction address puts us inside the previous range
            # where the variable is still on the stack (DW_OP_fbreg).
            lookup_pc = frame.address
            if not frame.is_crash_frame and frame.call_addr:
                lookup_pc = frame.call_addr - 1
            params = binary.get_params(lookup_pc)
            locals_ = binary.get_locals(lookup_pc)
            result['params'] = [_var_to_dict(v, ctx) for v in params]
            result['locals'] = [_var_to_dict(v, ctx) for v in locals_]

            # Infer unresolved params from ancestor frames (pyelftools only).
            # GDB/LLDB backends resolve entry_values themselves.
            if session.backend not in ('gdb', 'lldb'):
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

            # Globals: pyelftools discovers CU-scope names, GDB backend
            # evaluates values (if available) for runtime-accurate data.
            pyelf_binary = binary_for_frame(
                frame, session.source, session.extra_sources)
            if pyelf_binary:
                globals_ = pyelf_binary.get_globals(frame.address)
                # Richer backends (GDB/LLDB) resolve globals to runtime
                # values instead of ELF initializers. evaluate_globals()
                # takes the pyelftools-discovered list as its input.
                if session.backend == 'gdb' and session.gdb_dwarf:
                    from .gdb_backend import GdbBackend
                    if isinstance(session.gdb_dwarf, GdbBackend):
                        globals_ = session.gdb_dwarf.evaluate_globals(globals_)
                elif session.backend == 'lldb' and session.lldb_dwarf:
                    from .lldb_backend import LldbBackend
                    if isinstance(session.lldb_dwarf, LldbBackend):
                        globals_ = session.lldb_dwarf.evaluate_globals(globals_)
            else:
                globals_ = binary.get_globals(frame.address)
            result['globals'] = [_var_to_dict(v, ctx) for v in globals_]
        else:
            result['params'] = []
            result['locals'] = []
            result['globals'] = []

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
        # Target highlight and forward-decode anchor is the frame's
        # own address (return address for non-crash frames, crash PC
        # for frame 0) because that's the instruction the UI wants
        # marked "we're about to execute this". `frame.call_addr` is
        # `address - insn_size` for DWARF location-list lookups and
        # is *not* a valid instruction boundary on variable-length
        # x86, so the target highlight would never match any decoded
        # instruction if we used it as the anchor.
        target_addr = frame.address or frame.call_addr
        if not binary or not target_addr:
            return jsonify(instructions=[])

        context = min(request.args.get('context', 24, type=int), 200)
        insns = binary.disassemble_around(target_addr, context)
        src_map = binary.source_lines_for_addrs([a for a, _, _ in insns])

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
        if target not in ('pyelftools', 'gdb', 'lldb'):
            return jsonify(
                error='backend must be "pyelftools", "gdb", or "lldb"'), 400

        if target == session.backend:
            return jsonify(backend=session.backend)

        if target == 'gdb':
            if not gdb_available():
                return jsonify(error='GDB/pygdbmi not available'), 400
            if session.pe_path is not None:
                return jsonify(
                    error='GDB backend requires an ELF primary; '
                          'this session is PE+PDB'), 400
            if not session.gdb_dwarf:
                try:
                    from .gdb_backend import GdbBackend
                    frame_data = [(f.frame_fp, f.address)
                                  for f in session.result.frames]
                    session.gdb_dwarf = GdbBackend(
                        session.elf_path,
                        session.result.crash_info.registers,
                        session.result.crash_info.crash_pc,
                        session.result.stack_base,
                        session.result.stack_mem,
                        session.img_base,
                        frames=frame_data,
                    )
                except Exception as e:
                    return jsonify(error=f'Failed to start GDB backend: {e}'), 500

        if target == 'lldb':
            if not lldb_available():
                return jsonify(error='lldb Python module not available'), 400
            if not session.lldb_dwarf:
                try:
                    from .lldb_backend import LldbBackend
                    frame_data = [(f.frame_fp, f.address)
                                  for f in session.result.frames]
                    if session.pe_path is not None and \
                            session.pdb_path is not None:
                        session.lldb_dwarf = LldbBackend.from_pe_pdb(
                            session.pe_path,
                            session.pdb_path,
                            session.result.crash_info.registers,
                            session.result.crash_info.crash_pc,
                            session.result.stack_base,
                            session.result.stack_mem,
                            session.img_base,
                            frames=frame_data,
                        )
                    else:
                        session.lldb_dwarf = LldbBackend(
                            session.elf_path,
                            session.result.crash_info.registers,
                            session.result.crash_info.crash_pc,
                            session.result.stack_base,
                            session.result.stack_mem,
                            session.img_base,
                            frames=frame_data,
                        )
                except Exception as e:
                    return jsonify(error=f'Failed to start LLDB backend: {e}'), 500

        session.backend = target
        session.frame_cache.clear()
        _backfill_source_loc_from_richer_backend(session)
        return jsonify(backend=session.backend)

    # -----------------------------------------------------------------
    # DELETE /api/session/<id> — cleanup
    # -----------------------------------------------------------------
    @app.delete('/api/session/<session_id>')
    def delete_session(session_id: str):
        session = pop_session(session_id)
        if not session:
            return jsonify(error='session not found'), 404
        cleanup_session(session)
        return jsonify(deleted=True)

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
