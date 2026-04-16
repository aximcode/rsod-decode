"""Session ingestion pipeline — the single owner of the
staging → hash → dedup → promote → analyze → persist lifecycle.

Every code path that creates a new persisted session goes through
`ingest_session`: the HTTP upload route, the bundle import route,
the CLI pre-load in `rsod serve`, and the `rsod decode` text
report flow. Callers are responsible for getting files into a
staging directory (multipart upload, zip extraction, or file copy);
this module handles everything from content-hash computation onward.

Does NOT import Flask. Relies on `storage`, `data_dir`, `service`.
"""
from __future__ import annotations

import os
import shutil
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import data_dir as _data_dir, storage
from .models import SymbolSource
from .pdb_routing import _pair_map_with_pe, _pop_pdb_for
from .service import AnalysisContext, run_analysis
from .storage import canonical_filename
from .symbols import SymbolLoadError, is_pe, load_symbols


# =============================================================================
# Result type
# =============================================================================

@dataclass
class IngestResult:
    """Returned by `ingest_session`."""
    session_id: str
    ctx: AnalysisContext
    is_new: bool
    created_at: str


# =============================================================================
# Staging directory
# =============================================================================

def staging_dir() -> Path:
    """Create and return a fresh scratch dir for in-flight uploads.

    Uploads land here first so we can compute the content hash — and
    thus the canonical session id — before choosing a final location.
    Staging dirs live under `files/.staging/` so the top level of
    `files/` contains only real session ids. The directory is created
    immediately so callers can write to it without an extra mkdir.
    """
    root = _data_dir.session_files_dir() / '.staging'
    root.mkdir(parents=True, exist_ok=True)
    d = root / uuid.uuid4().hex
    d.mkdir()
    return d


# =============================================================================
# Per-session upload serialization
# =============================================================================

_session_locks_master = threading.Lock()
_session_locks: dict[str, threading.Lock] = {}


def _session_lock(session_id: str) -> threading.Lock:
    with _session_locks_master:
        lock = _session_locks.get(session_id)
        if lock is None:
            lock = threading.Lock()
            _session_locks[session_id] = lock
        return lock


# =============================================================================
# Core analysis (Flask-free)
# =============================================================================

def analyze_from_disk(
    *,
    rsod_text: str,
    primary_path: Path,
    extra_paths: list[Path],
    base_override: int | None = None,
    dwarf_prefix: str | None = None,
    repo_root: Path | None = None,
    symbol_search_paths: list[Path] | None = None,
    source_roots: list[Path] | None = None,
    backend: str = 'auto',
) -> tuple[AnalysisContext, Path | None, Path | None, list[Path]]:
    """Run symbol loading + analysis on already-persisted files.

    Returns `(ctx, companion_path, pdb_path, remaining_extras)`. The
    three path return values reflect how `_pair_map_with_pe` and
    `_pop_pdb_for` classified the input set, so `persist_session` can
    store a matching session_files row for each.

    No Flask dependency — all config values are explicit parameters.
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
        repo_root=repo_root,
        companion_path=companion,
        pdb_path=pdb_path if companion is None else None)

    extra_sources: dict[str, SymbolSource] = {}
    for p in remaining_extras:
        s = load_symbols(p, dwarf_prefix=dwarf_prefix, repo_root=repo_root)
        extra_sources[p.stem.lower()] = s

    # temp_dir is deliberately None. `evict_from_memory` wipes
    # `session.temp_dir` on LRU eviction — setting it to the
    # persistent files dir would nuke `~/.rsod-debug/files/<id>/`.
    ctx = run_analysis(
        rsod_text, source, extra_sources,
        base_override=base_override,
        symbol_search_paths=symbol_search_paths,
        temp_dir=None,
        elf_path=primary_path,
        pe_path=pe_for_pdb,
        pdb_path=pdb_path,
        backend=backend,
        source_roots=source_roots or [],
    )
    return ctx, companion, pdb_path, remaining_extras


# =============================================================================
# Persistence
# =============================================================================

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
    name: str | None = None,
) -> None:
    """Insert one row + session_files entries for a freshly-ingested session."""
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
        name=name,
    )


# =============================================================================
# Promote staging → final
# =============================================================================

def promote_staging(stg: Path, session_id: str) -> Path:
    """Atomically rename `stg` to its content-hash final dir.

    Uses `os.rename`, which fails if the target non-empty dir already
    exists. On failure the caller retries dedup resolution.

    Orphan directories (files without a row, from a crashed upload
    that never persisted) are handled at startup by
    `storage.collect_orphans`, not inline during the promote.
    """
    final_dir = _data_dir.session_files_dir_for(session_id)
    try:
        os.rename(str(stg), str(final_dir))
    except OSError as e:
        raise FileExistsError(str(final_dir)) from e
    return final_dir


# =============================================================================
# Dedup resolution
# =============================================================================

def try_resolve_existing(
    session_id: str,
    *,
    dwarf_prefix: str | None = None,
    repo_root: Path | None = None,
    symbol_search_paths: list[Path] | None = None,
    source_roots: list[Path] | None = None,
    backend: str = 'auto',
) -> IngestResult | None:
    """Return an IngestResult if `session_id` has a healthy DB row + files.

    Hydrates the session via `analyze_from_disk` against the
    persisted inputs. Returns None if the row is missing, files have
    vanished, or hydration fails — in which case the caller treats
    the upload as fresh.
    """
    files_dir = _data_dir.session_files_dir_for(session_id)
    if not storage.session_exists(session_id) or not files_dir.exists():
        return None
    inputs = storage.hydrate_inputs(session_id)
    if inputs is None:
        return None
    extras = list(inputs.extra_paths)
    if inputs.companion_path is not None:
        extras.append(inputs.companion_path)
    if inputs.pdb_path is not None:
        extras.append(inputs.pdb_path)
    try:
        ctx, _, _, _ = analyze_from_disk(
            rsod_text=inputs.rsod_text,
            primary_path=inputs.primary_path,
            extra_paths=extras,
            base_override=inputs.base_override,
            dwarf_prefix=inputs.dwarf_prefix or dwarf_prefix,
            repo_root=repo_root,
            symbol_search_paths=symbol_search_paths,
            source_roots=source_roots,
            backend=backend,
        )
    except (FileNotFoundError, SymbolLoadError):
        return None
    return IngestResult(
        session_id=session_id,
        ctx=ctx,
        is_new=False,
        created_at=inputs.created_at,
    )


# =============================================================================
# Main entry point
# =============================================================================

def ingest_session(
    stg: Path,
    *,
    base_override: int | None = None,
    dwarf_prefix: str | None = None,
    repo_root: Path | None = None,
    symbol_search_paths: list[Path] | None = None,
    source_roots: list[Path] | None = None,
    backend: str = 'auto',
    imported_from: str | None = None,
    name: str | None = None,
) -> IngestResult:
    """Stage → hash → dedup → promote → analyze → persist.

    `stg` must already contain rsod.txt + symbol files with
    canonical basenames. This function handles everything from
    content-hash computation onward.

    On dedup hit: discards stg, returns is_new=False with the
    existing session hydrated.
    On fresh: promotes stg to files/<id>/, runs the full analysis
    pipeline, persists the DB row, returns is_new=True.

    Raises `SymbolLoadError` on symbol-loading failures. On any
    failure after promotion, the files_dir is rolled back.
    """
    rsod_text = (stg / 'rsod.txt').read_text(
        encoding='utf-8', errors='replace')
    session_id = storage.compute_session_id(stg)

    analysis_kwargs = dict(
        dwarf_prefix=dwarf_prefix,
        repo_root=repo_root,
        symbol_search_paths=symbol_search_paths,
        source_roots=source_roots,
        backend=backend,
    )

    with _session_lock(session_id):
        existing = try_resolve_existing(session_id, **analysis_kwargs)
        if existing is not None:
            shutil.rmtree(stg, ignore_errors=True)
            return existing

        try:
            files_dir = promote_staging(stg, session_id)
        except FileExistsError:
            shutil.rmtree(stg, ignore_errors=True)
            existing = try_resolve_existing(session_id, **analysis_kwargs)
            if existing is not None:
                return existing
            raise RuntimeError(
                f'files/{session_id} exists but cannot hydrate')

        # Discover the primary symbol file — the first non-rsod.txt
        # entry alphabetically. Which file is "primary" doesn't
        # actually matter: analyze_from_disk passes all paths to
        # _pair_map_with_pe which reclassifies by extension anyway.
        primary_path: Path | None = None
        extra_paths: list[Path] = []
        for item in sorted(files_dir.iterdir(), key=lambda p: p.name):
            if not item.is_file() or item.name == 'rsod.txt':
                continue
            if primary_path is None:
                primary_path = item
            else:
                extra_paths.append(item)
        if primary_path is None:
            shutil.rmtree(files_dir, ignore_errors=True)
            raise SymbolLoadError('no symbol file found in staging')

        try:
            ctx, companion, pdb_path, remaining_extras = analyze_from_disk(
                rsod_text=rsod_text,
                primary_path=primary_path,
                extra_paths=extra_paths,
                base_override=base_override,
                **analysis_kwargs,
            )
        except Exception:
            shutil.rmtree(files_dir, ignore_errors=True)
            raise

        created_at = datetime.now(timezone.utc).isoformat()
        try:
            persist_session(
                session_id=session_id,
                created_at=created_at,
                ctx=ctx,
                rsod_text=rsod_text,
                primary_path=primary_path,
                companion_path=companion,
                pdb_path=pdb_path,
                remaining_extras=remaining_extras,
                base_override=base_override,
                dwarf_prefix=dwarf_prefix,
                imported_from=imported_from,
                name=name,
            )
        except Exception:
            shutil.rmtree(files_dir, ignore_errors=True)
            raise

    return IngestResult(
        session_id=session_id,
        ctx=ctx,
        is_new=True,
        created_at=created_at,
    )
