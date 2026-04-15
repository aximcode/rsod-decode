#!/usr/bin/env python3
"""
RSOD Debugger — Interactive Web UI

Starts a local web server for interactive RSOD crash analysis.
Optionally pre-loads an RSOD log and symbol file from the command line.

Usage:
  rsod-debug.py                                    # opens with upload form
  rsod-debug.py rsod.txt app.efi.so                # pre-loads analysis
  rsod-debug.py rsod.txt app.efi.so -v             # verbose (params/disasm)
  rsod-debug.py rsod.txt app.efi.so -s DxeCore.debug
  rsod-debug.py --port 9090                        # custom port
"""
from __future__ import annotations

import argparse
import shutil
import socket
import sys
import uuid
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from . import data_dir as _data_dir, storage
from .app import create_app, persist_session
from .session import Session, register_session
from .symbols import SymbolLoadError, load_symbols


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    """Poll a TCP port until it accepts connections (for browser open)."""
    import socket as _socket
    target = '127.0.0.1' if host in ('0.0.0.0', '') else host
    deadline = __import__('time').monotonic() + timeout
    while __import__('time').monotonic() < deadline:
        try:
            with _socket.create_connection((target, port), timeout=0.2):
                return True
        except OSError:
            __import__('time').sleep(0.05)
    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Interactive RSOD crash debugger web UI.')
    parser.add_argument('rsod_log', nargs='?', type=Path, default=None,
                        help='RSOD serial console capture (optional)')
    parser.add_argument('symbol_file', nargs='?', type=Path, default=None,
                        help='MSVC .map file or ELF binary (optional)')
    parser.add_argument('-s', '--sym', action='append', type=Path, default=[],
                        help='Additional symbol files for multi-module traces')
    parser.add_argument('--base', type=str, default=None,
                        help='Override image base address (hex)')
    parser.add_argument('--tag', type=str, default=None,
                        help='Git tag for source context')
    parser.add_argument('--commit', type=str, default=None,
                        help='Git commit hash for source context')
    parser.add_argument('--port', type=int, default=5000,
                        help='Server port (default: 5000)')
    parser.add_argument('--host', type=str, default='0.0.0.0',
                        help='Server host (default: 0.0.0.0)')
    parser.add_argument('--no-browser', action='store_true',
                        help='Do not open browser automatically')
    parser.add_argument('--dwarf-prefix', type=str, default=None,
                        help='Path prefix to strip from DWARF source paths '
                             '(auto-detected if not specified)')
    parser.add_argument('--backend', type=str, default='auto',
                        choices=['auto', 'lldb', 'gdb', 'pyelftools'],
                        help='DWARF backend: lldb (system lldb Python API), '
                             'gdb (uses GDB/MI), pyelftools (standalone), '
                             'auto (prefers lldb → gdb → pyelftools)')
    parser.add_argument('--symbol-path', type=Path, action='append',
                        default=[], dest='symbol_paths',
                        help='Directory to search for module symbol files '
                             '(repeatable; auto-loads .so/.debug matching '
                             'image table modules)')
    parser.add_argument('--source-path', type=Path, action='append',
                        default=[], dest='source_paths',
                        help='Additional source tree to search when a '
                             'DWARF/PDB file path is not under the '
                             'rsod-decode repo (repeatable; e.g. '
                             '~/projects/aximcode/axl-sdk)')
    args = parser.parse_args()

    # Validate file args
    if args.rsod_log and not args.symbol_file:
        parser.error('symbol_file is required when rsod_log is specified')
    if args.rsod_log and not args.rsod_log.exists():
        sys.exit(f"Error: RSOD log not found: {args.rsod_log}")
    if args.symbol_file and not args.symbol_file.exists():
        sys.exit(f"Error: symbol file not found: {args.symbol_file}")
    for s in args.sym:
        if not s.exists():
            sys.exit(f"Error: extra symbol file not found: {s}")

    # Find repo root for DWARF prefix auto-detection
    repo_root: Path | None = None
    for parent in Path(__file__).resolve().parents:
        if (parent / '.git').exists():
            repo_root = parent
            break

    # Validate any --source-path arguments eagerly so typos don't
    # silently produce empty-Source tabs.
    for sp in args.source_paths:
        if not sp.is_dir():
            sys.exit(f"Error: --source-path directory not found: {sp}")

    # Create Flask app with static file serving
    app = create_app(repo_root=repo_root, dwarf_prefix=args.dwarf_prefix,
                     symbol_search_paths=args.symbol_paths or None,
                     source_paths=args.source_paths or None)
    from .resource_paths import frontend_dist
    dist_dir = frontend_dist()

    if dist_dir.is_dir():
        from flask import send_from_directory

        @app.get('/')
        def serve_index():
            return send_from_directory(str(dist_dir), 'index.html')

        @app.get('/assets/<path:filename>')
        def serve_assets(filename: str):
            return send_from_directory(str(dist_dir / 'assets'), filename)
    else:
        _log(f"Warning: frontend not built ({dist_dir} not found)")
        _log("Run: cd frontend && npm run build")

    # Pre-load session if files specified
    session_id: str | None = None
    if args.rsod_log and args.symbol_file:
        _log(f"Loading {args.rsod_log.name} + {args.symbol_file.name}...")

        base_override = None
        if args.base:
            try:
                base_override = int(args.base, 16)
            except ValueError:
                sys.exit(f"Error: invalid base address: {args.base}")

        # Stage the CLI inputs, compute the content-hash session id,
        # then either promote staging to the final location or discard
        # it and reuse the existing files if this content was already
        # uploaded (possibly in a prior `rsod serve` run on the same
        # data dir).
        staging_root = _data_dir.session_files_dir() / '.staging'
        staging_root.mkdir(parents=True, exist_ok=True)
        staging_dir = staging_root / uuid.uuid4().hex
        staging_dir.mkdir(parents=True, exist_ok=True)
        try:
            (staging_dir / 'rsod.txt').write_bytes(args.rsod_log.read_bytes())
            staging_primary = staging_dir / args.symbol_file.name
            shutil.copy2(args.symbol_file, staging_primary)
            for src in args.sym:
                shutil.copy2(src, staging_dir / src.name)
        except OSError as e:
            shutil.rmtree(staging_dir, ignore_errors=True)
            sys.exit(f"Error copying inputs: {e}")

        session_id = storage.compute_session_id(staging_dir)
        files_dir = _data_dir.session_files_dir_for(session_id)
        is_dedup = storage.session_exists(session_id) and files_dir.exists()
        if is_dedup:
            _log(f"Session {session_id} already in store — reusing persisted files")
            shutil.rmtree(staging_dir, ignore_errors=True)
        else:
            storage.delete_session(session_id)  # drop stale row, no-op if absent
            if files_dir.exists():
                shutil.rmtree(files_dir)
            try:
                staging_dir.rename(files_dir)
            except OSError as e:
                shutil.rmtree(staging_dir, ignore_errors=True)
                sys.exit(f"Error promoting staging dir: {e}")

        primary_path = files_dir / args.symbol_file.name
        extra_paths: list[Path] = [files_dir / s.name for s in args.sym]

        def _cli_rollback() -> None:
            # Only rmtree on the fresh-promotion path. Dedup reuses
            # the already-persisted files dir — erasing it would
            # break every other session that content-hashes to it.
            if not is_dedup:
                shutil.rmtree(files_dir, ignore_errors=True)
                storage.delete_session(session_id)

        # MSVC/EPSA: detect a MAP+EFI companion pair in the extras, and
        # pick up a matching .pdb for PDB-backed LLDB.
        from .pdb_routing import _pair_map_with_pe, _pop_pdb_for
        from .symbols import is_pe
        companion, remaining_extras = _pair_map_with_pe(primary_path, extra_paths)
        pe_for_pdb = companion if companion and is_pe(companion) else (
            primary_path if is_pe(primary_path) else None)
        pdb_path: Path | None = None
        if pe_for_pdb is not None:
            pdb_path, remaining_extras = _pop_pdb_for(
                pe_for_pdb.stem, remaining_extras)

        try:
            source = load_symbols(
                primary_path,
                dwarf_prefix=args.dwarf_prefix,
                repo_root=repo_root,
                companion_path=companion,
                pdb_path=pdb_path if companion is None else None)
        except SymbolLoadError as e:
            _cli_rollback()
            sys.exit(f"Error: {e}")

        extra_sources = {}
        for p in remaining_extras:
            try:
                s = load_symbols(p, dwarf_prefix=args.dwarf_prefix,
                                 repo_root=repo_root)
            except SymbolLoadError as e:
                _cli_rollback()
                sys.exit(f"Error: {e}")
            extra_sources[p.stem.lower()] = s

        rsod_text = (files_dir / 'rsod.txt').read_text(
            encoding='utf-8', errors='replace')

        cli_source_roots: list[Path] = []
        if repo_root is not None:
            cli_source_roots.append(repo_root)
        cli_source_roots.extend(args.source_paths or [])

        from .service import run_analysis
        ctx = run_analysis(
            rsod_text, source, extra_sources,
            base_override=base_override,
            symbol_search_paths=args.symbol_paths or None,
            elf_path=primary_path,
            pe_path=pe_for_pdb,
            pdb_path=pdb_path,
            backend=args.backend,
            source_roots=cli_source_roots,
        )

        created_at = datetime.now(timezone.utc).isoformat()
        try:
            # INSERT OR IGNORE inside save_session makes this a no-op
            # on dedup, so we can always call it. The row's
            # created_at stays at whatever the first upload recorded.
            persist_session(
                session_id=session_id, created_at=created_at, ctx=ctx,
                rsod_text=rsod_text,
                primary_path=primary_path, companion_path=companion,
                pdb_path=pdb_path, remaining_extras=remaining_extras,
                base_override=base_override,
                dwarf_prefix=args.dwarf_prefix,
            )
        except Exception as e:
            _cli_rollback()
            sys.exit(f"Error persisting session: {e}")

        sess = Session.from_analysis_context(
            ctx, session_id, created_at=created_at)
        register_session(sess)

        _log(f'Using {sess.backend} backend')
        _log(f"Session {session_id}: {len(ctx.result.frames)} frames, "
             f"{ctx.result.resolved_count} addresses resolved")

    # Build URLs for all accessible addresses
    session_hash = f"/#session/{session_id}" if session_id else ""
    if args.host == '0.0.0.0':
        urls = [f"http://127.0.0.1:{args.port}{session_hash}"]
        seen = {'127.0.0.1'}
        try:
            for info in socket.getaddrinfo(
                socket.gethostname(), None, socket.AF_INET,
            ):
                addr = info[4][0]
                if addr not in seen:
                    seen.add(addr)
                    urls.append(f"http://{addr}:{args.port}{session_hash}")
        except socket.gaierror:
            pass
        # Also try a UDP connect to find the default route address
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))
                addr = s.getsockname()[0]
                if addr not in seen:
                    seen.add(addr)
                    urls.append(f"http://{addr}:{args.port}{session_hash}")
        except OSError:
            pass
    else:
        urls = [f"http://{args.host}:{args.port}{session_hash}"]

    _log(f"\nRSOD Debugger running at:")
    for u in urls:
        _log(f"  {u}")
    _log("Press Ctrl+C to stop\n")

    # Open the browser on a background thread that waits for Flask to
    # bind the socket before calling webbrowser.open. The prior code
    # opened pre-bind, which broke text browsers like lynx that don't
    # retry (graphical browsers hid it by spinning until connect).
    if not args.no_browser:
        import threading

        def _open_when_ready() -> None:
            if _wait_for_port(args.host, args.port, timeout=5.0):
                webbrowser.open(urls[0])

        threading.Thread(target=_open_when_ready, daemon=True).start()

    # Run server
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == '__main__':
    main()
