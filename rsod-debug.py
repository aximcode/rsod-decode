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
import sys
import uuid
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from backend.app import Session, _sessions, create_app
from backend.decoder import analyze_rsod
from backend.models import GitRef
from backend.decoder import resolve_git_ref
from backend.symbols import SymbolLoadError, load_symbols


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


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

    # Create Flask app with static file serving
    app = create_app(repo_root=repo_root, dwarf_prefix=args.dwarf_prefix)
    dist_dir = Path(__file__).resolve().parent / 'frontend' / 'dist'

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

        try:
            source = load_symbols(args.symbol_file,
                                  dwarf_prefix=args.dwarf_prefix,
                                  repo_root=repo_root)
        except SymbolLoadError as e:
            sys.exit(f"Error: {e}")

        extra_sources = {}
        for p in args.sym:
            try:
                s = load_symbols(p, dwarf_prefix=args.dwarf_prefix,
                                 repo_root=repo_root)
            except SymbolLoadError as e:
                sys.exit(f"Error: {e}")
            extra_sources[p.stem.lower()] = s

        rsod_text = args.rsod_log.read_text(encoding='utf-8', errors='replace')

        base_override = None
        if args.base:
            try:
                base_override = int(args.base, 16)
            except ValueError:
                sys.exit(f"Error: invalid base address: {args.base}")

        result = analyze_rsod(rsod_text, source, extra_sources, base_override)

        session_id = uuid.uuid4().hex[:12]
        _sessions[session_id] = Session(
            id=session_id,
            result=result,
            source=source,
            extra_sources=extra_sources,
            rsod_text=rsod_text,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        _log(f"Session {session_id}: {len(result.frames)} frames, "
             f"{result.resolved_count} addresses resolved")

    # Build URL
    host_display = 'localhost' if args.host == '0.0.0.0' else args.host
    url = f"http://{host_display}:{args.port}"
    if session_id:
        url += f"/#session/{session_id}"

    _log(f"\nRSOD Debugger running at: {url}")
    _log("Press Ctrl+C to stop\n")

    # Open browser
    if not args.no_browser:
        webbrowser.open(url)

    # Run server
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == '__main__':
    main()
