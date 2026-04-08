#!/usr/bin/env python3
"""
RSOD Decode Tool

Resolves raw addresses in UEFI RSOD (Red Screen of Death) stack dumps to
function names, source locations, and more using symbol files.

Works with any UEFI application crash — supports x86-64 (MSVC .map) and
ARM64 (GCC ELF via pyelftools/capstone).

Usage:
  rsod-decode.py <rsod-log> <symbol-file> [-o output] [-v] [--base HEX]
  rsod-decode.py rsod.txt app.efi.map
  rsod-decode.py rsod.txt app.efi.so -v
  rsod-decode.py rsod.txt app.efi.so -s DxeCore.debug -s Shell.debug
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from backend.decoder import decode_rsod, resolve_git_ref
from backend.models import GitRef
from backend.symbols import SymbolLoadError


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Decode RSOD stack dumps using MSVC map files or ELF binaries.')
    parser.add_argument('rsod_log', type=Path,
                        help='RSOD serial console capture (putty log)')
    parser.add_argument('symbol_file', type=Path,
                        help='MSVC .map file or ELF binary (.efi/.so)')
    parser.add_argument('-o', '--output', type=Path, default=None,
                        help='Output file (default: <log>_decode.txt)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show disassembly, source context, parameters')
    parser.add_argument('-s', '--sym', action='append', type=Path, default=[],
                        help='Additional symbol files for multi-module traces')
    parser.add_argument('--base', type=str, default=None,
                        help='Override image base address (hex)')
    parser.add_argument('--source-root', type=Path, default=None,
                        help='Local source tree root for source context')
    parser.add_argument('--tag', type=str, default=None,
                        help='Git tag for source context (e.g. v1.0.3)')
    parser.add_argument('--commit', type=str, default=None,
                        help='Git commit hash for source context')
    args = parser.parse_args()

    if not args.rsod_log.exists():
        sys.exit(f"Error: RSOD log not found: {args.rsod_log}")
    if not args.symbol_file.exists():
        sys.exit(f"Error: symbol file not found: {args.symbol_file}")
    for s in args.sym:
        if not s.exists():
            sys.exit(f"Error: extra symbol file not found: {s}")

    out_path = args.output or args.rsod_log.with_name(
        f"{args.rsod_log.stem}_decode{args.rsod_log.suffix}")

    base_override: int | None = None
    if args.base is not None:
        try:
            base_override = int(args.base, 16)
        except ValueError:
            sys.exit(f"Error: invalid base address: {args.base}")

    # Default source root: infer from script location
    # Script is at scripts/rsod-decode/rsod-decode.py, so parents[3] = source/src/
    source_root = args.source_root
    if source_root is None:
        candidate = Path(__file__).resolve().parents[3]
        if candidate.is_dir():
            source_root = candidate

    # Resolve git ref (tag or commit) for source context
    git_ref: GitRef | None = None
    repo_root: Path | None = None
    ref_str = args.tag or args.commit
    if ref_str:
        # Find the repo root (walk up from source_root or script location)
        for candidate_root in (source_root, Path(__file__).resolve().parents[4]):
            if candidate_root and (candidate_root / '.git').exists():
                repo_root = candidate_root
                break
            # Check parent — source/src/ → source/ → repo root
            for p in (candidate_root,) if candidate_root else ():
                for parent in p.parents:
                    if (parent / '.git').exists():
                        repo_root = parent
                        break
                if repo_root:
                    break
            if repo_root:
                break

        if repo_root:
            git_ref = resolve_git_ref(ref_str, repo_root)
            if git_ref:
                _log(f"Source: {git_ref.label()}")
            else:
                _log(f"Warning: git ref '{ref_str}' not found in {repo_root}")
        else:
            _log("Warning: git repo not found, --tag/--commit ignored")

    try:
        decode_rsod(args.rsod_log, args.symbol_file, out_path,
                    base_override, args.verbose, args.sym,
                    source_root, git_ref, repo_root)
    except SymbolLoadError as e:
        sys.exit(f"Error: {e}")


if __name__ == '__main__':
    main()
