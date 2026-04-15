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

from .decoder import decode_rsod, resolve_git_ref
from .models import GitRef
from .symbols import SymbolLoadError


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
    parser.add_argument('--source-path', type=Path, action='append',
                        default=[], dest='source_paths',
                        help='Source tree to search for DWARF/PDB source '
                             'files (repeatable; auto-detected rsod-decode '
                             'repo is always searched as a fallback)')
    parser.add_argument('--tag', type=str, default=None,
                        help='Git tag for source context (e.g. v1.0.3)')
    parser.add_argument('--commit', type=str, default=None,
                        help='Git commit hash for source context')
    parser.add_argument('--dwarf-prefix', type=str, default=None,
                        help='Path prefix to strip from DWARF source paths '
                             '(auto-detected if not specified)')
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

    # Find repo root (walk up from script location looking for .git)
    repo_root: Path | None = None
    for parent in Path(__file__).resolve().parents:
        if (parent / '.git').exists():
            repo_root = parent
            break

    # Validate --source-path args eagerly so typos don't silently
    # degrade to "source file not found" later.
    for sp in args.source_paths:
        if not sp.is_dir():
            sys.exit(f"Error: --source-path directory not found: {sp}")
    # Every --source-path comes first (highest-priority search roots)
    # and we always fall back to the auto-detected rsod-decode repo
    # so in-tree fixtures keep working without extra flags.
    fallback_root = repo_root or Path(__file__).resolve().parents[3]
    source_root: Path | list[Path] = (
        [*args.source_paths, fallback_root]
        if args.source_paths else fallback_root)

    # Resolve git ref (tag or commit) for source context
    git_ref: GitRef | None = None
    ref_str = args.tag or args.commit
    if ref_str:
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
                    source_root, git_ref, repo_root,
                    dwarf_prefix=args.dwarf_prefix)
    except SymbolLoadError as e:
        sys.exit(f"Error: {e}")


if __name__ == '__main__':
    main()
