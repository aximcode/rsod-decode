#!/usr/bin/env python3
"""
RSOD Decode Tool

Resolves raw addresses in UEFI RSOD (Red Screen of Death) stack dumps to
function names, source locations, and more using symbol files.

Two modes:

  rsod decode <rsod-log> <symbol-file> [options]   # from raw files
  rsod decode --session <id> [options]              # from a persisted session

The `--session` form replays the analysis against files already
persisted in `~/.rsod-debug/files/<id>/` by a prior `rsod serve`
upload or bundle import. Accepts full 16-char ids or unambiguous
prefixes (8+ chars, matching what the history UI shows).
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
    parser.add_argument('rsod_log', nargs='?', type=Path, default=None,
                        help='RSOD serial console capture (putty log)')
    parser.add_argument('symbol_file', nargs='?', type=Path, default=None,
                        help='MSVC .map file or ELF binary (.efi/.so)')
    parser.add_argument('--session', type=str, default=None, dest='session_id',
                        help='Replay a persisted session by id (full or '
                             'unambiguous prefix). Reads from '
                             '~/.rsod-debug/sessions.db instead of raw files.')
    parser.add_argument('-o', '--output', type=Path, default=None,
                        help='Output file (default: <log>_decode.txt or stdout '
                             'for --session)')
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
    parser.add_argument('--backend', default='auto',
                        choices=['auto', 'lldb', 'gdb', 'pyelftools'],
                        help='DWARF backend for variable resolution. '
                             '"auto" picks lldb > gdb > pyelftools.')
    args = parser.parse_args()

    if args.session_id is not None:
        _decode_from_session(args)
    elif args.rsod_log is not None and args.symbol_file is not None:
        _decode_from_files(args)
    else:
        parser.error(
            'provide rsod_log + symbol_file, or --session <id>')


def _decode_from_session(args: argparse.Namespace) -> None:
    """Hydrate a persisted session and write the text report."""
    from . import storage

    storage.init_db()
    try:
        session_id = storage.resolve_partial_id(args.session_id)
    except ValueError as e:
        sys.exit(f"Error: {e}")

    inputs = storage.hydrate_inputs(session_id)
    if inputs is None:
        sys.exit(f"Error: session {session_id} not found in database")

    _log(f"Session {session_id[:8]}… ({inputs.primary_path.name})")

    # Reconstruct the flat extras list so _pair_map_with_pe can
    # re-classify companion + pdb the same way the original upload
    # handler did. This is idempotent.
    extra_paths = list(inputs.extra_paths)
    if inputs.companion_path is not None:
        extra_paths.append(inputs.companion_path)
    if inputs.pdb_path is not None:
        extra_paths.append(inputs.pdb_path)

    repo_root = _find_repo_root()

    src_roots: list[Path] = list(args.source_paths)
    if repo_root is not None:
        src_roots.append(repo_root)

    git_ref = _resolve_git_ref(args, repo_root)

    out_path = args.output or Path(f'{session_id[:8]}_decode.txt')

    try:
        decode_rsod(
            inputs.primary_path.parent / 'rsod.txt',
            inputs.primary_path,
            out_path,
            inputs.base_override,
            args.verbose,
            extra_paths,
            src_roots or repo_root,
            git_ref, repo_root,
            dwarf_prefix=inputs.dwarf_prefix or args.dwarf_prefix,
            backend=args.backend,
        )
    except SymbolLoadError as e:
        sys.exit(f"Error: {e}")
    except FileNotFoundError as e:
        sys.exit(f"Error: session files missing on disk: {e}")

    _log(f"Output: {out_path}")


def _decode_from_files(args: argparse.Namespace) -> None:
    """Original file-based decode path (positional rsod_log + symbol_file)."""
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

    repo_root = _find_repo_root()

    for sp in args.source_paths:
        if not sp.is_dir():
            sys.exit(f"Error: --source-path directory not found: {sp}")

    fallback_root = repo_root or Path(__file__).resolve().parents[3]
    source_root: Path | list[Path] = (
        [*args.source_paths, fallback_root]
        if args.source_paths else fallback_root)

    git_ref = _resolve_git_ref(args, repo_root)

    try:
        decode_rsod(args.rsod_log, args.symbol_file, out_path,
                    base_override, args.verbose, args.sym,
                    source_root, git_ref, repo_root,
                    dwarf_prefix=args.dwarf_prefix,
                    backend=args.backend)
    except SymbolLoadError as e:
        sys.exit(f"Error: {e}")


def _find_repo_root() -> Path | None:
    for parent in Path(__file__).resolve().parents:
        if (parent / '.git').exists():
            return parent
    return None


def _resolve_git_ref(
    args: argparse.Namespace, repo_root: Path | None,
) -> GitRef | None:
    ref_str = args.tag or args.commit
    if not ref_str:
        return None
    if repo_root:
        git_ref = resolve_git_ref(ref_str, repo_root)
        if git_ref:
            _log(f"Source: {git_ref.label()}")
        else:
            _log(f"Warning: git ref '{ref_str}' not found in {repo_root}")
        return git_ref
    _log("Warning: git repo not found, --tag/--commit ignored")
    return None


if __name__ == '__main__':
    main()
