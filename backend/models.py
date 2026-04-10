"""Shared data structures and utilities for the RSOD decoder."""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .dwarf_info import DwarfInfo


# =============================================================================
# Symbol data structures
# =============================================================================

@dataclass
class MapSymbol:
    """One symbol from a map file or ELF."""
    address: int
    name: str
    object_file: str
    is_function: bool = True


@dataclass
class SymbolTable:
    """Sorted symbol list with binary-search lookup."""
    symbols: list[MapSymbol] = field(default_factory=list)
    addresses: list[int] = field(default_factory=list)
    preferred_base: int = 0
    image_end: int = 0

    def lookup(self, addr: int) -> tuple[MapSymbol, int] | None:
        """Find the symbol containing addr. Returns (symbol, offset) or None."""
        if addr < self.preferred_base or addr > self.image_end:
            return None
        idx = bisect.bisect_right(self.addresses, addr) - 1
        if idx < 0:
            return None
        sym = self.symbols[idx]
        offset = addr - sym.address
        return (sym, offset) if offset >= 0 else None


@dataclass
class SymbolSource:
    """Loaded symbols plus metadata."""
    table: SymbolTable
    elf_path: Path | None = None
    name: str = ''
    dwarf: DwarfInfo | None = None

    def has_debug_info(self) -> bool:
        return self.dwarf is not None


# =============================================================================
# Frame and crash data structures
# =============================================================================

@dataclass
class FrameInfo:
    """One resolved stack frame."""
    index: int
    address: int
    module: str
    symbol: MapSymbol | None = None
    sym_offset: int = 0
    source_loc: str = ''
    inlines: list[tuple[str, str]] = field(default_factory=list)
    is_crash_frame: bool = False  # True for the crash PC frame (don't adjust)
    call_addr: int = 0  # address - instruction_size for call-site resolution
    frame_fp: int = 0  # this frame's actual FP value (from FP chain walk)
    frame_cfa: int = 0  # CFA (Canonical Frame Address) from CFI rules
    frame_registers: dict[str, int] = field(default_factory=dict)


@dataclass
class CrashInfo:
    """Crash metadata extracted from the RSOD."""
    fmt: str = ''
    exception_desc: str = ''
    crash_pc: int | None = None
    crash_symbol: str = ''
    image_name: str = ''
    image_base: int = 0
    registers: dict[str, int] = field(default_factory=dict)
    v_registers: dict[str, str] = field(default_factory=dict)  # SIMD V0-V31 (128-bit hex strings)
    esr: int | None = None
    far: int | None = None
    sp: int | None = None
    lbr: list[dict] = field(default_factory=list)  # [{type, addr, module, offset}]


# =============================================================================
# DWARF data structures
# =============================================================================

@dataclass
class AddressInfo:
    """Resolved address: function, source location, and inlines."""
    function: str = ''
    source_loc: str = ''
    inlines: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class VarInfo:
    """A function parameter or local variable."""
    name: str = ''
    type_name: str = ''
    location: str = ''
    reg_name: str | None = None
    byte_size: int = 0
    type_offset: int = 0  # DWARF DIE offset for type expansion
    cu_offset: int = 0  # compilation unit offset
    # Pre-resolved fields (filled by GDB backend, skip _var_to_dict resolution)
    value: int | None = None
    is_expandable: bool | None = None  # None = let _var_to_dict decide
    expand_addr: int | None = None
    string_preview: str | None = None
    var_key: str = ''  # GDB variable object name (for expand_type)


# =============================================================================
# Git reference
# =============================================================================

@dataclass
class GitRef:
    """Resolved git reference for source context."""
    commit: str        # full commit hash
    short: str         # short hash
    summary: str       # commit subject line
    ref_name: str      # original --tag or --commit value

    def label(self) -> str:
        return f"{self.short} ({self.summary})"


# =============================================================================
# Module key normalization (shared across decoders, decoder.py, app.py)
# =============================================================================

def module_key(mod_name: str) -> str:
    """Normalize module name to lookup key (e.g. 'CrashTest.dll' -> 'crashtest').

    Handles double extensions like 'CrashTest.efi.efi' from Dell RSOD.
    """
    key = mod_name
    while True:
        stripped = re.sub(r'\.(dll|efi|debug|so)$', '', key, flags=re.IGNORECASE)
        if stripped == key:
            break
        key = stripped
    return key.lower()


def dwarf_for_frame(
    frame: FrameInfo,
    primary: SymbolSource,
    extra_sources: dict[str, SymbolSource],
) -> DwarfInfo | None:
    """Get the correct DwarfInfo for a frame's module.

    Returns None for modules without dedicated symbols to avoid
    cross-module misresolution.
    """
    if frame.module:
        mk = module_key(frame.module)
        extra = extra_sources.get(mk)
        if extra and extra.dwarf:
            return extra.dwarf
        if mk == primary.name.lower():
            return primary.dwarf
        return None
    return primary.dwarf


# =============================================================================
# Path cleanup (shared by dwarf_info and decoder)
# =============================================================================

def clean_path(raw: str) -> str:
    """Clean a DWARF source path for display.

    Strips discriminator suffixes and normalizes separators.
    The heavy lifting (prefix stripping) is done by DwarfInfo using
    the detected or configured dwarf_prefix.
    """
    raw = re.sub(r'\s*\(discriminator \d+\)', '', raw)
    return raw.replace('\\', '/')


# =============================================================================
# Source file resolution
# =============================================================================

# Cache: (repo_root, lowercase_filename) → list[Path]
_file_index: dict[tuple[str, str], list[Path]] = {}
_file_index_root: str = ''


def _build_file_index(repo_root: Path) -> None:
    """Build an index of all source files under repo_root (once)."""
    global _file_index, _file_index_root
    root_str = str(repo_root)
    if _file_index_root == root_str:
        return
    _file_index = {}
    _file_index_root = root_str
    skip = {'.git', '__pycache__', 'node_modules', 'archive'}
    src_exts = {'.c', '.h', '.cpp', '.hpp', '.cc', '.cxx', '.s', '.asm',
                '.inc', '.inf', '.dsc', '.dec', '.py', '.rs'}
    for p in repo_root.rglob('*'):
        if (p.is_file() and p.suffix.lower() in src_exts
                and not any(part.lower() in skip for part in p.parts)):
            key = (root_str, p.name.lower())
            _file_index.setdefault(key, []).append(p)


def find_source_file(
    repo_root: Path, dwarf_path: str, target_line: int,
) -> Path | None:
    """Resolve a DWARF source path to a file in the repo.

    Strategies (in order):
    1. Direct path match (exact)
    2. Case-insensitive direct match (Windows→Linux cross-compile)
    3. Filename search with line-count validation (build-reorganized files)
       - If ambiguous, pick the match with the most path components in common

    Args:
        repo_root: Root of the repository / source tree.
        dwarf_path: Relative path from DWARF (already prefix-stripped).
        target_line: The line number we need — used to reject files too short.

    Returns:
        Resolved Path or None.
    """
    dwarf_path = dwarf_path.replace('\\', '/')

    # 1. Direct match
    candidate = repo_root / dwarf_path
    if candidate.is_file():
        return candidate

    # 2. Case-insensitive direct match — walk the path components
    resolved = _case_insensitive_lookup(repo_root, dwarf_path)
    if resolved:
        return resolved

    # 3. Filename search with validation
    _build_file_index(repo_root)
    filename_lower = Path(dwarf_path).name.lower()
    matches = _file_index.get((str(repo_root), filename_lower), [])
    if not matches:
        return None

    # Filter: line count must be sufficient, skip archive/backup dirs
    valid: list[Path] = []
    for m in matches:
        rel = m.relative_to(repo_root).as_posix().lower()
        if '/archive/' in rel or rel.startswith('archive/'):
            continue
        try:
            with m.open(encoding='utf-8', errors='replace') as f:
                line_count = sum(1 for _ in f)
            if line_count >= target_line:
                valid.append(m)
        except OSError:
            continue

    if not valid:
        return None
    if len(valid) == 1:
        return valid[0]

    # Multiple valid matches — score by path component overlap,
    # prefer source/src/ paths over others
    dwarf_parts = [p.lower() for p in dwarf_path.split('/')]
    best: Path | None = None
    best_score = -1
    for m in valid:
        rel = m.relative_to(repo_root).as_posix()
        rel_parts = [p.lower() for p in rel.split('/')]
        score = sum(1 for p in dwarf_parts if p in rel_parts)
        # Prefer source/src/ paths
        if rel.lower().startswith('source/src/'):
            score += 10
        if score > best_score:
            best_score = score
            best = m
    return best


def _case_insensitive_lookup(root: Path, rel_path: str) -> Path | None:
    """Walk path components case-insensitively from root."""
    current = root
    for part in rel_path.split('/'):
        if not current.is_dir():
            return None
        part_lower = part.lower()
        found = None
        try:
            for entry in current.iterdir():
                if entry.name.lower() == part_lower:
                    found = entry
                    break
        except OSError:
            return None
        if found is None:
            return None
        current = found
    return current if current.is_file() else None
