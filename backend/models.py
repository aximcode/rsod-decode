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
    esr: int | None = None
    far: int | None = None
    sp: int | None = None


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
# Path cleanup (shared by dwarf_info and decoder)
# =============================================================================

def clean_path(raw: str) -> str:
    """Clean DWARF paths to readable relative form.

    Strips discriminator suffixes, build-directory prefixes, and
    Windows drive letter artifacts from cross-compile paths.
    """
    raw = re.sub(r'\s*\(discriminator \d+\)', '', raw)
    # Strip everything up to the last recognized source root marker
    # Common patterns: .../source/src/..., .../src/..., .../Build/...
    for marker in (r'source[/\\]src[/\\]', r'src[/\\]', r'Build[/\\]'):
        m = re.search(rf'.*[/\\]{marker}(.*)', raw)
        if m:
            return m.group(1).replace('\\', '/')
    # Strip build directory + drive letter artifacts
    cleaned = re.sub(r'^.*[/\\]build[/\\][^/\\]+[/\\]([A-Z]:[/\\])?', '', raw,
                     flags=re.IGNORECASE)
    return cleaned.replace('\\', '/')
