"""Symbol table loading from MSVC map files and ELF binaries."""
from __future__ import annotations

import re
import sys
from collections.abc import Callable
from pathlib import Path

from .models import MapSymbol, SymbolTable, SymbolSource
from .dwarf_backend import DwarfInfo


class SymbolLoadError(Exception):
    """Raised when a symbol file cannot be loaded."""


# =============================================================================
# MSVC map file parser
# =============================================================================

RE_PREFERRED_BASE = re.compile(
    r'Preferred load address is\s+([0-9A-Fa-f]+)', re.IGNORECASE)

RE_SYMBOL_ENTRY = re.compile(
    r'^\s+([0-9A-Fa-f]+):[0-9A-Fa-f]+\s+'
    r'(\S+)\s+([0-9A-Fa-f]+)\s+(?:([fi])\s+)?(\S+)\s*$')


def parse_map_file(path: Path) -> SymbolTable:
    """Parse an MSVC linker map file."""
    all_lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    table = SymbolTable()

    for line in all_lines:
        m = RE_PREFERRED_BASE.search(line)
        if m:
            table.preferred_base = int(m.group(1), 16)
            break

    raw: list[MapSymbol] = []
    for line in all_lines:
        m = RE_SYMBOL_ENTRY.match(line)
        if not m:
            continue
        seg, name, addr_hex, flag, obj = m.groups()
        addr = int(addr_hex, 16)
        if addr == 0:
            continue
        is_func = flag in ('f', 'i') or seg in ('0001', '0002')
        raw.append(MapSymbol(addr, name, obj.strip(), is_func))

    return _build_table(table, raw)


# =============================================================================
# ELF / symbol table helpers
# =============================================================================

def _build_table(table: SymbolTable, raw: list[MapSymbol]) -> SymbolTable:
    """Sort, deduplicate, and finalize a SymbolTable."""
    raw.sort(key=lambda s: s.address)
    seen: set[int] = set()
    for sym in raw:
        if sym.address not in seen:
            seen.add(sym.address)
            table.symbols.append(sym)
            table.addresses.append(sym.address)
    if table.symbols:
        table.image_end = table.symbols[-1].address + 0x10000
    return table


def is_elf(path: Path) -> bool:
    """Check if a file is an ELF binary."""
    try:
        with path.open('rb') as f:
            return f.read(4) == b'\x7fELF'
    except OSError:
        return False


def load_symbols(path: Path, log: Callable[[str], None] | None = None,
                 dwarf_prefix: str | None = None,
                 repo_root: Path | None = None) -> SymbolSource:
    """Auto-detect symbol file format and load.

    Args:
        path: Path to the symbol file (.map or ELF).
        log: Optional callable(str) for status messages.
             Defaults to printing to stderr.
        dwarf_prefix: Optional prefix to strip from DWARF paths.
        repo_root: Optional repo root for auto-detecting dwarf_prefix.
    """
    if log is None:
        def log(msg: str) -> None:
            print(msg, file=sys.stderr)

    elf_path: Path | None = None
    dwarf_info: DwarfInfo | None = None

    if is_elf(path):
        elf_path = path
        try:
            dwarf_info = DwarfInfo(path, dwarf_prefix=dwarf_prefix,
                                   repo_root=repo_root)
            raw = dwarf_info.get_symbols()
        except Exception as e:
            raise SymbolLoadError(f"failed to read ELF {path}: {e}") from e
        table = SymbolTable()
        _build_table(table, [MapSymbol(a, n, '', f) for a, n, f in raw])
        src = 'ELF+DWARF'
    else:
        table = parse_map_file(path)
        src = 'MAP'

    func_count = sum(1 for s in table.symbols if s.is_function)
    data_count = len(table.symbols) - func_count
    log(f"Loaded {len(table.symbols)} symbols ({func_count} code, "
        f"{data_count} data) from {path.name} [{src}]")
    if table.preferred_base:
        log(f"Preferred base: 0x{table.preferred_base:X}")
    if table.symbols:
        log(f"Symbol range: 0x{table.addresses[0]:X} - "
            f"0x{table.addresses[-1]:X}")
    if dwarf_info:
        log("DWARF debug info via pyelftools (native)")
        if dwarf_info.dwarf_prefix:
            log(f"DWARF prefix: {dwarf_info.dwarf_prefix}")

    return SymbolSource(table=table, elf_path=elf_path,
                        name=path.stem, dwarf=dwarf_info)
