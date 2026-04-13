"""Symbol annotation helpers for RSOD decoder output."""
from __future__ import annotations

import re

from ..models import MapSymbol, SymbolTable


def format_annotation(
    sym: MapSymbol, offset: int, source_loc: str = '',
) -> str:
    """Format a symbol lookup result for inline annotation."""
    obj = f"({sym.object_file})" if sym.object_file else ''
    loc = f"  [{source_loc}]" if source_loc else ''
    if sym.is_function:
        return f"<- {sym.name}{obj} + 0x{offset:03X}{loc}"
    return f"--data-- <- {sym.name}{obj}"


def source_loc(
    line_info: dict[int, list[tuple[str, str]]], addr: int,
) -> str:
    """Get the primary source location for an address."""
    entries = line_info.get(addr, [])
    return entries[0][1] if entries else ''


def lookup_and_annotate(
    addr: int, table: SymbolTable,
    line_info: dict[int, list[tuple[str, str]]],
) -> str | None:
    """Look up addr, return annotation string or None."""
    result = table.lookup(addr)
    if not result:
        return None
    sym, offset = result
    return format_annotation(sym, offset, source_loc(line_info, addr))


def annotate_regs(
    line: str, patterns: list[re.Pattern[str]],
    table: SymbolTable, base_delta: int,
) -> str:
    """Annotate register values that resolve to symbols."""
    matches: list[tuple[str, str]] = []
    for pat in patterns:
        matches = pat.findall(line)
        if matches:
            break
    if not matches:
        return line
    anns: list[str] = []
    for reg, val_hex in matches:
        result = table.lookup(int(val_hex, 16) - base_delta)
        if result:
            anns.append(f"{reg}={format_annotation(*result)}")
    return f"{line}  [{', '.join(anns)}]" if anns else line
