"""FormatDecoder ABC and shared helpers for RSOD format decoders."""
from __future__ import annotations

import re
import struct
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import ClassVar

from ..models import (
    CrashInfo, FrameInfo, MapSymbol, SymbolSource, SymbolTable,
    clean_path, module_key,
)
from ..dwarf_backend import DwarfInfo

# Re-export from submodules for backward compatibility
from .annotations import (  # noqa: F401
    annotate_regs, format_annotation, lookup_and_annotate,
    source_loc,
)
from .unwinding import (  # noqa: F401
    parse_stack_dump, walk_fp_chain, walk_rbp_chain,
)


# =============================================================================
# Abstract base class
# =============================================================================

class FormatDecoder(ABC):
    """Base class for RSOD format decoders.

    Each subclass handles one RSOD text format: detection, crash info
    extraction, address collection + DWARF resolution, and line-by-line
    decode with annotation.
    """
    name: ClassVar[str]
    insn_size: ClassVar[int]  # 4 for ARM64, 1 for x86

    @staticmethod
    @abstractmethod
    def detect(lines: list[str]) -> bool:
        """Return True if this decoder can handle the given RSOD lines."""

    @abstractmethod
    def detect_base_delta(
        self, lines: list[str], table: SymbolTable,
        base_override: int | None,
    ) -> int:
        """Compute the base address delta for symbol lookup."""

    @abstractmethod
    def extract_crash_info(
        self, lines: list[str], table: SymbolTable, base_delta: int,
    ) -> CrashInfo:
        """Extract crash metadata (exception type, PC, registers)."""

    @abstractmethod
    def collect_and_resolve(
        self, lines: list[str], source: SymbolSource,
        extra_sources: dict[str, SymbolSource],
        base_delta: int, log: Callable[[str], None],
    ) -> dict[str, dict[int, list[tuple[str, str]]]]:
        """Collect addresses and resolve via DWARF.

        Returns line_info_by_module: {module_key: {addr: [(func, loc), ...]}}.
        """

    @abstractmethod
    def decode(
        self, lines: list[str], table: SymbolTable, base_delta: int,
        line_info_by_module: dict[str, dict[int, list[tuple[str, str]]]],
        extra_sources: dict[str, SymbolSource] | None,
        default_module_key: str,
    ) -> tuple[list[str], int, list[FrameInfo]]:
        """Decode RSOD lines into annotated output + frames.

        Returns (annotated_lines, resolved_count, frames).
        """

    def supports_fp_chain(self) -> bool:
        """Whether this format supports FP chain unwinding."""
        return False


# =============================================================================
# Shared regex patterns
# =============================================================================

RE_STACK_LINE = re.compile(
    r'^(\s+[0-9A-Fa-f]+\s+)([0-9A-Fa-f]{16})(\s+.*)$')

RE_STACK_DUMP_LINE = re.compile(
    r'^\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]{16})\s')

# Multi-value stack dump (EDK2 ARM64: 4 values per line, optional > marker and colon)
RE_STACK_DUMP_ADDR = re.compile(r'^\s*>?\s*([0-9A-Fa-f]+):?\s+')
RE_HEX16 = re.compile(r'\b([0-9A-Fa-f]{16})\b')



# (Annotation helpers moved to annotations.py)


# =============================================================================
# Frame builder
# =============================================================================

def make_frame(
    index: int, address: int, module: str,
    sym: MapSymbol, offset: int,
    line_info: dict[int, list[tuple[str, str]]],
    info_key: int,
) -> FrameInfo:
    """Build a FrameInfo from a resolved symbol."""
    entries = line_info.get(info_key, [])
    loc = entries[0][1] if entries else ''
    inlines = entries[1:] if len(entries) > 1 else []
    return FrameInfo(
        index=index, address=address, module=module,
        symbol=sym, sym_offset=offset, source_loc=loc, inlines=inlines)


# =============================================================================
# Address extraction
# =============================================================================

def extract_addr_from_line(
    line: str, patterns: list[tuple[re.Pattern[str], int]],
) -> int | None:
    """Try each (pattern, group_index) pair; return first matched address."""
    for pat, group in patterns:
        m = pat.match(line)
        if m:
            return int(m.group(group), 16)
    return None


# =============================================================================
# DWARF address resolution
# =============================================================================

def resolve_addresses_dwarf(
    dwarf_info: DwarfInfo, addresses: list[int],
) -> dict[int, list[tuple[str, str]]]:
    """Resolve addresses via DwarfInfo.

    Returns {addr: [(func, file:line), ...]} for the line_info dict format.
    """
    resolved_raw = dwarf_info.resolve_addresses(addresses)
    result: dict[int, list[tuple[str, str]]] = {}
    for addr, info in resolved_raw.items():
        pairs: list[tuple[str, str]] = []
        if info.function and info.source_loc:
            pairs.append((info.function, clean_path(info.source_loc)))
        for func, loc in info.inlines:
            pairs.append((func, clean_path(loc)))
        if pairs:
            result[addr] = pairs
    return result


# =============================================================================
# Shared Dell UEFI decode + collect (uefi_arm64 + uefi_x86)
# =============================================================================

def collect_per_module(
    lines: list[str], source: SymbolSource,
    extra_sources: dict[str, SymbolSource],
    base_delta: int, log: Callable[[str], None],
    frame_pattern: re.Pattern[str],
    pc_pattern: re.Pattern[str] | None,
) -> dict[str, dict[int, list[tuple[str, str]]]]:
    """Collect addresses per-module from sNN frame + PC/RIP lines, then DWARF-resolve."""
    default_key = source.name.lower()
    line_info_by_module: dict[str, dict[int, list[tuple[str, str]]]] = {}

    module_addrs: dict[str, list[int]] = {}
    for line in lines:
        fm = frame_pattern.match(line)
        if fm:
            mk = module_key(fm.group(3))
            module_addrs.setdefault(mk, []).append(int(fm.group(4), 16))
        if pc_pattern:
            pc = pc_pattern.match(line)
            if pc:
                module_addrs.setdefault(default_key, []).append(
                    int(pc.group(1), 16))

    dedicated: dict[str, SymbolSource] = {
        k: v for k, v in extra_sources.items() if v.has_debug_info()}
    for mk, addrs in module_addrs.items():
        mod_src = dedicated.get(mk, source)
        if mod_src.has_debug_info() and mod_src.dwarf:
            src_key = mk if mk in dedicated else default_key
            info = resolve_addresses_dwarf(mod_src.dwarf, addrs)
            if info:
                line_info_by_module.setdefault(src_key, {}).update(info)
                log(f"resolve [{mk}]: {len(info)}/{len(addrs)} resolved")

    return line_info_by_module


def decode_dell_common(
    lines: list[str], table: SymbolTable, base_delta: int,
    line_info_by_module: dict[str, dict[int, list[tuple[str, str]]]],
    extra_sources: dict[str, SymbolSource] | None,
    default_module_key: str,
    pc_pattern: re.Pattern[str],
    frame_pattern: re.Pattern[str],
    reg_patterns: list[re.Pattern[str]],
    decoder: object,
) -> tuple[list[str], int, list[FrameInfo]]:
    """Shared Dell UEFI decode for both ARM64 and x86 sNN-format RSODs."""
    resolved = 0
    out: list[str] = []
    frames: list[FrameInfo] = []
    frame_idx = 0
    seen_modules: dict[str, int] = {}

    default_info = line_info_by_module.get(default_module_key, {})

    for line in lines:
        # --> PC/RIP line
        pc_match = pc_pattern.match(line)
        if pc_match:
            if frames:
                break
            addr = int(pc_match.group(1), 16)
            ann = lookup_and_annotate(
                addr - base_delta, table, default_info)
            if ann:
                out.append(f"{line} {ann}")
                resolved += 1
            else:
                out.append(line)
            continue

        # sNN frame lines
        fm = frame_pattern.match(line)
        if fm:
            module = fm.group(3)
            abs_addr = int(fm.group(2), 16)
            offset_in_module = int(fm.group(4), 16)
            mod_base = abs_addr - offset_in_module

            mk = module_key(module)
            if mk not in seen_modules:
                idx = len(getattr(decoder, 'module_bases', {}))
                decoder.module_bases[idx] = (module, mod_base)
                seen_modules[mk] = idx

            src = (extra_sources or {}).get(mk)
            if src:
                use_table = src.table
            elif mk == default_module_key:
                use_table = table
            else:
                use_table = None
            use_info = line_info_by_module.get(
                mk, line_info_by_module.get(
                    default_module_key, {}))

            result = None
            if use_table:
                if use_table.preferred_base == 0:
                    lookup_addr = offset_in_module
                else:
                    lookup_addr = use_table.preferred_base + offset_in_module
                result = use_table.lookup(lookup_addr)

            if result:
                sym, off = result
                loc = source_loc(use_info, offset_in_module)
                out.append(
                    f"{line}  {format_annotation(sym, off, loc)}")
                resolved += 1
                frames.append(make_frame(
                    frame_idx, offset_in_module, module,
                    sym, off, use_info, offset_in_module))
                frame_idx += 1
            else:
                out.append(line)
                frames.append(FrameInfo(
                    index=frame_idx, address=offset_in_module,
                    module=module))
                frame_idx += 1
            continue

        # Register lines
        if any(pat.search(line) for pat in reg_patterns):
            out.append(annotate_regs(line, reg_patterns, table, base_delta))
            continue

        out.append(line)

    # Parse image table if present
    img_table = parse_image_table(lines)
    if img_table:
        decoder.module_bases = {
            i: (name, base) for i, (name, base, _) in img_table.items()}
        decoder.image_table = img_table

    return out, resolved, frames


# =============================================================================
# Image table parser (Dell UEFI formats)
# =============================================================================

RE_IMAGE_TABLE_ENTRY = re.compile(
    r'^\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+(\S+)')

def parse_image_table(
    lines: list[str],
) -> dict[int, tuple[str, int, int]]:
    """Parse the EFI Debug Support Table into {index: (name, base, size)}.

    Format:
        EFI Debug Support Table ...
          BASE SIZE NAME
          BASE SIZE NAME
    """
    table: dict[int, tuple[str, int, int]] = {}
    in_table = False
    idx = 0
    for line in lines:
        if 'EFI Debug Support Table' in line and 'TableSize' in line:
            in_table = True
            continue
        if not in_table:
            continue
        m = RE_IMAGE_TABLE_ENTRY.match(line)
        if not m:
            if in_table and line.strip():
                in_table = False
            continue
        base = int(m.group(1), 16)
        size = int(m.group(2), 16)
        name = m.group(3)
        table[idx] = (name, base, size)
        idx += 1
    return table



# (Stack dump parser and chain walkers moved to unwinding.py)

# =============================================================================
# Shared x86 decode logic (used by both UefiX86 and Edk2X64)
# =============================================================================

def decode_x86_common(
    lines: list[str], table: SymbolTable, base_delta: int,
    line_info: dict[int, list[tuple[str, str]]],
    rip_patterns: list[tuple[re.Pattern[str], int]],
    reg_patterns: list[re.Pattern[str]],
) -> tuple[list[str], int, list[FrameInfo]]:
    """Shared x86/EDK2 line-by-line decode.

    Returns (annotated_lines, resolved_count, frames).
    """
    in_registers = False
    in_stack = False
    resolved = 0
    out: list[str] = []
    frames: list[FrameInfo] = []
    frame_idx = 0

    for line in lines:
        has_regs = any(pat.search(line) is not None for pat in reg_patterns)
        if has_regs and not in_stack:
            in_registers = True

        if line.strip().startswith('Stack Dump'):
            in_stack = True
            in_registers = False
            out.append(line)
            continue

        if in_registers and RE_STACK_LINE.match(line):
            in_stack = True
            in_registers = False

        if in_registers and not in_stack:
            out.append(annotate_regs(line, reg_patterns, table, base_delta))
            continue

        # RIP / crash PC line
        rip_addr = extract_addr_from_line(line, rip_patterns)
        if rip_addr is not None:
            ann = lookup_and_annotate(rip_addr - base_delta, table, line_info)
            if ann:
                out.append(f"{line} {ann}")
                resolved += 1
            else:
                out.append(line)
            continue

        # Stack dump lines
        sm = RE_STACK_LINE.match(line) if in_stack else None
        if sm:
            value = int(sm.group(2), 16)
            adjusted = value - base_delta
            result = table.lookup(adjusted)
            if result:
                sym, offset = result
                out.append(f"{line} {format_annotation(
                    sym, offset, source_loc(line_info, adjusted))}")
                resolved += 1
                frames.append(make_frame(
                    frame_idx, value, '', sym, offset, line_info, adjusted))
                frame_idx += 1
            else:
                out.append(line)
            continue

        out.append(line)

    return out, resolved, frames


# =============================================================================
# Shared x86 address collector
# =============================================================================

def collect_x86_addrs(
    lines: list[str], table: SymbolTable, base_delta: int,
    rip_patterns: list[tuple[re.Pattern[str], int]],
) -> list[int]:
    """Collect resolvable addresses from x86 RSOD lines."""
    addrs: list[int] = []
    in_stack = False
    for line in lines:
        if line.strip().startswith('Stack Dump'):
            in_stack = True
            continue
        rip_addr = extract_addr_from_line(line, rip_patterns)
        if rip_addr is not None:
            adj = rip_addr - base_delta
            if table.lookup(adj):
                addrs.append(adj)
        if in_stack:
            sm = RE_STACK_LINE.match(line)
            if sm:
                adj = int(sm.group(2), 16) - base_delta
                if table.lookup(adj):
                    addrs.append(adj)
    return addrs
