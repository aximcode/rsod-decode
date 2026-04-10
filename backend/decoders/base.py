"""FormatDecoder ABC and shared helpers for RSOD format decoders."""
from __future__ import annotations

import re
import struct
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import ClassVar

from ..models import (
    CrashInfo, FrameInfo, MapSymbol, SymbolSource, SymbolTable,
    clean_path,
)
from ..dwarf_info import DwarfInfo


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


# =============================================================================
# Annotation helpers
# =============================================================================

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


# =============================================================================
# Register annotation
# =============================================================================

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


def walk_rbp_chain(
    rbp: int, ret_addr: int, stack_memory: bytes, stack_base: int,
    max_frames: int = 32,
) -> list[tuple[int, int]]:
    """Walk the x86-64 RBP chain through raw stack memory.

    x86-64 frame layout: [RBP] = saved_RBP, [RBP+8] = return_addr.
    Returns list of (return_address, frame_pointer) tuples.
    """
    stack_end = stack_base + len(stack_memory)
    frames: list[tuple[int, int]] = []

    if ret_addr:
        frames.append((ret_addr, rbp))

    cur_rbp = rbp
    for _ in range(max_frames):
        if cur_rbp == 0 or cur_rbp < stack_base or cur_rbp + 16 > stack_end:
            break
        offset = cur_rbp - stack_base
        saved_rbp = struct.unpack_from('<Q', stack_memory, offset)[0]
        saved_ret = struct.unpack_from('<Q', stack_memory, offset + 8)[0]
        if saved_ret == 0:
            break
        frames.append((saved_ret, saved_rbp))
        if saved_rbp <= cur_rbp:
            break  # RBP must grow (stack grows down, frames go up)
        cur_rbp = saved_rbp

    return frames


# Stack dump parser and FP chain walker (ARM64)
# =============================================================================

def parse_stack_dump(lines: list[str]) -> tuple[int, bytes]:
    """Parse hex stack dump lines into a contiguous memory buffer.

    Handles both single-value lines (Dell: ``ADDR  VALUE ...``) and
    multi-value lines (EDK2: ``ADDR: V1 V2 V3 V4``).

    Returns (base_address, memory_bytes). Gaps are filled with zeros.
    """
    entries: list[tuple[int, int]] = []
    in_dump = False
    for line in lines:
        if 'stack dump' in line.lower():
            in_dump = True
            continue
        if not in_dump:
            continue
        addr_m = RE_STACK_DUMP_ADDR.match(line)
        if not addr_m:
            continue
        base_addr = int(addr_m.group(1), 16)
        # Find all 16-hex-digit values after the address
        rest = line[addr_m.end():]
        values = RE_HEX16.findall(rest)
        for i, val_hex in enumerate(values):
            entries.append((base_addr + i * 8, int(val_hex, 16)))

    if not entries:
        return 0, b''

    entries.sort(key=lambda x: x[0])
    base = entries[0][0]
    end = entries[-1][0] + 8
    buf = bytearray(end - base)
    for addr, val in entries:
        struct.pack_into('<Q', buf, addr - base, val)
    return base, bytes(buf)


def walk_fp_chain(
    fp: int, lr: int, stack_memory: bytes, stack_base: int,
    max_frames: int = 32,
) -> list[tuple[int, int]]:
    """Walk the ARM64 frame pointer chain through raw stack memory.

    Returns list of (return_address, frame_pointer) tuples.
    The first entry is the crash LR.
    """
    stack_end = stack_base + len(stack_memory)
    frames: list[tuple[int, int]] = []

    if lr:
        frames.append((lr, fp))

    for _ in range(max_frames):
        if fp == 0 or fp < stack_base or fp + 16 > stack_end:
            break
        off = fp - stack_base
        saved_fp = struct.unpack_from('<Q', stack_memory, off)[0]
        saved_lr = struct.unpack_from('<Q', stack_memory, off + 8)[0]
        if saved_lr == 0:
            break
        frames.append((saved_lr, saved_fp))
        fp = saved_fp

    return frames


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
