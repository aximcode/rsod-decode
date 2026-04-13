"""EDK2 x64 exception handler RSOD format decoder."""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import ClassVar

from ..models import CrashInfo, FrameInfo, SymbolSource, SymbolTable
from .base import (
    FormatDecoder,
    collect_x86_addrs,
    decode_x86_common,
    resolve_addresses_dwarf,
)


# =============================================================================
# Regex patterns
# =============================================================================

RE_EDK2_RIP = re.compile(r'^(RIP\s+-\s+)([0-9A-Fa-f]+)(.*)')
RE_EDK2_REG = re.compile(r'([A-Z0-9]+)\s+-\s+([0-9A-Fa-f]{16})')
RE_EDK2_TYPE = re.compile(
    r'X64 Exception Type\s*-\s*([0-9a-fA-F]+)\(([^)]+)\)', re.IGNORECASE)
RE_EDK2_IMAGEBASE = re.compile(r'ImageBase=([0-9A-Fa-f]+)', re.IGNORECASE)

_RIP_PATTERNS: list[tuple[re.Pattern[str], int]] = [(RE_EDK2_RIP, 2)]


# =============================================================================
# Decoder
# =============================================================================

class Edk2X64Decoder(FormatDecoder):
    """EDK2 x64 exception handler format with REG - VALUE registers."""

    name: ClassVar[str] = 'edk2_x64'
    insn_size: ClassVar[int] = 1

    @staticmethod
    def detect(lines: list[str]) -> bool:
        for line in lines:
            if '!!!! X64 Exception' in line:
                return True
            if RE_EDK2_RIP.match(line):
                return True
        return False

    def detect_base_delta(
        self, lines: list[str], table: SymbolTable,
        base_override: int | None,
    ) -> int:
        if base_override is not None:
            return base_override - table.preferred_base
        for line in lines:
            m = RE_EDK2_IMAGEBASE.search(line)
            if m:
                detected = int(m.group(1), 16)
                if detected != table.preferred_base:
                    return detected - table.preferred_base
        return 0

    def extract_crash_info(
        self, lines: list[str], table: SymbolTable, base_delta: int,
    ) -> CrashInfo:
        info = CrashInfo(fmt=self.name, image_base=table.preferred_base)
        regs: dict[str, int] = {}

        for line in lines:
            if not info.exception_desc:
                m = RE_EDK2_TYPE.search(line)
                if m:
                    info.exception_desc = f"{m.group(2)} (0x{m.group(1)})"

            m = RE_EDK2_RIP.match(line)
            if m:
                info.crash_pc = int(m.group(2), 16)

            for reg, val in RE_EDK2_REG.findall(line):
                regs[reg] = int(val, 16)

        info.registers = regs
        info.sp = regs.get('RSP', regs.get('SP'))

        if info.crash_pc is not None:
            result = table.lookup(info.crash_pc - base_delta)
            info.crash_symbol = result[0].name if result else "not in image"

        return info

    def collect_and_resolve(
        self, lines: list[str], source: SymbolSource,
        extra_sources: dict[str, SymbolSource],
        base_delta: int, log: Callable[[str], None],
    ) -> dict[str, dict[int, list[tuple[str, str]]]]:
        default_key = source.name.lower()
        line_info_by_module: dict[str, dict[int, list[tuple[str, str]]]] = {}

        if source.has_debug_info() and source.binary:
            addrs = collect_x86_addrs(
                lines, source.table, base_delta, _RIP_PATTERNS)
            if addrs:
                info = resolve_addresses_dwarf(source.binary, addrs)
                if info:
                    line_info_by_module[default_key] = info
                    log(f"resolve: {len(info)}/{len(addrs)} addresses")

        return line_info_by_module

    def decode(
        self, lines: list[str], table: SymbolTable, base_delta: int,
        line_info_by_module: dict[str, dict[int, list[tuple[str, str]]]],
        extra_sources: dict[str, SymbolSource] | None,
        default_module_key: str,
    ) -> tuple[list[str], int, list[FrameInfo]]:
        flat_info = line_info_by_module.get(default_module_key, {})
        return decode_x86_common(
            lines, table, base_delta, flat_info,
            rip_patterns=_RIP_PATTERNS,
            reg_patterns=[RE_EDK2_REG])
