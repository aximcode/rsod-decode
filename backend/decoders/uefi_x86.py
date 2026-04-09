"""Dell UEFI x86-64 RSOD format decoder."""
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

RE_RIP_LINE = re.compile(r'^-->\s*RIP\s+([0-9A-Fa-f]+)(.*)', re.IGNORECASE)
RE_UEFI_X86_REG = re.compile(r'([A-Z0-9]{2})=([0-9A-Fa-f]{16})')
RE_UEFI_X86_TYPE = re.compile(r'^Type:\s*(.+?)\s*Source:', re.IGNORECASE)

_RIP_PATTERNS: list[tuple[re.Pattern[str], int]] = [(RE_RIP_LINE, 1)]


# =============================================================================
# Decoder
# =============================================================================

class UefiX86Decoder(FormatDecoder):
    """Dell UEFI x86-64 format with -->RIP and XX=HEX registers."""

    name: ClassVar[str] = 'uefi_x86'
    insn_size: ClassVar[int] = 1

    @staticmethod
    def detect(lines: list[str]) -> bool:
        for line in lines:
            if RE_RIP_LINE.match(line):
                return True
        return False

    def detect_base_delta(
        self, lines: list[str], table: SymbolTable,
        base_override: int | None,
    ) -> int:
        if base_override is not None:
            return base_override - table.preferred_base
        return 0

    def extract_crash_info(
        self, lines: list[str], table: SymbolTable, base_delta: int,
    ) -> CrashInfo:
        info = CrashInfo(fmt=self.name, image_base=table.preferred_base)
        regs: dict[str, int] = {}

        for line in lines:
            if not info.exception_desc:
                m = RE_UEFI_X86_TYPE.search(line)
                if m:
                    info.exception_desc = m.group(1).strip()

            m = RE_RIP_LINE.match(line)
            if m:
                info.crash_pc = int(m.group(1), 16)

            for reg, val in RE_UEFI_X86_REG.findall(line):
                regs[reg] = int(val, 16)

        info.registers = regs
        info.sp = regs.get('SP', regs.get('RSP'))

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

        if source.has_debug_info() and source.dwarf:
            addrs = collect_x86_addrs(
                lines, source.table, base_delta, _RIP_PATTERNS)
            if addrs:
                info = resolve_addresses_dwarf(source.dwarf, addrs)
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
            reg_patterns=[RE_UEFI_X86_REG])
