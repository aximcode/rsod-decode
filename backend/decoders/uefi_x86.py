"""Dell UEFI x86-64 RSOD format decoder."""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import ClassVar

from ..models import CrashInfo, FrameInfo, SymbolSource, SymbolTable
from .base import (
    FormatDecoder,
    collect_per_module,
    decode_dell_common,
)


# =============================================================================
# Regex patterns
# =============================================================================

RE_RIP_LINE = re.compile(r'^-->\s*RIP\s+([0-9A-Fa-f]+)(.*)', re.IGNORECASE)
RE_RIP_LINE_WITH_OFFSET = re.compile(
    r'^-->\s*RIP\s+([0-9A-Fa-f]+)\s+\S+\s+\+([0-9A-Fa-f]+)', re.IGNORECASE)
RE_UEFI_X86_REG = re.compile(r'([A-Z0-9]{2,3})=([0-9A-Fa-f]{16})')
RE_UEFI_X86_TYPE = re.compile(r'^Type:\s*(.+?)\s*Source:', re.IGNORECASE)

# Dell RSOD uses short register names; map to canonical x86-64 names
_X86_REG_NORMALIZE: dict[str, str] = {
    'AX': 'RAX', 'BX': 'RBX', 'CX': 'RCX', 'DX': 'RDX',
    'SI': 'RSI', 'DI': 'RDI', 'BP': 'RBP', 'SP': 'RSP',
    'IP': 'RIP',
    '10': 'R10', '11': 'R11', '12': 'R12',
    '13': 'R13', '14': 'R14', '15': 'R15',
    'R8': 'R8', 'R9': 'R9',
}
RE_X86_FRAME = re.compile(
    r'^\s*(s\d+)\s+([0-9A-Fa-f]+)\s+(\S+\.efi(?:\.efi)?)\s+\+([0-9A-Fa-f]+)')
RE_X86_LBR = re.compile(
    r'^(LBR\w+)\s+([0-9A-Fa-f]+)\s+(\S+\.efi)\s+\+([0-9A-Fa-f]+)')


# =============================================================================
# Decoder
# =============================================================================

class UefiX86Decoder(FormatDecoder):
    """Dell UEFI x86-64 format with -->RIP, sNN frames, and XX=HEX registers."""

    name: ClassVar[str] = 'uefi_x86'
    insn_size: ClassVar[int] = 1

    def __init__(self) -> None:
        self.module_bases: dict[int, tuple[str, int]] = {}
        self.module_table: dict[int, str] = {}
        self.image_table: dict[int, tuple[str, int, int]] = {}

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
        lbr_entries: list[dict] = []

        for line in lines:
            if not info.exception_desc:
                m = RE_UEFI_X86_TYPE.search(line)
                if m:
                    info.exception_desc = m.group(1).strip()

            m = RE_RIP_LINE.match(line)
            if m:
                info.crash_pc = int(m.group(1), 16)
                m2 = RE_RIP_LINE_WITH_OFFSET.match(line)
                if m2:
                    abs_addr = int(m2.group(1), 16)
                    offset = int(m2.group(2), 16)
                    info.image_base = abs_addr - offset

            for reg, val in RE_UEFI_X86_REG.findall(line):
                canonical = _X86_REG_NORMALIZE.get(reg, reg)
                regs[canonical] = int(val, 16)

            # LBR entries
            lbr_m = RE_X86_LBR.match(line)
            if lbr_m:
                lbr_entries.append({
                    'type': lbr_m.group(1),
                    'addr': int(lbr_m.group(2), 16),
                    'module': lbr_m.group(3),
                    'offset': int(lbr_m.group(4), 16),
                })

        info.registers = regs
        info.lbr = lbr_entries
        info.sp = regs.get('RSP')

        if info.crash_pc is not None:
            result = table.lookup(info.crash_pc - base_delta)
            info.crash_symbol = result[0].name if result else "not in image"

        return info

    def collect_and_resolve(
        self, lines: list[str], source: SymbolSource,
        extra_sources: dict[str, SymbolSource],
        base_delta: int, log: Callable[[str], None],
    ) -> dict[str, dict[int, list[tuple[str, str]]]]:
        return collect_per_module(
            lines, source, extra_sources, base_delta, log,
            RE_X86_FRAME, RE_RIP_LINE)

    def decode(
        self, lines: list[str], table: SymbolTable, base_delta: int,
        line_info_by_module: dict[str, dict[int, list[tuple[str, str]]]],
        extra_sources: dict[str, SymbolSource] | None,
        default_module_key: str,
    ) -> tuple[list[str], int, list[FrameInfo]]:
        return decode_dell_common(
            lines, table, base_delta, line_info_by_module,
            extra_sources, default_module_key,
            RE_RIP_LINE, RE_X86_FRAME, [RE_UEFI_X86_REG], self)

    def supports_fp_chain(self) -> bool:
        return False

    def supports_rbp_chain(self) -> bool:
        return True
