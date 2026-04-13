"""Dell UEFI ARM64 RSOD format decoder."""
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

RE_PC_LINE = re.compile(r'^-->\s*PC\s+([0-9A-Fa-f]+)(.*)', re.IGNORECASE)
RE_PC_LINE_WITH_OFFSET = re.compile(
    r'^-->\s*PC\s+([0-9A-Fa-f]+)\s+\S+\s+\+([0-9A-Fa-f]+)', re.IGNORECASE)
RE_ARM64_FRAME = re.compile(
    r'^\s*(s\d+)\s+([0-9A-Fa-f]+)\s+(\S+\.efi)\s+\+([0-9A-Fa-f]+)')
RE_ARM64_REG = re.compile(
    r'(X\d+|FP|LR|SP|ELR|SPSR|FPSR|FAR|PC|ESR)=(?:0x)?([0-9A-Fa-f]+)')
RE_UEFI_ARM64_TYPE = re.compile(r'^Type:\s*(.+)', re.IGNORECASE)
RE_UEFI_ARM64_VREG = re.compile(
    r'(V\d+)=0x([0-9A-Fa-f]{16})\s+([0-9A-Fa-f]{16})')


# =============================================================================
# Decoder
# =============================================================================

class UefiArm64Decoder(FormatDecoder):
    """Dell UEFI ARM64 format with -->PC and sNN frame lines."""

    name: ClassVar[str] = 'uefi_arm64'
    insn_size: ClassVar[int] = 4

    def __init__(self) -> None:
        self.module_bases: dict[int, tuple[str, int]] = {}
        self.module_table: dict[int, str] = {}
        self.image_table: dict[int, tuple[str, int, int]] = {}

    @staticmethod
    def detect(lines: list[str]) -> bool:
        for line in lines:
            if RE_PC_LINE.match(line):
                return True
            if RE_ARM64_FRAME.match(line):
                return True
            if line.startswith('--> PC') or line.startswith('-->PC'):
                return True
            if RE_ARM64_REG.search(line) and 'X0=' in line:
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
        v_regs: dict[str, str] = {}

        for line in lines:
            if not info.exception_desc:
                m = RE_UEFI_ARM64_TYPE.search(line)
                if m:
                    info.exception_desc = m.group(1).strip()

            m = RE_PC_LINE.match(line)
            if m:
                info.crash_pc = int(m.group(1), 16)
                # Extract image_base from -->PC ABSADDR Module +OFFSET
                m2 = RE_PC_LINE_WITH_OFFSET.match(line)
                if m2:
                    abs_addr = int(m2.group(1), 16)
                    offset = int(m2.group(2), 16)
                    info.image_base = abs_addr - offset

            for reg, val in RE_ARM64_REG.findall(line):
                regs[reg] = int(val, 16)

            for vreg, hi, lo in RE_UEFI_ARM64_VREG.findall(line):
                v_regs[vreg] = f'0x{hi}_{lo}'

        info.registers = regs
        info.v_registers = v_regs
        info.sp = regs.get('SP')
        info.esr = regs.get('ESR')
        info.far = regs.get('FAR')

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
            RE_ARM64_FRAME, RE_PC_LINE)

    def decode(
        self, lines: list[str], table: SymbolTable, base_delta: int,
        line_info_by_module: dict[str, dict[int, list[tuple[str, str]]]],
        extra_sources: dict[str, SymbolSource] | None,
        default_module_key: str,
    ) -> tuple[list[str], int, list[FrameInfo]]:
        return decode_dell_common(
            lines, table, base_delta, line_info_by_module,
            extra_sources, default_module_key,
            RE_PC_LINE, RE_ARM64_FRAME, [RE_ARM64_REG], self)

    def supports_fp_chain(self) -> bool:
        return True
