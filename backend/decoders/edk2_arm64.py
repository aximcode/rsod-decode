"""EDK2 ARM64 exception handler RSOD format decoder (QEMU serial output)."""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import ClassVar

from ..models import CrashInfo, FrameInfo, SymbolSource, SymbolTable
from .base import (
    FormatDecoder,
    annotate_regs,
    format_annotation,
    make_frame,
    resolve_addresses_dwarf,
    source_loc,
)


# =============================================================================
# Regex patterns
# =============================================================================

# "Synchronous Exception at 0x000000005CB55F4C"
RE_EDK2_ARM64_EXCEPTION = re.compile(
    r'(Synchronous|SError|IRQ|FIQ)\s+Exception\s+at\s+0x([0-9A-Fa-f]+)',
    re.IGNORECASE)

# "PC 0x00005CB55F4C (0x00005CB54000+0x00001F4C) [ 0] CrashTest.dll"
RE_EDK2_ARM64_PC_FRAME = re.compile(
    r'^PC\s+0x([0-9A-Fa-f]+)\s+'
    r'\(0x([0-9A-Fa-f]+)\+0x([0-9A-Fa-f]+)\)\s+'
    r'\[\s*(\d+)\]\s+(\S+)')

# "  X0 0x0000000000000000   X1 0x0000000000000001"
# "  SP 0x00000000476865A0  ELR 0x000000005CB55F4C  SPSR 0xA0000205"
# " ESR 0x96000047          FAR 0x0000000000000000"
RE_EDK2_ARM64_REG = re.compile(
    r'(X\d+|FP|LR|SP|ELR|SPSR|FPSR|FAR|ESR)\s+0x([0-9A-Fa-f]+)')

# "[ 0] /home/.../CrashTest.dll"
RE_EDK2_ARM64_MODULE = re.compile(r'^\[\s*(\d+)\]\s+(\S+)')

# "Data abort: Translation fault, third level"
RE_EDK2_ARM64_ABORT_DESC = re.compile(
    r'^(Data abort|Instruction abort|PC alignment|SP alignment'
    r'|SError|Breakpoint|Software Step|Watchpoint'
    r'|BRK instruction|SVC instruction|HVC instruction|SMC instruction'
    r'|Trapped FP|Illegal execution state):\s*(.+)',
    re.IGNORECASE)


# =============================================================================
# Decoder
# =============================================================================

class Edk2Arm64Decoder(FormatDecoder):
    """EDK2 ARM64 exception handler format (QEMU serial output).

    Frame format: ``PC 0xABS (0xBASE+0xOFFSET) [ N] Module.dll``
    Register format: ``X0 0xVALUE`` (space-separated, 0x prefix, no ``=``).
    Module table: ``[ N] /path/to/Module.dll`` with debug symbol paths.
    """

    name: ClassVar[str] = 'edk2_arm64'
    insn_size: ClassVar[int] = 4

    def __init__(self) -> None:
        # Populated during decode() — module index → debug path
        self.module_table: dict[int, str] = {}

    @staticmethod
    def detect(lines: list[str]) -> bool:
        for line in lines:
            if RE_EDK2_ARM64_EXCEPTION.search(line):
                return True
            if RE_EDK2_ARM64_PC_FRAME.match(line):
                return True
        return False

    def detect_base_delta(
        self, lines: list[str], table: SymbolTable,
        base_override: int | None,
    ) -> int:
        # Each frame carries its own base — no global delta needed.
        if base_override is not None:
            return base_override - table.preferred_base
        return 0

    def extract_crash_info(
        self, lines: list[str], table: SymbolTable, base_delta: int,
    ) -> CrashInfo:
        info = CrashInfo(fmt=self.name, image_base=table.preferred_base)
        regs: dict[str, int] = {}

        for line in lines:
            # Exception description: "Synchronous Exception at 0x..."
            if not info.exception_desc:
                m = RE_EDK2_ARM64_EXCEPTION.search(line)
                if m:
                    info.exception_desc = f"{m.group(1)} Exception"

            # Refine with abort description: "Data abort: Translation fault..."
            m = RE_EDK2_ARM64_ABORT_DESC.match(line)
            if m:
                info.exception_desc = (
                    f"{info.exception_desc} — {m.group(1)}: {m.group(2)}"
                    if info.exception_desc
                    else f"{m.group(1)}: {m.group(2)}")

            # Crash PC from first PC frame line
            if info.crash_pc is None:
                m = RE_EDK2_ARM64_PC_FRAME.match(line)
                if m:
                    info.crash_pc = int(m.group(1), 16)

            # Registers
            for reg, val in RE_EDK2_ARM64_REG.findall(line):
                regs[reg] = int(val, 16)

        info.registers = regs
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
        default_key = source.name.lower()
        line_info_by_module: dict[str, dict[int, list[tuple[str, str]]]] = {}

        # Collect addresses per-module from PC frame lines
        module_addrs: dict[str, list[int]] = {}
        for line in lines:
            m = RE_EDK2_ARM64_PC_FRAME.match(line)
            if m:
                offset = int(m.group(3), 16)
                mod_name = m.group(5)
                mod_key = _module_key(mod_name)
                module_addrs.setdefault(mod_key, []).append(offset)

        # Resolve per-module via DWARF
        dedicated: dict[str, SymbolSource] = {
            k: v for k, v in extra_sources.items() if v.has_debug_info()}
        for mod_key, addrs in module_addrs.items():
            mod_src = dedicated.get(mod_key, source)
            if mod_src.has_debug_info() and mod_src.dwarf:
                src_key = mod_key if mod_key in dedicated else default_key
                info = resolve_addresses_dwarf(mod_src.dwarf, addrs)
                if info:
                    line_info_by_module.setdefault(src_key, {}).update(info)
                    log(f"resolve [{mod_key}]: "
                        f"{len(info)}/{len(addrs)} resolved")

        return line_info_by_module

    def decode(
        self, lines: list[str], table: SymbolTable, base_delta: int,
        line_info_by_module: dict[str, dict[int, list[tuple[str, str]]]],
        extra_sources: dict[str, SymbolSource] | None,
        default_module_key: str,
    ) -> tuple[list[str], int, list[FrameInfo]]:
        resolved = 0
        out: list[str] = []
        frames: list[FrameInfo] = []
        frame_idx = 0

        # Parse module table for logging / future auto-loading
        self.module_table = _parse_module_table(lines)

        for line in lines:
            # PC frame lines
            m = RE_EDK2_ARM64_PC_FRAME.match(line)
            if m:
                offset = int(m.group(3), 16)
                mod_name = m.group(5)
                mod_key = _module_key(mod_name)

                src = (extra_sources or {}).get(mod_key)
                use_table = src.table if src else table
                use_info = line_info_by_module.get(
                    mod_key, line_info_by_module.get(
                        default_module_key, {}))

                if use_table.preferred_base == 0:
                    lookup_addr = offset
                else:
                    lookup_addr = use_table.preferred_base + offset

                result = use_table.lookup(lookup_addr)
                if result:
                    sym, off = result
                    loc = source_loc(use_info, offset)
                    out.append(
                        f"{line}  {format_annotation(sym, off, loc)}")
                    resolved += 1
                    frames.append(make_frame(
                        frame_idx, offset, mod_name,
                        sym, off, use_info, offset))
                    frame_idx += 1
                else:
                    out.append(line)
                    frames.append(FrameInfo(
                        index=frame_idx, address=offset, module=mod_name))
                    frame_idx += 1
                continue

            # Register lines (skip vector registers Vnn)
            if RE_EDK2_ARM64_REG.search(line) and not re.match(r'^\s*V\d+', line):
                out.append(annotate_regs(
                    line, [RE_EDK2_ARM64_REG], table, base_delta))
                continue

            out.append(line)

        return out, resolved, frames

    def supports_fp_chain(self) -> bool:
        return True


# =============================================================================
# Helpers
# =============================================================================

def _module_key(mod_name: str) -> str:
    """Normalize module name to lookup key (e.g. 'CrashTest.dll' -> 'crashtest')."""
    return re.sub(r'\.(dll|efi|debug|so)$', '', mod_name, flags=re.IGNORECASE).lower()


def _parse_module_table(lines: list[str]) -> dict[int, str]:
    """Parse the module reference table: ``[ N] /path/to/Module.dll``.

    Returns {module_index: debug_path}.
    Only matches lines where the path starts with ``/`` (absolute paths).
    """
    table: dict[int, str] = {}
    for line in lines:
        m = RE_EDK2_ARM64_MODULE.match(line)
        if m and m.group(2).startswith('/'):
            table[int(m.group(1))] = m.group(2)
    return table
