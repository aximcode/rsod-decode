"""Dell UEFI ARM64 RSOD format decoder."""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import ClassVar

from ..models import CrashInfo, FrameInfo, SymbolSource, SymbolTable, module_key
from .base import (
    FormatDecoder,
    annotate_regs,
    format_annotation,
    lookup_and_annotate,
    make_frame,
    resolve_addresses_dwarf,
    source_loc,
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
        default_key = source.name.lower()
        line_info_by_module: dict[str, dict[int, list[tuple[str, str]]]] = {}

        # Collect addresses per-module from sNN frame lines + -->PC
        module_addrs: dict[str, list[int]] = {}
        for line in lines:
            fm = RE_ARM64_FRAME.match(line)
            if fm:
                mod_key = module_key(fm.group(3))
                module_addrs.setdefault(mod_key, []).append(
                    int(fm.group(4), 16))
            pc = RE_PC_LINE.match(line)
            if pc:
                module_addrs.setdefault(default_key, []).append(
                    int(pc.group(1), 16))

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
        self._seen_modules: dict[str, int] = {}

        default_info = line_info_by_module.get(default_module_key, {})

        for line in lines:
            # --> PC line (if we see a second one, reset — dual RSOD capture)
            pc_match = RE_PC_LINE.match(line)
            if pc_match:
                if frames:
                    # Second RSOD in the file — keep only the first
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
            fm = RE_ARM64_FRAME.match(line)
            if fm:
                module = fm.group(3)
                abs_addr = int(fm.group(2), 16)
                offset_in_module = int(fm.group(4), 16)
                mod_base = abs_addr - offset_in_module

                mod_key = module_key(module)
                # Track module bases (use frame_idx as module index)
                if mod_key not in self._seen_modules:
                    idx = len(self.module_bases)
                    self.module_bases[idx] = (module, mod_base)
                    self._seen_modules[mod_key] = idx
                src = (extra_sources or {}).get(mod_key)
                # Only use primary table for the primary module;
                # don't resolve other modules against wrong symbols
                if src:
                    use_table = src.table
                elif mod_key == default_module_key:
                    use_table = table
                else:
                    use_table = None
                use_info = line_info_by_module.get(
                    mod_key, line_info_by_module.get(
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
            if RE_ARM64_REG.search(line):
                out.append(annotate_regs(
                    line, [RE_ARM64_REG], table, base_delta))
                continue

            out.append(line)

        return out, resolved, frames

    def supports_fp_chain(self) -> bool:
        return True
