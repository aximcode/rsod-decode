"""RSOD text parsing, format detection, and decode orchestrator.

This module handles:
- RSOD format detection (uefi_x86, uefi_arm64, edk2_x64)
- Crash info extraction (exception type, PC, registers, ESR)
- Address annotation and frame building for x86 and ARM64
- Output formatting (crash summary, backtrace, params, disassembly, source)
- Git source context resolution
- The main analyze_rsod() / decode_rsod() orchestrator
"""
from __future__ import annotations

import re
import subprocess as _subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .models import (
    CrashInfo, FrameInfo, GitRef, MapSymbol, SymbolSource, SymbolTable,
    VarInfo, clean_path,
)
from .dwarf_info import DwarfInfo
from .esr import format_esr
from .symbols import load_symbols


# =============================================================================
# Utility
# =============================================================================

def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


# =============================================================================
# RSOD line patterns
# =============================================================================

RE_STACK_LINE = re.compile(
    r'^(\s+[0-9A-Fa-f]+\s+)([0-9A-Fa-f]{16})(\s+.*)$')
RE_RIP_LINE = re.compile(r'^-->\s*RIP\s+([0-9A-Fa-f]+)(.*)', re.IGNORECASE)
RE_UEFI_X86_REG = re.compile(r'([A-Z0-9]{2})=([0-9A-Fa-f]{16})')
RE_EDK2_RIP = re.compile(r'^(RIP\s+-\s+)([0-9A-Fa-f]+)(.*)')
RE_EDK2_REG = re.compile(r'([A-Z0-9]+)\s+-\s+([0-9A-Fa-f]{16})')
RE_EDK2_IMAGEBASE = re.compile(r'ImageBase=([0-9A-Fa-f]+)', re.IGNORECASE)
RE_ARM64_REG = re.compile(
    r'(X\d+|FP|LR|SP|ELR|SPSR|FPSR|FAR|PC|ESR)=([0-9A-Fa-f]+)')
RE_PC_LINE = re.compile(r'^-->\s*PC\s+([0-9A-Fa-f]+)(.*)', re.IGNORECASE)
RE_ARM64_FRAME = re.compile(
    r'^(s\d+)\s+([0-9A-Fa-f]+)\s+(\S+\.efi)\s+\+([0-9A-Fa-f]+)')


# =============================================================================
# Crash summary extraction
# =============================================================================

RE_UEFI_X86_TYPE = re.compile(r'^Type:\s*(.+?)\s*Source:', re.IGNORECASE)
RE_UEFI_ARM64_TYPE = re.compile(r'^Type:\s*(.+)', re.IGNORECASE)
RE_EDK2_TYPE = re.compile(
    r'X64 Exception Type\s*-\s*([0-9a-fA-F]+)\(([^)]+)\)', re.IGNORECASE)


def extract_crash_info(
    lines: list[str], fmt: str, table: SymbolTable, base_delta: int,
) -> CrashInfo:
    """Extract crash metadata from RSOD lines."""
    info = CrashInfo(fmt=fmt, image_base=table.preferred_base)
    regs: dict[str, int] = {}

    # Choose patterns based on format
    if fmt == 'uefi_arm64':
        type_pats = [RE_UEFI_ARM64_TYPE]
        pc_pats = [RE_PC_LINE]
        reg_pats = [RE_ARM64_REG]
    elif fmt == 'edk2_x64':
        type_pats = [RE_EDK2_TYPE]
        pc_pats = [RE_EDK2_RIP]
        reg_pats = [RE_EDK2_REG]
    else:
        type_pats = [RE_UEFI_X86_TYPE]
        pc_pats = [RE_RIP_LINE]
        reg_pats = [RE_UEFI_X86_REG]

    for line in lines:
        # Exception description
        if not info.exception_desc:
            for pat in type_pats:
                m = pat.search(line)
                if m:
                    if pat == RE_EDK2_TYPE:
                        info.exception_desc = f"{m.group(2)} (0x{m.group(1)})"
                    else:
                        info.exception_desc = m.group(1).strip()
                    break

        # Crash PC
        for pat in pc_pats:
            m = pat.match(line)
            if m:
                group_idx = 2 if pat == RE_EDK2_RIP else 1
                info.crash_pc = int(m.group(group_idx), 16)

        # Registers
        for pat in reg_pats:
            for reg, val in pat.findall(line):
                regs[reg] = int(val, 16)

    info.registers = regs
    info.sp = regs.get('SP', regs.get('RSP'))
    info.esr = regs.get('ESR')
    info.far = regs.get('FAR')

    # Resolve crash PC
    if info.crash_pc is not None:
        result = table.lookup(info.crash_pc - base_delta)
        if result:
            info.crash_symbol = result[0].name
        else:
            info.crash_symbol = "not in image"

    return info


# =============================================================================
# RSOD format detection
# =============================================================================

def detect_format(lines: list[str]) -> str:
    """Detect the RSOD format from the log lines."""
    for line in lines:
        if RE_PC_LINE.match(line) or RE_ARM64_FRAME.match(line):
            return 'uefi_arm64'
        if line.startswith('--> PC') or line.startswith('-->PC'):
            return 'uefi_arm64'
        if RE_ARM64_REG.search(line) and 'X0=' in line:
            return 'uefi_arm64'
        if '!!!! X64 Exception' in line or RE_EDK2_RIP.match(line):
            return 'edk2_x64'
        if RE_RIP_LINE.match(line):
            return 'uefi_x86'
    return 'uefi_x86'


# =============================================================================
# Output formatters
# =============================================================================

def format_crash_summary(
    info: CrashInfo, git_ref: GitRef | None = None,
) -> list[str]:
    """Format the --- Crash Summary --- block."""
    lines = ['--- Crash Summary ---']
    if info.exception_desc:
        lines.append(f"Exception: {info.exception_desc}")
    if info.crash_pc is not None:
        sym = f" [{info.crash_symbol}]" if info.crash_symbol else ''
        lines.append(f"Crash PC:  0x{info.crash_pc:X}{sym}")
    if info.image_name:
        base = f" (base 0x{info.image_base:X})" if info.image_base else ''
        lines.append(f"Image:     {info.image_name}{base}")
    if git_ref:
        lines.append(f"Source:    {git_ref.label()}")
    if info.esr is not None:
        lines.extend(format_esr(info.esr, info.far))
    return lines


def format_backtrace(
    frames: list[FrameInfo],
    call_verified: dict[int, bool] | None = None,
) -> list[str]:
    """Format a clean gdb-style backtrace."""
    if not frames:
        return []
    verified = call_verified or {}
    lines = ['--- Backtrace ---']
    for f in frames:
        name = f.symbol.name if f.symbol else '???'
        loc = f" at {f.source_loc}" if f.source_loc else ''
        mod = f" [{f.module}]" if f.module else ''
        tag = ''
        if f.address in verified:
            tag = ' [verified]' if verified[f.address] else ' [stale?]'
        lines.append(f"#{f.index:<3d} 0x{f.address:X} in {name}{loc}{mod}{tag}")
        for func, sloc in f.inlines:
            lines.append(f"      (inlined) {func} at {sloc}")
    return lines


# =============================================================================
# Parameter and local variable formatting
# =============================================================================

def _format_vars(
    vars_: list[VarInfo], registers: dict[str, int],
    frame: FrameInfo, label: str,
) -> list[str]:
    """Format a list of VarInfo (params or locals) with register values."""
    if not vars_:
        return []
    func_name = frame.symbol.name.split('(')[0].rsplit('::', 1)[-1] if frame.symbol else '???'
    lines = [f'--- {label} (frame #{frame.index}: {func_name}) ---']
    for v in vars_:
        val_str = ''
        if v.reg_name and v.reg_name in registers:
            val = registers[v.reg_name]
            dec = f"  ({val})" if val < 0x10000 else ''
            val_str = f' = 0x{val:016X}{dec}'
        lines.append(f"  {v.name:<15s} ({v.type_name:<20s}) {v.location}{val_str}")
    return lines


def format_params(
    dwarf_info: DwarfInfo, crash_pc: int, registers: dict[str, int],
    frame: FrameInfo,
) -> list[str]:
    """Format parameters using real DWARF names and PC-accurate locations."""
    return _format_vars(
        dwarf_info.get_params(crash_pc), registers, frame, 'Parameters')


def format_locals(
    dwarf_info: DwarfInfo, crash_pc: int, registers: dict[str, int],
    frame: FrameInfo,
) -> list[str]:
    """Format local variables using DWARF info."""
    return _format_vars(
        dwarf_info.get_locals(crash_pc), registers, frame, 'Locals')


# =============================================================================
# Disassembly context
# =============================================================================

def format_disassembly(
    dwarf: DwarfInfo, address: int, context: int = 24,
) -> list[str]:
    """Disassemble around an address using DwarfInfo, marking the target with >."""
    insns = dwarf.disassemble_around(address, context)
    if not insns:
        return []

    # Batch-resolve source lines for all instruction addresses
    src_map = dwarf.source_lines_for_addrs([a for a, _, _ in insns])

    lines = [f'--- Disassembly (0x{address:X}) ---']
    prev_src: str = ''
    for iaddr, mnemonic, op_str in insns:
        src = src_map.get(iaddr, '')
        if src and src != prev_src:
            lines.append(f'  {src}')
            prev_src = src

        marker = '>' if iaddr == address else ' '
        asm_text = f"{mnemonic}  {op_str}".rstrip()
        lines.append(f"  {marker} {iaddr:x}: {asm_text}")

    return lines if len(lines) > 1 else []


# =============================================================================
# Source context
# =============================================================================

def format_source_context(
    source_loc: str, source_root: Path, context: int = 3,
    git_ref: GitRef | None = None, repo_root: Path | None = None,
) -> list[str]:
    """Show source lines around the target, marking it with >.
    If git_ref is provided, reads source at that commit via git show."""
    if ':' not in source_loc:
        return []
    file_part, line_part = source_loc.rsplit(':', 1)
    try:
        target_line = int(line_part)
    except ValueError:
        return []

    src_lines: list[str] | None = None
    display_path = file_part

    if git_ref and repo_root:
        # Read from git at the specified commit
        src_lines = _read_source_from_git(git_ref, file_part, repo_root)
        if not src_lines:
            # Try filename-only search via git ls-tree
            filename = Path(file_part).name
            src_lines = _read_source_from_git(git_ref, filename, repo_root)
        if src_lines:
            display_path = f"{file_part} @ {git_ref.short}"
    else:
        # Read from working tree
        src_path = source_root / file_part
        if not src_path.exists():
            filename = Path(file_part).name
            for candidate_dir in sorted(source_root.iterdir()):
                if not candidate_dir.is_dir() or candidate_dir.name.startswith('.'):
                    continue
                matches = list(candidate_dir.rglob(filename))
                if len(matches) == 1:
                    src_path = matches[0]
                    display_path = str(src_path.relative_to(source_root))
                    break
            if not src_path.exists():
                return []
        try:
            src_lines = src_path.read_text(
                encoding='utf-8', errors='replace').splitlines()
        except OSError:
            return []

    if not src_lines:
        return []

    start = max(0, target_line - context - 1)
    end = min(len(src_lines), target_line + context)

    out = [f'--- Source ({display_path}) ---']
    for i in range(start, end):
        lineno = i + 1
        marker = '>' if lineno == target_line else ' '
        out.append(f"  {marker} {lineno:4d}: {src_lines[i]}")

    return out if len(out) > 1 else []


# =============================================================================
# Call-site verification
# =============================================================================

def verify_call_sites(
    dwarf: DwarfInfo, addresses: list[int],
) -> dict[int, bool]:
    """Check if return addresses have a preceding call instruction."""
    verified: dict[int, bool] = {}
    for addr in addresses:
        verified[addr] = dwarf.is_call_before(addr)
    return verified


# =============================================================================
# Annotation formatting
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


def _source_loc(
    line_info: dict[int, list[tuple[str, str]]], addr: int,
) -> str:
    """Get the primary source location for an address from resolved data."""
    entries = line_info.get(addr, [])
    return entries[0][1] if entries else ''


def _lookup_and_annotate(
    addr: int, table: SymbolTable, line_info: dict[int, list[tuple[str, str]]],
) -> str | None:
    """Look up addr, return annotation string or None."""
    result = table.lookup(addr)
    if not result:
        return None
    sym, offset = result
    return format_annotation(sym, offset, _source_loc(line_info, addr))


# =============================================================================
# Decode: shared register annotation helper
# =============================================================================

def _annotate_regs(
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
# Decode: shared frame builder
# =============================================================================

def _make_frame(
    index: int, address: int, module: str,
    sym: MapSymbol, offset: int,
    line_info: dict[int, list[tuple[str, str]]],
    info_key: int,
) -> FrameInfo:
    """Build a FrameInfo from a resolved symbol + resolved data."""
    entries = line_info.get(info_key, [])
    loc = entries[0][1] if entries else ''
    inlines = entries[1:] if len(entries) > 1 else []
    return FrameInfo(
        index=index, address=address, module=module,
        symbol=sym, sym_offset=offset, source_loc=loc, inlines=inlines)


def _extract_addr_from_line(
    line: str, patterns: list[tuple[re.Pattern[str], int]],
) -> int | None:
    """Try each (pattern, group_index) pair; return first matched address."""
    for pat, group in patterns:
        m = pat.match(line)
        if m:
            return int(m.group(group), 16)
    return None


# =============================================================================
# Decode: UEFI x86 + EDK2 x64
# =============================================================================

# (pattern, capture group for the address)
_RIP_PATTERNS: list[tuple[re.Pattern[str], int]] = [
    (RE_RIP_LINE, 1),
    (RE_EDK2_RIP, 2),
]


def decode_x86(
    lines: list[str], table: SymbolTable, base_delta: int,
    line_info: dict[int, list[tuple[str, str]]],
) -> tuple[list[str], int, list[FrameInfo]]:
    """Decode x86 RSOD. Returns (annotated_lines, resolved_count, frames)."""
    in_registers = False
    in_stack = False
    resolved = 0
    out: list[str] = []
    frames: list[FrameInfo] = []
    frame_idx = 0

    for line in lines:
        has_regs = (RE_UEFI_X86_REG.search(line) is not None
                    or RE_EDK2_REG.search(line) is not None)
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
            out.append(_annotate_regs(
                line, [RE_UEFI_X86_REG, RE_EDK2_REG], table, base_delta))
            continue

        # -->RIP or EDK2 RIP
        rip_addr = _extract_addr_from_line(line, _RIP_PATTERNS)
        if rip_addr is not None:
            ann = _lookup_and_annotate(rip_addr - base_delta, table, line_info)
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
                    sym, offset, _source_loc(line_info, adjusted))}")
                resolved += 1
                frames.append(_make_frame(
                    frame_idx, value, '', sym, offset, line_info, adjusted))
                frame_idx += 1
            else:
                out.append(line)
            continue

        out.append(line)

    return out, resolved, frames


# =============================================================================
# Decode: UEFI ARM64
# =============================================================================

def decode_arm64(
    lines: list[str], table: SymbolTable, base_delta: int,
    line_info_by_module: dict[str, dict[int, list[tuple[str, str]]]],
    extra_sources: dict[str, SymbolSource] | None = None,
    default_module_key: str = '',
) -> tuple[list[str], int, list[FrameInfo]]:
    """Decode ARM64 RSOD. Returns (annotated_lines, resolved_count, frames).

    line_info_by_module maps module key -> {addr: [(func, loc), ...]}.
    The default_module_key is for the primary symbol file.
    """
    resolved = 0
    out: list[str] = []
    frames: list[FrameInfo] = []
    frame_idx = 0

    # Flat line_info for -->PC (not module-scoped)
    default_info = line_info_by_module.get(default_module_key, {})

    for line in lines:
        # --> PC line
        pc_match = RE_PC_LINE.match(line)
        if pc_match:
            addr = int(pc_match.group(1), 16)
            ann = _lookup_and_annotate(addr - base_delta, table, default_info)
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
            offset_in_module = int(fm.group(4), 16)

            # Multi-module: pick the right symbol source and line info
            mod_key = module.replace('.efi', '').lower()
            src = (extra_sources or {}).get(mod_key)
            use_table = src.table if src else table
            # Try module-specific line info, fall back to primary
            use_info = line_info_by_module.get(
                mod_key, line_info_by_module.get(default_module_key, {}))

            if use_table.preferred_base == 0:
                lookup_addr = offset_in_module
            else:
                lookup_addr = use_table.preferred_base + offset_in_module

            result = use_table.lookup(lookup_addr)
            if result:
                sym, off = result
                loc = _source_loc(use_info, offset_in_module)
                out.append(f"{line}  {format_annotation(sym, off, loc)}")
                resolved += 1
                frames.append(_make_frame(
                    frame_idx, offset_in_module, module,
                    sym, off, use_info, offset_in_module))
                frame_idx += 1
            else:
                out.append(line)
                frames.append(FrameInfo(
                    index=frame_idx, address=offset_in_module, module=module))
                frame_idx += 1
            continue

        # Register lines
        if RE_ARM64_REG.search(line):
            out.append(_annotate_regs(
                line, [RE_ARM64_REG], table, base_delta))
            continue

        out.append(line)

    return out, resolved, frames


# =============================================================================
# Git source resolution
# =============================================================================

def resolve_git_ref(ref: str, repo_root: Path) -> GitRef | None:
    """Validate a git tag or commit hash and return its info."""
    try:
        r = _subprocess.run(
            ['git', '-C', str(repo_root), 'log', '--format=%H%n%h%n%s',
             '-1', ref],
            capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return None
        lines = r.stdout.strip().splitlines()
        if len(lines) < 3:
            return None
        return GitRef(
            commit=lines[0], short=lines[1],
            summary=lines[2], ref_name=ref)
    except (FileNotFoundError, _subprocess.TimeoutExpired):
        return None


def _read_source_from_git(
    git_ref: GitRef, file_path: str, repo_root: Path,
) -> list[str] | None:
    """Read source file at a specific git commit."""
    # Try the path directly with common prefixes
    for prefix in ('source/src/', ''):
        git_path = f"{prefix}{file_path}"
        lines = _git_show(git_ref.commit, git_path, repo_root)
        if lines is not None:
            return lines

    # Fallback: search entire repo for the filename
    filename = Path(file_path).name
    found = _git_find_file(git_ref.commit, filename, '', repo_root)
    if found:
        return _git_show(git_ref.commit, found, repo_root)

    return None


def _git_show(
    commit: str, path: str, repo_root: Path,
) -> list[str] | None:
    """Run git show commit:path, return lines or None."""
    try:
        r = _subprocess.run(
            ['git', '-C', str(repo_root), 'show', f'{commit}:{path}'],
            capture_output=True, text=True, timeout=10)
        return r.stdout.splitlines() if r.returncode == 0 else None
    except (FileNotFoundError, _subprocess.TimeoutExpired):
        return None


def _git_find_file(
    commit: str, filename: str, subtree: str, repo_root: Path,
) -> str | None:
    """Find a file by name in a subtree at a specific commit."""
    try:
        r = _subprocess.run(
            ['git', '-C', str(repo_root), 'ls-tree', '-r', '--name-only',
             commit, subtree],
            capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return None
        matches = [p for p in r.stdout.splitlines() if p.endswith(f'/{filename}')]
        return matches[0] if len(matches) == 1 else None
    except (FileNotFoundError, _subprocess.TimeoutExpired):
        return None


# =============================================================================
# DWARF address resolution helper
# =============================================================================

def _resolve_addresses_dwarf(
    dwarf_info: DwarfInfo, addresses: list[int],
) -> dict[int, list[tuple[str, str]]]:
    """Resolve addresses via DwarfInfo.
    Returns {addr: [(func, file:line), ...]} for compatibility with
    the line_info dict format used by the decoders."""
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
# x86 address collector
# =============================================================================

def _collect_x86_addrs(
    lines: list[str], table: SymbolTable, base_delta: int,
) -> list[int]:
    """Collect resolvable addresses from x86/EDK2 RSOD lines."""
    addrs: list[int] = []
    in_stack = False
    for line in lines:
        if line.strip().startswith('Stack Dump'):
            in_stack = True
            continue
        for pat in (RE_RIP_LINE, RE_EDK2_RIP):
            m = pat.match(line)
            if m:
                addr = int(m.group(1 if pat == RE_RIP_LINE else 2), 16)
                adj = addr - base_delta
                if table.lookup(adj):
                    addrs.append(adj)
        if in_stack:
            sm = RE_STACK_LINE.match(line)
            if sm:
                adj = int(sm.group(2), 16) - base_delta
                if table.lookup(adj):
                    addrs.append(adj)
    return addrs


# =============================================================================
# Analysis result
# =============================================================================

@dataclass
class AnalysisResult:
    """Complete analysis of an RSOD capture."""
    crash_info: CrashInfo
    frames: list[FrameInfo]
    annotated_lines: list[str]
    resolved_count: int
    rsod_format: str
    call_verified: dict[int, bool] = field(default_factory=dict)
    line_info_by_module: dict[str, dict[int, list[tuple[str, str]]]] = field(
        default_factory=dict)


# =============================================================================
# Core analysis (shared by CLI and Flask API)
# =============================================================================

def analyze_rsod(
    rsod_text: str,
    source: SymbolSource,
    extra_sources: dict[str, SymbolSource] | None = None,
    base_override: int | None = None,
    log: object = None,
) -> AnalysisResult:
    """Analyze an RSOD capture against symbol files.

    This is the shared analysis core used by both the CLI and the Flask API.
    Returns an AnalysisResult with all resolved data.
    """
    if log is None:
        log = _log
    if extra_sources is None:
        extra_sources = {}

    lines = rsod_text.splitlines()
    table = source.table
    fmt = detect_format(lines)
    log(f"RSOD format: {fmt}")

    # Base delta
    base_delta = 0
    if base_override is not None:
        base_delta = base_override - table.preferred_base
        log(f"Base override: 0x{base_override:X} (delta: {base_delta:+X})")
    elif fmt == 'edk2_x64':
        for line in lines:
            m = RE_EDK2_IMAGEBASE.search(line)
            if m:
                detected = int(m.group(1), 16)
                if detected != table.preferred_base:
                    base_delta = detected - table.preferred_base
                    log(f"Auto-detected ImageBase: 0x{detected:X}")
                break

    # Collect addresses and resolve -- per-module for ARM64
    default_key = source.name.lower()
    line_info_by_module: dict[str, dict[int, list[tuple[str, str]]]] = {}

    if fmt == 'uefi_arm64':
        module_addrs: dict[str, list[int]] = {}
        for line in lines:
            fm = RE_ARM64_FRAME.match(line)
            if fm:
                mod_key = fm.group(3).replace('.efi', '').lower()
                module_addrs.setdefault(mod_key, []).append(
                    int(fm.group(4), 16))
            pc = RE_PC_LINE.match(line)
            if pc:
                module_addrs.setdefault(default_key, []).append(
                    int(pc.group(1), 16))

        dedicated: dict[str, SymbolSource] = {
            k: v for k, v in extra_sources.items() if v.has_debug_info()}
        for mod_key, addrs in module_addrs.items():
            mod_src = dedicated.get(mod_key, source)
            if mod_src.has_debug_info() and mod_src.dwarf:
                src_key = mod_key if mod_key in dedicated else default_key
                info = _resolve_addresses_dwarf(mod_src.dwarf, addrs)
                if info:
                    line_info_by_module.setdefault(src_key, {}).update(info)
                    log(f"resolve [{mod_key}]: "
                        f"{len(info)}/{len(addrs)} resolved")
    elif source.has_debug_info() and source.dwarf:
        addrs = _collect_x86_addrs(lines, table, base_delta)
        if addrs:
            info = _resolve_addresses_dwarf(source.dwarf, addrs)
            if info:
                line_info_by_module[default_key] = info
                log(f"resolve: {len(info)}/{len(addrs)} addresses")

    # Extract crash info
    crash_info = extract_crash_info(lines, fmt, table, base_delta)
    crash_info.image_name = source.name

    # Decode (annotated lines + frames)
    if fmt == 'uefi_arm64':
        annotated, resolved, frames = decode_arm64(
            lines, table, base_delta, line_info_by_module,
            extra_sources, default_key)
    else:
        flat_info = line_info_by_module.get(default_key, {})
        annotated, resolved, frames = decode_x86(
            lines, table, base_delta, flat_info)

    # Call-site verification via capstone (ELF sources only)
    call_verified: dict[int, bool] = {}
    if source.dwarf and frames:
        call_verified = verify_call_sites(
            source.dwarf, [f.address for f in frames])

    return AnalysisResult(
        crash_info=crash_info,
        frames=frames,
        annotated_lines=annotated,
        resolved_count=resolved,
        rsod_format=fmt,
        call_verified=call_verified,
        line_info_by_module=line_info_by_module,
    )


# =============================================================================
# CLI decode orchestrator
# =============================================================================

def decode_rsod(
    log_path: Path, sym_path: Path, out_path: Path,
    base_override: int | None, verbose: bool,
    extra_sym_paths: list[Path], source_root: Path | None,
    git_ref: GitRef | None = None, repo_root: Path | None = None,
) -> None:
    """Read RSOD log + symbol file, write annotated + enhanced output."""
    source = load_symbols(sym_path)

    extra_sources: dict[str, SymbolSource] = {}
    for p in extra_sym_paths:
        s = load_symbols(p)
        extra_sources[p.stem.lower()] = s

    rsod_text = log_path.read_text(encoding='utf-8', errors='replace')
    result = analyze_rsod(rsod_text, source, extra_sources, base_override)

    # Assemble output
    out: list[str] = []
    out.extend(format_crash_summary(result.crash_info, git_ref))
    out.append('')
    out.extend(result.annotated_lines)
    out.append('')
    out.extend(format_backtrace(result.frames, result.call_verified))

    # Verbose sections for frame #0
    if verbose and result.frames:
        f0 = result.frames[0]

        if source.dwarf:
            params = format_params(
                source.dwarf, f0.address, result.crash_info.registers, f0)
            if params:
                out.append('')
                out.extend(params)

            locals_ = format_locals(
                source.dwarf, f0.address, result.crash_info.registers, f0)
            if locals_:
                out.append('')
                out.extend(locals_)

            if f0.address:
                disasm = format_disassembly(source.dwarf, f0.address)
                if disasm:
                    out.append('')
                    out.extend(disasm)

        if (source_root or git_ref) and f0.source_loc:
            src = format_source_context(
                f0.source_loc, source_root or Path('.'),
                git_ref=git_ref, repo_root=repo_root)
            if src:
                out.append('')
                out.extend(src)

    out_path.write_text('\n'.join(out) + '\n', encoding='utf-8')
    _log(f"Resolved {result.resolved_count} addresses")
    _log(f"Output: {out_path}")
