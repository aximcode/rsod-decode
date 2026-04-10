"""RSOD decode orchestrator and output formatters.

This module provides:
- Output formatting (crash summary, backtrace, params, disassembly, source)
- Git source context resolution
- The main analyze_rsod() / decode_rsod() orchestrators
- Call-site verification

Format-specific logic (detection, extraction, decode) lives in the
``decoders`` subpackage.
"""
from __future__ import annotations

import subprocess as _subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .models import (
    CrashInfo, FrameInfo, GitRef, MapSymbol, SymbolSource, SymbolTable,
    VarInfo, clean_path, dwarf_for_frame, find_source_file, module_key,
)
from .dwarf_backend import DwarfInfo
from .esr import format_esr
from .symbols import load_symbols
from .decoders import FormatDecoder, detect_format
from .decoders.base import (
    parse_stack_dump,
    resolve_addresses_dwarf,
    walk_fp_chain,
    walk_rbp_chain,
)


# =============================================================================
# Utility
# =============================================================================

def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


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
        src_lines = _read_source_from_git(git_ref, file_part, repo_root)
        if src_lines:
            display_path = f"{file_part} @ {git_ref.short}"
    else:
        src_path = find_source_file(source_root, file_part, target_line)
        if not src_path:
            src_path = source_root / file_part
        if not src_path.is_file():
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
    for prefix in ('source/src/', ''):
        git_path = f"{prefix}{file_path}"
        lines = _git_show(git_ref.commit, git_path, repo_root)
        if lines is not None:
            return lines

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
    stack_base: int = 0
    stack_mem: bytes = b''
    modules: list[dict] = field(default_factory=list)  # [{index, name, base, debug_path}]


def _build_module_list(decoder: object) -> list[dict]:
    """Extract module table from decoder if available."""
    modules: list[dict] = []
    bases = getattr(decoder, 'module_bases', {})
    table = getattr(decoder, 'module_table', {})
    img_table = getattr(decoder, 'image_table', {})
    for idx in sorted(set(bases) | set(table) | set(img_table)):
        name, base = bases.get(idx, ('', 0))
        debug_path = table.get(idx, '')
        size = 0
        if idx in img_table:
            iname, ibase, isize = img_table[idx]
            if not name:
                name = iname
            if not base:
                base = ibase
            size = isize
        if not name and debug_path:
            name = debug_path.rsplit('/', 1)[-1]
        modules.append({
            'index': idx,
            'name': name,
            'base': base,
            'size': size,
            'debug_path': debug_path,
        })
    return modules


# =============================================================================
# Core analysis (shared by CLI and Flask API)
# =============================================================================

def analyze_rsod(
    rsod_text: str,
    source: SymbolSource,
    extra_sources: dict[str, SymbolSource] | None = None,
    base_override: int | None = None,
    log: Callable[[str], None] | None = None,
    symbol_search_paths: list[Path] | None = None,
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

    # 1. Detect format → decoder instance
    decoder = detect_format(lines)
    log(f"RSOD format: {decoder.name}")

    # 2. Base delta
    table = source.table
    base_delta = decoder.detect_base_delta(lines, table, base_override)
    if base_delta:
        log(f"Base delta: {base_delta:+X}")

    # 3. Collect addresses + DWARF resolve (per-module)
    line_info_by_module = decoder.collect_and_resolve(
        lines, source, extra_sources, base_delta, log)

    # 4. Extract crash info
    crash_info = decoder.extract_crash_info(lines, table, base_delta)
    crash_info.image_name = source.name

    # 5. Decode (annotated lines + frames)
    default_key = source.name.lower()
    annotated, resolved, frames = decoder.decode(
        lines, table, base_delta, line_info_by_module,
        extra_sources, default_key)

    # 5b. Auto-discover symbol files from image table
    if symbol_search_paths:
        img_table = getattr(decoder, 'image_table', {})
        for _idx, (mod_name, _base, _size) in img_table.items():
            mk = module_key(mod_name)
            if mk in extra_sources or mk == source.name.lower():
                continue
            # Search for matching .so or .debug file
            stem = mk.replace('.efi', '').replace('.dll', '')
            for search_dir in symbol_search_paths:
                for ext in ('.so', '.debug', '.efi'):
                    for candidate in search_dir.glob(f'**/{stem}*{ext}'):
                        try:
                            s = load_symbols(candidate,
                                             dwarf_prefix=None,
                                             repo_root=None)
                            if s.has_debug_info():
                                extra_sources[mk] = s
                                log(f"auto-loaded symbols: {candidate.name} for {mod_name}")
                                break
                        except Exception:
                            continue
                    if mk in extra_sources:
                        break
                if mk in extra_sources:
                    break

    # 6. FP chain unwinding: ARM64 formats with raw stack dumps
    fp_unwound = False
    chain: list[tuple[int, int]] = []
    stack_base, stack_mem = parse_stack_dump(lines)
    if stack_mem and decoder.supports_fp_chain():
        fp = crash_info.registers.get('FP', 0)
        lr = crash_info.registers.get('LR', 0)
        if fp and lr:
            chain = walk_fp_chain(fp, lr, stack_mem, stack_base)
            if chain:
                fp_unwound = True
                log(f"FP chain: {len(chain)} frames unwound from stack dump")

    # 6b. RBP chain unwinding: x86-64 formats with raw stack dumps
    if stack_mem and not chain and getattr(decoder, 'supports_rbp_chain', lambda: False)():
        rbp = crash_info.registers.get('RBP', crash_info.registers.get('BP', 0))
        ret = crash_info.registers.get('RIP', crash_info.registers.get('IP', 0))
        if rbp and ret:
            chain = walk_rbp_chain(rbp, ret, stack_mem, stack_base)
            if chain:
                fp_unwound = True
                log(f"RBP chain: {len(chain)} frames unwound from stack dump")

    # 7. Call-site verification via capstone — batch per module
    call_verified: dict[int, bool] = {}
    if frames:
        by_dwarf: dict[int, tuple[DwarfInfo, list[int]]] = {}
        for f in frames:
            dwarf = dwarf_for_frame(f, source, extra_sources)
            if dwarf:
                key = id(dwarf)
                if key not in by_dwarf:
                    by_dwarf[key] = (dwarf, [])
                by_dwarf[key][1].append(f.address)
        for dwarf, addrs in by_dwarf.values():
            call_verified.update(verify_call_sites(dwarf, addrs))

    # 8. Compute call_addr and frame_fp for each frame
    insn_size = decoder.insn_size
    for f in frames:
        if f.index == 0:
            f.is_crash_frame = True
            f.call_addr = f.address
            f.frame_fp = crash_info.registers.get('FP', 0)
        else:
            f.call_addr = f.address - insn_size

    # Assign per-frame FP from the FP chain walk.
    # chain[i] = (return_addr, frame_pointer) — chain[0] is frame #1's data.
    if chain and len(frames) > 1:
        for i, (_, fp_val) in enumerate(chain):
            frame_idx = i + 1
            if frame_idx < len(frames):
                frames[frame_idx].frame_fp = fp_val

    # 8b. CFI register unwinding — reconstruct per-frame register state
    if stack_mem and frames:
        # Crash frame gets the actual crash registers
        frames[0].frame_registers = dict(crash_info.registers)

        # Walk forward: each frame's registers are unwound from the previous
        for i in range(1, len(frames)):
            prev = frames[i - 1]
            if not prev.frame_registers:
                break
            dwarf = dwarf_for_frame(prev, source, extra_sources)
            if not dwarf:
                break
            unwinder = dwarf.get_cfi_unwinder()
            if not unwinder:
                break
            caller_regs = unwinder.unwind_frame(
                prev.address, prev.frame_registers, stack_base, stack_mem)
            if caller_regs is None:
                break
            frames[i].frame_registers = caller_regs

    # 8c. Compute CFA for each frame (needed for DW_OP_fbreg variables)
    for f in frames:
        if f.frame_registers:
            dwarf = dwarf_for_frame(f, source, extra_sources)
            if dwarf:
                unwinder = dwarf.get_cfi_unwinder()
                if unwinder:
                    f.frame_cfa = unwinder.compute_cfa(
                        f.address, f.frame_registers)

    # 9. Re-resolve source_loc at call_addr — batch per module
    if frames:
        by_dwarf2: dict[int, tuple[DwarfInfo, list[FrameInfo]]] = {}
        for f in frames:
            if f.is_crash_frame:
                continue
            dwarf = dwarf_for_frame(f, source, extra_sources)
            if not dwarf:
                continue
            key = id(dwarf)
            if key not in by_dwarf2:
                by_dwarf2[key] = (dwarf, [])
            by_dwarf2[key][1].append(f)
        for dwarf, flist in by_dwarf2.values():
            call_info = resolve_addresses_dwarf(
                dwarf, [f.call_addr for f in flist])
            for f in flist:
                entry = call_info.get(f.call_addr)
                if entry:
                    f.source_loc = entry[0][1]
                    f.inlines = entry[1:] if len(entry) > 1 else []

    return AnalysisResult(
        crash_info=crash_info,
        frames=frames,
        annotated_lines=annotated,
        resolved_count=resolved,
        rsod_format=decoder.name,
        call_verified=call_verified,
        line_info_by_module=line_info_by_module,
        stack_base=stack_base,
        stack_mem=stack_mem,
        modules=_build_module_list(decoder),
    )


# =============================================================================
# CLI decode orchestrator
# =============================================================================

def decode_rsod(
    log_path: Path, sym_path: Path, out_path: Path,
    base_override: int | None, verbose: bool,
    extra_sym_paths: list[Path], source_root: Path | None,
    git_ref: GitRef | None = None, repo_root: Path | None = None,
    dwarf_prefix: str | None = None,
) -> None:
    """Read RSOD log + symbol file, write annotated + enhanced output."""
    source = load_symbols(sym_path, dwarf_prefix=dwarf_prefix,
                          repo_root=repo_root)

    extra_sources: dict[str, SymbolSource] = {}
    for p in extra_sym_paths:
        s = load_symbols(p, dwarf_prefix=dwarf_prefix, repo_root=repo_root)
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
