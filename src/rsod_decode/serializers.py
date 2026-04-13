"""Serialization helpers for converting analysis models to JSON-ready dicts."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .dwarf_backend import DwarfInfo, _strip_qualifiers, _is_string_type
from .models import (
    CrashInfo, FrameInfo, SymbolSource, VarInfo, dwarf_for_frame,
)
from .session import Session


# Pattern for indirect memory locations: [REG+N] or [REG-N] or [REG]
_RE_MEM_LOC = re.compile(r'^\[(\w+)([+-]\d+)?\]$')

# Pattern for DW_OP_addr (absolute address for globals): 0xADDR
_RE_ADDR_LOC = re.compile(r'^0x([0-9A-Fa-f]+)$')

# Pattern for DW_OP_entry_value: (DW_OP_reg0 (x0)); DW_OP_stack_value)
_RE_ENTRY_VALUE = re.compile(
    r'\(DW_OP_entry_value:.*DW_OP_reg\d+\s+\((\w+)\).*DW_OP_stack_value\)')


@dataclass
class _FrameCtx:
    """Context for resolving variable values within a specific frame."""
    registers: dict[str, int]
    stack_base: int
    stack_mem: bytes
    frame_fp: int
    is_crash_frame: bool
    has_unwound_regs: bool = False
    frame_cfa: int = 0
    dwarf: DwarfInfo | None = None
    image_base: int = 0


def _read_stack(addr: int, size: int, stack_base: int, stack_mem: bytes) -> int | None:
    """Read an integer from the stack dump at the given address."""
    offset = addr - stack_base
    if offset < 0 or offset + size > len(stack_mem):
        return None
    return int.from_bytes(stack_mem[offset:offset + size], 'little')


def _build_frame_ctx(
    frame: FrameInfo, session: Session, img_base: int,
) -> _FrameCtx:
    """Build a _FrameCtx for resolving variable values in *frame*."""
    has_unwound = bool(frame.frame_registers)
    regs = frame.frame_registers or session.result.crash_info.registers
    return _FrameCtx(
        registers=regs,
        stack_base=session.result.stack_base,
        stack_mem=session.result.stack_mem,
        frame_fp=frame.frame_fp,
        is_crash_frame=frame.is_crash_frame,
        has_unwound_regs=has_unwound,
        frame_cfa=frame.frame_cfa,
        dwarf=dwarf_for_frame(
            frame, session.source, session.extra_sources),
        image_base=img_base,
    )


def dwarf_for_session(session: Session, frame: FrameInfo) -> object | None:
    """Get the DWARF backend for a frame, respecting session backend choice."""
    if session.backend == 'gdb' and session.gdb_dwarf:
        return session.gdb_dwarf
    return dwarf_for_frame(frame, session.source, session.extra_sources)


def _var_to_dict(v: VarInfo, ctx: _FrameCtx) -> dict:
    # If the backend pre-resolved the value (GDB backend), use it directly
    if v.value is not None or v.is_expandable is not None:
        return {
            'name': v.name,
            'type': v.type_name,
            'location': v.location,
            'reg_name': v.reg_name,
            'value': v.value,
            'approximate': False,
            'is_expandable': bool(v.is_expandable),
            'expand_addr': v.expand_addr,
            'string_preview': v.string_preview,
            'type_offset': v.type_offset,
            'cu_offset': v.cu_offset,
            'var_key': v.var_key,
        }

    value = None
    mem_addr: int | None = None  # memory address for expandable types
    location = v.location
    approximate = False

    # Direct register location
    if v.reg_name and v.reg_name in ctx.registers:
        value = ctx.registers[v.reg_name]
        if not ctx.is_crash_frame and not ctx.has_unwound_regs:
            approximate = True
    # DW_OP_entry_value — value at function entry. Only resolvable for
    # crash frame (registers are exact) or if CFI recovered the register.
    elif (m := _RE_ENTRY_VALUE.search(v.location)):
        reg = m.group(1).upper()
        location = f'{reg} (at entry)'
        if reg in ctx.registers and (ctx.is_crash_frame or ctx.has_unwound_regs):
            value = ctx.registers[reg]
    # DW_OP_addr — absolute address (global/static variables).
    # Values are ELF initializers, not runtime state — mark approximate.
    elif (m := _RE_ADDR_LOC.match(v.location)) and ctx.dwarf:
        elf_addr = int(m.group(1), 16)
        runtime_addr = elf_addr + ctx.image_base
        mem_addr = runtime_addr
        approximate = True
        size = v.byte_size or 8
        if size <= 8:
            value = ctx.dwarf.read_int(
                runtime_addr, size,
                ctx.stack_base, ctx.stack_mem, ctx.image_base)
        else:
            value = runtime_addr
    # Indirect memory location: [REG+offset] or [CFA+offset]
    elif ctx.stack_mem:
        m = _RE_MEM_LOC.match(v.location)
        if m:
            reg = m.group(1)
            off = int(m.group(2)) if m.group(2) else 0
            if reg == 'CFA' and ctx.frame_cfa:
                base = ctx.frame_cfa
            elif reg == 'FP' and ctx.frame_fp:
                base = ctx.frame_fp
            else:
                base = ctx.registers.get(reg)
            if base is not None:
                addr = base + off
                mem_addr = addr
                size = v.byte_size or 8
                if size <= 8:
                    value = _read_stack(addr, size, ctx.stack_base, ctx.stack_mem)
                else:
                    # Aggregate type — store the address, not the data
                    value = addr
    # Expandability and string preview
    is_pointer = False
    is_expandable = False
    string_preview = None
    expand_type_offset = v.type_offset
    expand_cu_offset = v.cu_offset
    if ctx.dwarf and v.type_offset:
        type_die = ctx.dwarf.get_type_die(v.cu_offset, v.type_offset)
        if type_die:
            real = _strip_qualifiers(type_die)
            if real:
                is_pointer = real.tag == 'DW_TAG_pointer_type'
                is_aggregate = real.tag in (
                    'DW_TAG_structure_type', 'DW_TAG_class_type',
                    'DW_TAG_union_type', 'DW_TAG_array_type')
                is_expandable = is_aggregate
                if is_pointer and 'DW_AT_type' in real.attributes:
                    target = _strip_qualifiers(
                        real.get_DIE_from_attribute('DW_AT_type'))
                    if target and target.tag in (
                            'DW_TAG_structure_type', 'DW_TAG_class_type',
                            'DW_TAG_union_type'):
                        is_expandable = True
                        expand_type_offset = target.offset
                        expand_cu_offset = target.cu.cu_offset
                # String preview for char pointers
                if is_pointer and value and _is_string_type(v.type_name):
                    string_preview = ctx.dwarf.read_string(
                        value, ctx.stack_base, ctx.stack_mem,
                        ctx.image_base, max_len=64)

    # expand_addr: address the frontend passes to /api/expand.
    # For pointer-to-struct: the pointer value (target address).
    # For embedded aggregates: the field's memory address.
    expand_addr: int | None = None
    if is_expandable:
        if is_pointer and value is not None:
            expand_addr = value
        elif mem_addr is not None:
            expand_addr = mem_addr

    return {
        'name': v.name,
        'type': v.type_name,
        'location': location,
        'reg_name': v.reg_name,
        'value': value,
        'approximate': approximate,
        'is_expandable': is_expandable,
        'expand_addr': expand_addr,
        'string_preview': string_preview,
        'type_offset': expand_type_offset,
        'cu_offset': expand_cu_offset,
    }


def crash_info_to_dict(info: CrashInfo) -> dict:
    return {
        'format': info.fmt,
        'exception_desc': info.exception_desc,
        'crash_pc': info.crash_pc,
        'crash_symbol': info.crash_symbol,
        'image_name': info.image_name,
        'image_base': info.image_base,
        'esr': info.esr,
        'far': info.far,
        'sp': info.sp,
    }


def frame_to_dict(f: FrameInfo) -> dict:
    return {
        'index': f.index,
        'address': f.address,
        'call_addr': f.call_addr,
        'is_crash_frame': f.is_crash_frame,
        'module': f.module,
        'symbol': f.symbol.name if f.symbol else None,
        'sym_offset': f.sym_offset,
        'source_loc': f.source_loc,
        'inlines': [{'function': func, 'source_loc': loc}
                     for func, loc in f.inlines],
    }


def registers_to_dict(regs: dict[str, int]) -> dict:
    return {k: f'0x{v:X}' for k, v in regs.items()}
