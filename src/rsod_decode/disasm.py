"""Shared capstone disassembly helpers used by DWARF and PE binary backends."""
from __future__ import annotations

from capstone import CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_ARM, CS_MODE_64, Cs


_CALL_MNEMONICS = ('call', 'bl', 'blr', 'blx')


def make_capstone(arch: str) -> Cs:
    """Create a capstone disassembler for the given architecture.

    `arch` is either 'aarch64' or 'x86_64'. Both DWARF and PE backends use
    this so the disassembly flags stay consistent.
    """
    if arch == 'aarch64':
        return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    if arch == 'x86_64':
        return Cs(CS_ARCH_X86, CS_MODE_64)
    raise ValueError(f"unsupported capstone arch: {arch!r}")


def disassemble_around(
    cs: Cs, text_bytes: bytes, text_vaddr: int,
    addr: int, context: int = 24,
) -> list[tuple[int, str, str]]:
    """Disassemble instructions in the window [addr-context, addr+context).

    Returns [(address, mnemonic, op_str), ...]. `text_vaddr` is the virtual
    address at which `text_bytes` begins (so byte offset = addr - text_vaddr).
    Empty list if the window falls outside the section.
    """
    if not text_bytes:
        return []

    start = max(text_vaddr, addr - context)
    # Align to 4-byte boundary for ARM64 (fixed-length instructions)
    if cs.arch == CS_ARCH_ARM64:
        start = start & ~3
    end = addr + context

    offset = start - text_vaddr
    end_offset = end - text_vaddr
    if offset < 0 or offset >= len(text_bytes):
        return []
    end_offset = min(end_offset, len(text_bytes))
    code = text_bytes[offset:end_offset]

    result: list[tuple[int, str, str]] = []
    for insn in cs.disasm(code, start):
        result.append((insn.address, insn.mnemonic, insn.op_str))
    return result


def is_call_before(
    cs: Cs, text_bytes: bytes, text_vaddr: int, addr: int,
) -> bool:
    """Check if the instruction immediately before `addr` is a call.

    Reads the 8 bytes preceding `addr` and disassembles them; returns True
    if the last decoded instruction's mnemonic is a call/branch-and-link.
    For ARM64 this is exact (4-byte fixed-length); for x86-64 it's a
    heuristic that relies on capstone picking up the call when disassembling
    from addr-8 forward.
    """
    check_start = addr - 8
    if check_start < text_vaddr:
        return False
    offset = check_start - text_vaddr
    end_offset = addr - text_vaddr
    if offset < 0 or end_offset > len(text_bytes):
        return False
    code = text_bytes[offset:end_offset]

    insns = list(cs.disasm(code, check_start))
    if not insns:
        return False
    return insns[-1].mnemonic in _CALL_MNEMONICS
