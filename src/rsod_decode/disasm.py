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


def _decode_sized(
    cs: Cs, text_bytes: bytes, text_vaddr: int,
    start: int, byte_count: int,
) -> list[tuple[int, int, str, str]]:
    """Capstone decode a byte window into (address, size, mnemonic, op_str)."""
    offset = start - text_vaddr
    if offset < 0 or offset >= len(text_bytes) or byte_count <= 0:
        return []
    end = min(offset + byte_count, len(text_bytes))
    return [
        (insn.address, insn.size, insn.mnemonic, insn.op_str)
        for insn in cs.disasm(text_bytes[offset:end], start)
    ]


def _backward_start_aligned(
    cs: Cs, text_bytes: bytes, text_vaddr: int,
    addr: int, context: int,
) -> int:
    """Find the largest `start` in `[addr - context, addr)` such that
    decoding from `start` produces a stream whose last instruction ends
    exactly at `addr`.

    For ARM64 this is just `(addr - context) & ~3` since fixed-length
    4-byte instructions are always aligned. For x86, instruction length
    is variable (1-15 bytes), so we iterate candidate starts outward
    from `addr` and keep the largest one that round-trips through
    capstone with the last instruction's `addr + size == addr`. This is
    the standard "backward alignment scan" trick that debuggers use
    when there's no function-start anchor available.
    """
    if cs.arch == CS_ARCH_ARM64:
        return max(text_vaddr, (addr - context) & ~3)

    best = addr  # sentinel: no valid backward window
    for off in range(1, context + 1):
        start = addr - off
        if start < text_vaddr:
            break
        stream = _decode_sized(cs, text_bytes, text_vaddr, start, off)
        if stream and stream[-1][0] + stream[-1][1] == addr:
            best = start
    return best


def disassemble_around(
    cs: Cs, text_bytes: bytes, text_vaddr: int,
    addr: int, context: int = 24,
    func_start: int | None = None,
) -> list[tuple[int, str, str]]:
    """Disassemble instructions in the window [addr-context, addr+context).

    Returns [(address, mnemonic, op_str), ...]. `text_vaddr` is the virtual
    address at which `text_bytes` begins (so byte offset = addr - text_vaddr).
    Empty list if the window falls outside the section.

    The forward half is decoded starting at `addr`, so whenever `addr`
    really is an instruction boundary the target shows up as an
    `insn.address == addr` entry (which the caller uses for highlight).
    The backward half has to land on an instruction boundary —
    trivial on ARM64 (4-byte alignment) but variable-length on x86.
    If `func_start` is provided (caller has a symbol table and knows
    the enclosing function entry), we decode from there; otherwise we
    run the backward alignment scan in `_backward_start_aligned`.

    Fallback for crash frames: on x86 a crash PC can legitimately
    fall mid-instruction (the CPU reports the faulting byte, which
    may be inside an instruction capstone can't decode starting from
    that exact offset). In that case the forward-from-`addr` decode
    yields nothing and we fall back to sweeping backward from
    `addr - context` and keeping whatever capstone produces — there's
    no valid `is_target` hit but the surrounding instructions still
    give the user context.
    """
    if not text_bytes:
        return []

    # -- forward half: addr is always a valid instruction boundary.
    forward = _decode_sized(cs, text_bytes, text_vaddr, addr, context)

    # -- backward half: pick a start that lands on a boundary.
    if func_start is not None and addr <= func_start:
        # `addr` is the function entry (or past the end of its
        # symbol range). Nothing valid lives in `[addr - context,
        # addr)` as far as this function's body goes, so skip the
        # backward half entirely — reaching into the preceding
        # function's epilogue + padding yields instructions tagged
        # with the wrong source line.
        back_start = addr
    elif (
        func_start is not None
        and addr - func_start <= context * 6
        and func_start >= text_vaddr
    ):
        back_start = func_start
    else:
        back_start = _backward_start_aligned(
            cs, text_bytes, text_vaddr, addr, context)

    backward: list[tuple[int, int, str, str]] = []
    if back_start < addr:
        backward = _decode_sized(
            cs, text_bytes, text_vaddr, back_start, addr - back_start)
        window_lo = addr - context
        backward = [ins for ins in backward if ins[0] >= window_lo]

    result: list[tuple[int, str, str]] = [
        (a, m, o) for (a, _sz, m, o) in backward
    ]
    result.extend((a, m, o) for (a, _sz, m, o) in forward)

    # Fallback for crash PCs that land mid-instruction: the forward
    # decode returned 0 instructions and the backward scan didn't
    # find any aligned window either. Do the pre-fix thing and hand
    # capstone whatever byte range we have — the `is_target` match
    # will fail for `addr` itself but at least the UI shows something.
    if not result:
        start = max(text_vaddr, addr - context)
        if cs.arch == CS_ARCH_ARM64:
            start = start & ~3
        end = addr + context
        sweep = _decode_sized(
            cs, text_bytes, text_vaddr, start, end - start)
        result = [(a, m, o) for (a, _sz, m, o) in sweep]

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
