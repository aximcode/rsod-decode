"""Unit tests for the MSVC x64 callsite argument resolver.

These run entirely in Python with hand-crafted instruction lists — no
LLDB, no fixture binaries. They cover the patterns
`tail_call_reconstructor.py` relies on when it fills in parameter
values for synthetic tail-called wrappers: immediate loads, RSP/RBP/R11
anchored ``lea``, RIP-relative loads, ``xor reg, reg`` zeroing, and the
"cannot resolve" fallbacks.
"""
from __future__ import annotations

from rsod_decode.callsite_args import (
    ARG_REGS_CANONICAL,
    KIND_IMMEDIATE,
    KIND_IP_REL,
    KIND_REGISTER,
    KIND_STACK_PTR,
    KIND_STACK_VALUE,
    KIND_UNKNOWN,
    KIND_ZERO,
    canonicalize_register,
    detect_stack_alloc,
    has_r11_entry_anchor,
    parse_operand,
    resolve_callsite_args,
    split_operands,
)


def _noop_reader(_addr: int, _size: int) -> bytes | None:
    return None


def test_canonicalize_register_aliases() -> None:
    assert canonicalize_register('%rcx') == 'rcx'
    assert canonicalize_register('ecx') == 'rcx'
    assert canonicalize_register('cl') == 'rcx'
    assert canonicalize_register('r8d') == 'r8'
    assert canonicalize_register('r15w') == 'r15'
    assert canonicalize_register('rip') == 'rip'
    assert canonicalize_register('nope') is None


def test_parse_immediate_operand() -> None:
    op = parse_operand('$0x1234')
    assert op.kind == 'imm' and op.value == 0x1234
    # Negatives are stored as unsigned 64-bit bit patterns so MSVC's
    # movabsq $-0x2100... renders cleanly as 0xDEFFBABECAFE0000.
    op = parse_operand('$-0x10')
    assert op.kind == 'imm' and op.value == 0xFFFFFFFFFFFFFFF0
    op = parse_operand('$-0x2100454135020000')
    assert op.kind == 'imm' and op.value == 0xDEFFBABECAFE0000
    op = parse_operand('$42')
    assert op.kind == 'imm' and op.value == 42


def test_parse_register_operand() -> None:
    op = parse_operand('%rcx')
    assert op.kind == 'reg' and op.reg == 'rcx'
    op = parse_operand('%r11')
    assert op.kind == 'reg' and op.reg == 'r11'


def test_parse_memory_operand() -> None:
    op = parse_operand('-0x38(%r11)')
    assert op.kind == 'mem' and op.reg == 'r11' and op.disp == -0x38
    op = parse_operand('(%rbx)')
    assert op.kind == 'mem' and op.reg == 'rbx' and op.disp == 0
    op = parse_operand('0x28(%rsp)')
    assert op.kind == 'mem' and op.reg == 'rsp' and op.disp == 0x28
    op = parse_operand('0xf1302(%rip)')
    assert op.kind == 'mem' and op.reg == 'rip' and op.disp == 0xf1302


def test_split_operands_handles_nested_parens() -> None:
    parts = split_operands('-0x38(%r11,%rax,4), %rcx')
    assert parts == ['-0x38(%r11,%rax,4)', '%rcx']


def test_detect_stack_alloc_finds_subq() -> None:
    insns = [
        (0x1000, 'movq', '%rsp, %r11'),
        (0x1003, 'subq', '$0x58, %rsp'),
        (0x1007, 'movq', '0x10(%rcx), %rax'),
    ]
    assert detect_stack_alloc(insns) == 0x58
    # No subq present → 0.
    assert detect_stack_alloc(insns[:1]) == 0


def test_has_r11_entry_anchor() -> None:
    insns = [
        (0x1000, 'movq', '%rsp, %r11'),
        (0x1003, 'subq', '$0x58, %rsp'),
    ]
    assert has_r11_entry_anchor(insns) is True
    assert has_r11_entry_anchor([(0x1000, 'subq', '$0x58, %rsp')]) is False


def test_resolve_immediate_before_call() -> None:
    # `movl $0xd, %ecx` then `jmp trigger_gp_fault`.
    insns = [
        (0x100, 'movl', '$0xd, %ecx'),
        (0x105, 'jmp', '0x200'),
    ]
    out = resolve_callsite_args(insns, call_index=1, body_rsp=0x1000,
                                memory_reader=_noop_reader)
    assert 'rcx' in out
    assert out['rcx'].kind == KIND_IMMEDIATE
    assert out['rcx'].value == 0xd


def test_resolve_lea_r11_with_stack_alloc() -> None:
    # Mirrors initialize_test's `leaq -0x38(%r11), %rcx; call prepare_crash_context`.
    # body_rsp=0x25fff110, stack_alloc=0x58 → r11=0x25fff168, result=0x25fff130.
    insns = [
        (0x180006100, 'movq', '%rsp, %r11'),
        (0x180006103, 'subq', '$0x58, %rsp'),
        (0x180006107, 'movq', '0x10(%rcx), %rax'),
        (0x18000610b, 'movabsq', '$-0x2100454135020000, %rdx'),
        (0x180006115, 'movq', '%rcx, -0x38(%r11)'),
        (0x180006119, 'xorq', '%rdx, %rax'),
        (0x18000611c, 'movl', '$0x1, 0x28(%rsp)'),
        (0x180006124, 'leaq', '-0x38(%r11), %rcx'),
        (0x180006128, 'movq', '%rax, -0x28(%r11)'),
        (0x18000613f, 'callq', '0x18000614c'),
    ]
    out = resolve_callsite_args(
        insns, call_index=len(insns) - 1,
        body_rsp=0x25fff110, memory_reader=_noop_reader)
    assert 'rcx' in out
    assert out['rcx'].kind == KIND_STACK_PTR
    assert out['rcx'].value == 0x25fff130


def test_resolve_lea_rsp_direct() -> None:
    insns = [
        (0x100, 'subq', '$0x40, %rsp'),
        (0x104, 'leaq', '0x20(%rsp), %r8'),
        (0x108, 'callq', '0x200'),
    ]
    out = resolve_callsite_args(insns, call_index=2, body_rsp=0x8000,
                                memory_reader=_noop_reader)
    assert out['r8'].kind == KIND_STACK_PTR
    assert out['r8'].value == 0x8020


def test_resolve_rip_relative_lea_via_register_chase() -> None:
    # `leaq 0xf1302(%rip), %rax` at addr 0x18000612f; next insn at 0x180006136.
    # Effective address = 0x180006136 + 0xf1302 = 0x1800f7438.
    # The `mov %rax, %rdx` chases %rax one hop back, picks up the
    # lea, and propagates the ip-rel address forward.
    insns = [
        (0x18000612f, 'leaq', '0xf1302(%rip), %rax'),
        (0x180006136, 'movq', '%rax, %rdx'),
        (0x180006139, 'callq', '0x200'),
    ]
    out = resolve_callsite_args(insns, call_index=2, body_rsp=0x1000,
                                memory_reader=_noop_reader)
    assert out['rdx'].kind == KIND_IP_REL
    assert out['rdx'].value == 0x1800f7438
    # Provenance chain is preserved in the source string so the UI
    # can hover-explain the derivation.
    assert '%rax' in out['rdx'].source
    assert 'lea' in out['rdx'].source


def test_register_chase_bails_at_function_start() -> None:
    # `mov %ecx, %edi` saves the incoming ecx, then later
    # `mov %edi, %edx` copies it to the arg reg — we can trace
    # %edi one hop back to %ecx but %ecx was never written inside
    # the function, so we end at KIND_REGISTER with a chain like
    # `mov %edi ← mov %ecx`.
    insns = [
        (0x100, 'movl', '%ecx, %edi'),
        (0x102, 'movl', '%edi, %edx'),
        (0x104, 'callq', '0x200'),
    ]
    out = resolve_callsite_args(insns, call_index=2, body_rsp=None,
                                memory_reader=_noop_reader)
    assert out['rdx'].kind == KIND_REGISTER
    assert out['rdx'].value is None
    # The provenance chain should record both hops.
    assert 'rdi' in out['rdx'].source
    assert 'rcx' in out['rdx'].source


def test_resolve_stack_value_via_memory_reader() -> None:
    # `movq 0x10(%rsp), %rcx` should trigger a memory read at rsp+0x10.
    reads: dict[int, bytes] = {0x8010: (0xDEAD_BEEF_CAFE_BABE).to_bytes(8, 'little')}
    insns = [
        (0x100, 'movq', '0x10(%rsp), %rcx'),
        (0x105, 'callq', '0x200'),
    ]
    out = resolve_callsite_args(
        insns, call_index=1, body_rsp=0x8000,
        memory_reader=lambda addr, size: reads.get(addr))
    assert out['rcx'].kind == KIND_STACK_VALUE
    assert out['rcx'].value == 0xDEAD_BEEF_CAFE_BABE


def test_xor_reg_reg_is_zero() -> None:
    insns = [
        (0x100, 'xorl', '%ecx, %ecx'),
        (0x102, 'callq', '0x200'),
    ]
    out = resolve_callsite_args(insns, call_index=1, body_rsp=None,
                                memory_reader=_noop_reader)
    assert out['rcx'].kind == KIND_ZERO
    assert out['rcx'].value == 0


def test_unresolved_operand_marks_unknown() -> None:
    # `addq $0x10, %rcx` is a tracked write but the resolver doesn't
    # model arithmetic, so it should record the register as UNKNOWN
    # and stop scanning earlier definitions.
    insns = [
        (0x0f0, 'movl', '$0x5, %ecx'),  # earlier, stale
        (0x0f5, 'addq', '$0x10, %rcx'),
        (0x0f9, 'callq', '0x200'),
    ]
    out = resolve_callsite_args(insns, call_index=2, body_rsp=None,
                                memory_reader=_noop_reader)
    assert out['rcx'].kind == KIND_UNKNOWN
    # Earlier movl is ignored because the intervening addq shadows it.


def test_walker_stops_at_function_start() -> None:
    # No resolving write for rcx anywhere in the function.
    insns = [
        (0x100, 'subq', '$0x20, %rsp'),
        (0x104, 'movq', '0x18(%rax), %rdx'),
        (0x108, 'callq', '0x200'),
    ]
    out = resolve_callsite_args(insns, call_index=2, body_rsp=0x9000,
                                memory_reader=_noop_reader)
    # rdx resolves via memory through %rax which we can't evaluate →
    # unknown; rcx/r8/r9 never referenced so they don't appear.
    assert 'rcx' not in out
    assert 'rdx' in out and out['rdx'].kind == KIND_UNKNOWN


def test_all_arg_regs_covered_by_constants() -> None:
    assert set(ARG_REGS_CANONICAL) == {'rcx', 'rdx', 'r8', 'r9'}
