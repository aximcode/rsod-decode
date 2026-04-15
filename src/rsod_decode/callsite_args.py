"""Reconstruct MSVC x64 argument register values at a call / jmp site.

Tail-called function wrappers compiled with MSVC x64 calling convention
leave no physical stack frame, so the debugger has nothing to read when
it wants to show the wrapper's parameter values. The workaround is to
walk backward from the caller's ``call`` (or ``jmp``) instruction and
decode how the four integer argument registers — ``RCX``, ``RDX``,
``R8``, ``R9`` — were set up. For the tail-call wrappers rsod-decode
reconstructs today this recovers the right value in ~every case because
the wrappers either propagate the outer caller's registers unchanged or
do a single ``mov imm``/``lea`` right before the final jmp.

The decoder handles the AT&T operand shapes LLDB emits:

- ``$imm``                              → literal
- ``%reg``                              → register-to-register copy
- ``(%base)`` / ``disp(%base)``         → memory at ``base + disp``
- ``disp(%base,%index,scale)``          → ``base + disp + index*scale``
- ``disp(%rip)``                        → RIP-relative (absolute file addr)

Addressing bases the resolver knows how to turn into absolute values:

- ``%rsp``           → body RSP (supplied by the caller)
- ``%rbp``           → frame pointer (supplied by the caller, if any)
- ``%r11``           → MSVC entry-RSP anchor, set by ``movq %rsp, %r11``
                       in the prologue. Resolved as ``body_rsp + stack_alloc``.
- ``%rip``           → next-instruction address of the referencing insn

Anything else (including reads through caller-saved registers the
resolver hasn't tracked) is reported as ``KIND_UNKNOWN``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable

Instr = tuple[int, str, str]  # (decoder-facing addr, mnemonic, operands)

# x86 MSVC calling convention — first four int/pointer args.
ARG_REGS_CANONICAL = ('rcx', 'rdx', 'r8', 'r9')

KIND_UNKNOWN = 'unknown'
KIND_IMMEDIATE = 'immediate'
KIND_STACK_PTR = 'stack_ptr'    # lea reg, [stack+N] → address on the stack
KIND_STACK_VALUE = 'stack_value'  # mov reg, [stack+N] → deref stack
KIND_IP_REL = 'ip_rel'          # lea reg, [rip+N] / mov reg, [rip+N]
KIND_REGISTER = 'register'      # mov reg, other_reg (chain unresolved)
KIND_ZERO = 'zero'              # xor reg, reg


@dataclass
class CallsiteArg:
    """Resolved value for one MSVC x64 argument register."""
    reg: str              # canonical lower-case register name (rcx/rdx/r8/r9)
    kind: str             # one of the KIND_* constants
    value: int | None     # resolved address/literal, or None if unknown
    source: str           # short provenance string for UI tooltips
    # When a register-copy chain bottoms out at an unwritten arg
    # register in the enclosing function (i.e. the value was inherited
    # from whatever the function's own caller placed in that register
    # at entry), this field carries the arg index 0..3 (rcx/rdx/r8/r9).
    # The reconstructor uses it to cross-reference the parent frame's
    # own callsite_params for cross-frame value propagation:
    #   run_crashtest.argc    (register-chained to fForceCrashIfRequested's
    #                          entry %ecx, arg0)
    #     → fForceCrashIfRequested.callsite_params[0] == 0x3
    #     → run_crashtest.argc = 0x3
    entry_arg_index: int | None = None


# ---------------------------------------------------------------------------
# Register name canonicalization
# ---------------------------------------------------------------------------

# 8 / 16 / 32 / 64 bit aliases all map to the canonical 64-bit name.
_REG_ALIASES: dict[str, str] = {}


def _register_aliases() -> dict[str, str]:
    if _REG_ALIASES:
        return _REG_ALIASES
    base = {
        'rax': ('rax', 'eax', 'ax', 'ah', 'al'),
        'rbx': ('rbx', 'ebx', 'bx', 'bh', 'bl'),
        'rcx': ('rcx', 'ecx', 'cx', 'ch', 'cl'),
        'rdx': ('rdx', 'edx', 'dx', 'dh', 'dl'),
        'rsi': ('rsi', 'esi', 'si', 'sil'),
        'rdi': ('rdi', 'edi', 'di', 'dil'),
        'rsp': ('rsp', 'esp', 'sp', 'spl'),
        'rbp': ('rbp', 'ebp', 'bp', 'bpl'),
        'rip': ('rip', 'eip', 'ip'),
    }
    for i in range(8, 16):
        canonical = f'r{i}'
        base[canonical] = (
            canonical, f'r{i}d', f'r{i}w', f'r{i}b', f'r{i}l')
    for canonical, aliases in base.items():
        for a in aliases:
            _REG_ALIASES[a] = canonical
    return _REG_ALIASES


def canonicalize_register(name: str) -> str | None:
    """Return the canonical 64-bit register name, or None if unrecognized."""
    return _register_aliases().get(name.strip().lstrip('%').lower())


# ---------------------------------------------------------------------------
# Operand parsing
# ---------------------------------------------------------------------------

_RE_IMM_HEX = re.compile(r'^\$\s*(-?)0x([0-9a-fA-F]+)$')
_RE_IMM_DEC = re.compile(r'^\$\s*(-?\d+)$')
_RE_REG = re.compile(r'^%([a-zA-Z]\w*)$')

# Memory operand: [disp](base[,index[,scale]])  — disp optional.
_RE_MEM = re.compile(
    r'^\s*(?P<disp>-?0x[0-9a-fA-F]+|-?\d+)?'
    r'\s*\(\s*'
    r'(?:%(?P<base>[a-zA-Z]\w+))?'
    r'(?:\s*,\s*%(?P<index>[a-zA-Z]\w+)\s*,\s*(?P<scale>\d+))?'
    r'\s*\)\s*$')


@dataclass
class Operand:
    """Parsed representation of an AT&T operand.

    ``kind`` is one of ``'imm'``, ``'reg'``, ``'mem'``, or ``'other'``.
    ``reg`` is populated for ``reg``/``mem`` (base reg) kinds with the
    canonical name. ``disp`` / ``index`` / ``scale`` apply to memory
    operands; ``value`` holds immediate literals.
    """
    kind: str
    reg: str | None = None
    disp: int = 0
    index: str | None = None
    scale: int = 1
    value: int | None = None
    raw: str = ''


def parse_operand(text: str) -> Operand:
    t = text.strip()
    if not t:
        return Operand(kind='other', raw=text)

    m = _RE_IMM_HEX.match(t)
    if m:
        sign = -1 if m.group(1) == '-' else 1
        raw_val = sign * int(m.group(2), 16)
        # Two's-complement mask to 64 bits so sign-extended constants
        # (e.g. MSVC's movabsq $-0x2100..., which is really
        #  0xDEFFBABECAFE0000) render as unsigned bit patterns.
        return Operand(
            kind='imm', value=raw_val & 0xFFFFFFFFFFFFFFFF, raw=text)
    m = _RE_IMM_DEC.match(t)
    if m:
        raw_val = int(m.group(1))
        return Operand(
            kind='imm', value=raw_val & 0xFFFFFFFFFFFFFFFF, raw=text)

    m = _RE_REG.match(t)
    if m:
        canonical = canonicalize_register(m.group(1))
        if canonical is not None:
            return Operand(kind='reg', reg=canonical, raw=text)
        return Operand(kind='other', raw=text)

    m = _RE_MEM.match(t)
    if m:
        disp_s = m.group('disp') or '0'
        try:
            if disp_s.lower().startswith(('-0x', '0x')):
                disp = int(disp_s, 16)
            elif disp_s.startswith('-0x'):
                disp = -int(disp_s[3:], 16)
            else:
                disp = int(disp_s)
        except ValueError:
            disp = 0
        base_name = m.group('base')
        base = canonicalize_register(base_name) if base_name else None
        index_name = m.group('index')
        index = canonicalize_register(index_name) if index_name else None
        scale = int(m.group('scale')) if m.group('scale') else 1
        return Operand(
            kind='mem', reg=base, disp=disp,
            index=index, scale=scale, raw=text)

    return Operand(kind='other', raw=text)


def split_operands(ops: str) -> list[str]:
    """Split an AT&T operand string on commas that aren't inside parens."""
    out: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in ops:
        if ch == '(':
            depth += 1
            current.append(ch)
        elif ch == ')':
            depth -= 1
            current.append(ch)
        elif ch == ',' and depth == 0:
            out.append(''.join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        out.append(''.join(current).strip())
    return out


# ---------------------------------------------------------------------------
# Prologue detection
# ---------------------------------------------------------------------------

def detect_stack_alloc(instructions: Iterable[Instr]) -> int:
    """Return the ``sub rsp, IMM`` amount from the enclosing function's
    prologue, or 0 if none is found in the first few instructions.

    MSVC x64 functions that reserve stack do so with a single
    ``subq $N, %rsp`` inside the first ~10 instructions.
    """
    for i, (_, mnem, ops) in enumerate(instructions):
        if i > 15:
            break
        if mnem.lower() not in ('sub', 'subq'):
            continue
        parts = split_operands(ops)
        if len(parts) != 2:
            continue
        src, dst = parse_operand(parts[0]), parse_operand(parts[1])
        if dst.kind == 'reg' and dst.reg == 'rsp' and src.kind == 'imm':
            return src.value or 0
    return 0


def has_r11_entry_anchor(instructions: Iterable[Instr]) -> bool:
    """True if the function starts with ``movq %rsp, %r11`` — MSVC's
    idiom for capturing the entry RSP into R11 so the body can use
    ``[r11+N]``-style addressing."""
    for i, (_, mnem, ops) in enumerate(instructions):
        if i > 5:
            break
        if mnem.lower() not in ('mov', 'movq'):
            continue
        parts = split_operands(ops)
        if len(parts) != 2:
            continue
        src, dst = parse_operand(parts[0]), parse_operand(parts[1])
        if (src.kind == 'reg' and src.reg == 'rsp'
                and dst.kind == 'reg' and dst.reg == 'r11'):
            return True
    return False


# ---------------------------------------------------------------------------
# Backward-walking resolver
# ---------------------------------------------------------------------------

MemoryReader = Callable[[int, int], bytes | None]


@dataclass
class _ResolverCtx:
    body_rsp: int | None
    entry_rsp: int | None  # body_rsp + stack_alloc; used for [r11±N]
    fp: int | None          # rbp/frame pointer if known
    memory_reader: MemoryReader
    r11_anchored: bool


# How deep we chase register copies (`mov %rcx, %edx`) backward through
# the same function. MSVC often saves an incoming parameter into a
# non-volatile register (``mov %ecx, %edi``) and later shuffles it
# into another arg register at a call site (``mov %edi, %edx``); one
# hop catches that idiom. We stop at the function prologue so we never
# loop forever and we don't pretend to resolve values that originated
# in the function's own parameters (which would themselves need an
# outer-caller's callsite walk to recover).
_MAX_REG_CHASE_DEPTH = 2


def _resolve_address(
    operand: Operand, insn_addr: int, insn_size: int, ctx: _ResolverCtx,
) -> tuple[int | None, str]:
    """Given a memory operand, compute the absolute address it points at.

    Returns ``(address, reason)`` where ``address`` is ``None`` when we
    couldn't resolve the expression and ``reason`` is a short provenance
    string for tooltips / diagnostics.
    """
    if operand.kind != 'mem' or operand.reg is None:
        return None, f'unsupported operand {operand.raw!r}'
    base = operand.reg
    if base == 'rsp' and ctx.body_rsp is not None:
        return ctx.body_rsp + operand.disp, f'[rsp{operand.disp:+d}]'
    if base == 'rbp' and ctx.fp is not None:
        return ctx.fp + operand.disp, f'[rbp{operand.disp:+d}]'
    if base == 'r11' and ctx.r11_anchored and ctx.entry_rsp is not None:
        return ctx.entry_rsp + operand.disp, f'[r11{operand.disp:+d}]'
    if base == 'rip':
        return insn_addr + insn_size + operand.disp, f'rip+0x{operand.disp:x}'
    return None, f'unresolved base {base!r}'


def _read_u64(addr: int, ctx: _ResolverCtx) -> int | None:
    data = ctx.memory_reader(addr, 8)
    if not data or len(data) < 8:
        return None
    return int.from_bytes(data[:8], 'little')


def _instr_size(insns: list[Instr], idx: int) -> int:
    """Approximate instruction size from successive addresses."""
    if idx + 1 < len(insns):
        return max(1, insns[idx + 1][0] - insns[idx][0])
    return 1  # best-effort for the last instruction


def _destination_canonical(ops: str) -> tuple[str | None, Operand | None, Operand | None]:
    """Return (canonical_dest_reg, source_operand, dest_operand) for a
    two-operand AT&T instruction — or ``(None, None, None)`` if the
    destination isn't a register or the operand count is wrong."""
    parts = split_operands(ops)
    if len(parts) != 2:
        return None, None, None
    src, dst = parse_operand(parts[0]), parse_operand(parts[1])
    if dst.kind != 'reg' or dst.reg is None:
        return None, None, None
    return dst.reg, src, dst


def _resolve_instruction_write(
    instructions: list[Instr],
    idx: int,
    target_reg: str,
    ctx: _ResolverCtx,
    depth: int,
) -> CallsiteArg | None:
    """Decode ``instructions[idx]`` as a write to ``target_reg`` and
    return a ``CallsiteArg`` describing what value it deposited, or
    ``None`` if the instruction doesn't write ``target_reg`` (or the
    write isn't decodable).

    ``depth`` caps recursive register-copy chasing (``mov %edi, %edx``
    → look back for ``mov %ecx, %edi``). The top-level call passes
    ``_MAX_REG_CHASE_DEPTH``; each recursion decrements by 1 and
    stops at 0.
    """
    addr, mnem, ops = instructions[idx]
    mnem_l = mnem.lower()
    insn_size = _instr_size(instructions, idx)

    if mnem_l in ('xor', 'xorl', 'xorq', 'xorw', 'xorb'):
        dst_reg, src, _dst = _destination_canonical(ops)
        if (dst_reg == target_reg and src is not None
                and src.kind == 'reg' and src.reg == dst_reg):
            return CallsiteArg(
                reg=target_reg, kind=KIND_ZERO, value=0,
                source=f'xor {target_reg},{target_reg}')
        return None

    if mnem_l in ('mov', 'movl', 'movq', 'movw', 'movb',
                  'movabs', 'movabsq', 'movsxd', 'movzx',
                  'movslq', 'movzbl', 'movzwl'):
        dst_reg, src, _dst = _destination_canonical(ops)
        if dst_reg != target_reg or src is None:
            return None
        if src.kind == 'imm':
            return CallsiteArg(
                reg=target_reg, kind=KIND_IMMEDIATE, value=src.value,
                source=f'mov ${src.value:#x}')
        if src.kind == 'reg' and src.reg:
            chased = _chase_register(
                instructions, idx - 1, src.reg, ctx, depth - 1)
            if chased is not None:
                # Preserve the provenance chain so tooltips can show
                # where the value originated, and carry through any
                # ``entry_arg_index`` if the chain bottomed out at an
                # unwritten arg register.
                return CallsiteArg(
                    reg=target_reg, kind=chased.kind,
                    value=chased.value,
                    source=f'mov %{src.reg} ← {chased.source}',
                    entry_arg_index=chased.entry_arg_index)
            return CallsiteArg(
                reg=target_reg, kind=KIND_REGISTER, value=None,
                source=f'mov %{src.reg}')
        if src.kind == 'mem':
            abs_addr, why = _resolve_address(src, addr, insn_size, ctx)
            if abs_addr is None:
                return CallsiteArg(
                    reg=target_reg, kind=KIND_UNKNOWN, value=None,
                    source=f'mov {why}')
            if src.reg == 'rip':
                val = _read_u64(abs_addr, ctx)
                return CallsiteArg(
                    reg=target_reg,
                    kind=KIND_STACK_VALUE if val is not None
                    else KIND_IP_REL,
                    value=val if val is not None else abs_addr,
                    source=f'mov {why}')
            val = _read_u64(abs_addr, ctx)
            if val is not None:
                return CallsiteArg(
                    reg=target_reg, kind=KIND_STACK_VALUE, value=val,
                    source=f'mov {why}')
            return CallsiteArg(
                reg=target_reg, kind=KIND_UNKNOWN, value=None,
                source=f'mov {why} (unreadable)')
        return None

    if mnem_l in ('lea', 'leal', 'leaq'):
        dst_reg, src, _dst = _destination_canonical(ops)
        if dst_reg != target_reg or src is None or src.kind != 'mem':
            return None
        abs_addr, why = _resolve_address(src, addr, insn_size, ctx)
        if abs_addr is None:
            return CallsiteArg(
                reg=target_reg, kind=KIND_UNKNOWN, value=None,
                source=f'lea {why}')
        kind = KIND_IP_REL if src.reg == 'rip' else KIND_STACK_PTR
        return CallsiteArg(
            reg=target_reg, kind=kind, value=abs_addr,
            source=f'lea {why}')

    # Any other instruction that touches `target_reg` (add, sub, shl,
    # or, etc.) — we can't model arithmetic without a full dataflow
    # walker, so report UNKNOWN so the caller stops scanning earlier
    # (potentially stale) definitions.
    dst_reg, _src, _dst = _destination_canonical(ops)
    if dst_reg == target_reg and mnem_l not in ('cmp', 'test'):
        return CallsiteArg(
            reg=target_reg, kind=KIND_UNKNOWN, value=None,
            source=f'{mnem_l} ... (not tracked)')
    return None


_ENTRY_ARG_INDEX: dict[str, int] = {
    'rcx': 0, 'rdx': 1, 'r8': 2, 'r9': 3,
}


def _chase_register(
    instructions: list[Instr],
    start_idx: int,
    target_reg: str,
    ctx: _ResolverCtx,
    depth: int,
) -> CallsiteArg | None:
    """Walk backward from ``start_idx`` looking for the most recent
    write to ``target_reg``. Returns the decoded write, or a synthetic
    "entry arg" CallsiteArg when the chain hits the function start
    without finding a write AND ``target_reg`` is one of the MSVC x64
    int-argument registers — that signals "the value is whatever the
    function's own caller placed in that register at entry", which
    the reconstructor can cross-reference against the parent frame's
    ``callsite_params``.
    """
    if depth <= 0 or start_idx < 0:
        return _entry_arg_sentinel(target_reg)
    for idx in range(start_idx, -1, -1):
        arg = _resolve_instruction_write(
            instructions, idx, target_reg, ctx, depth)
        if arg is not None:
            return arg
    return _entry_arg_sentinel(target_reg)


def _entry_arg_sentinel(reg: str) -> CallsiteArg | None:
    """Return a CallsiteArg for `reg` interpreted as "unmodified at
    function entry" — i.e. inherited from the caller's own setup.
    Only meaningful for MSVC x64 int-arg registers (rcx/rdx/r8/r9);
    returns None for anything else (callee-saved / non-ABI regs).
    """
    idx = _ENTRY_ARG_INDEX.get(reg)
    if idx is None:
        return None
    return CallsiteArg(
        reg=reg, kind=KIND_REGISTER, value=None,
        source=f'caller arg{idx} (%{reg} unmodified at entry)',
        entry_arg_index=idx,
    )


def resolve_callsite_args(
    instructions: list[Instr],
    call_index: int,
    body_rsp: int | None,
    memory_reader: MemoryReader,
    fp: int | None = None,
) -> dict[str, CallsiteArg]:
    """Walk backward from ``instructions[call_index]`` resolving each of
    the four MSVC x64 integer-argument registers.

    ``instructions`` must cover the entire enclosing function body (in
    order). ``call_index`` points at the ``call``/``jmp`` instruction we
    want to resolve. ``body_rsp`` is the post-prologue RSP at the moment
    the call was about to execute — the caller is responsible for
    supplying it (from ``SBFrame.GetSP()`` for physical frames, or from
    an inherited chain value for tail-called wrappers).

    Register-copy chasing: when the walker sees ``mov %rdi, %rdx`` it
    recursively looks back for a write to ``%rdi`` so the MSVC idiom
    of saving an incoming parameter to a non-volatile register and
    later shuffling it into an arg register at a call site resolves
    to the underlying value (or at least a richer provenance chain).
    The recursion is bounded by ``_MAX_REG_CHASE_DEPTH``.

    Returns a dict keyed by canonical argument register name. Registers
    the walker couldn't resolve are omitted; the caller can use the
    presence of a key to decide whether to render the parameter.
    """
    stack_alloc = detect_stack_alloc(instructions)
    entry_rsp = (
        body_rsp + stack_alloc if body_rsp is not None else None)
    ctx = _ResolverCtx(
        body_rsp=body_rsp,
        entry_rsp=entry_rsp,
        fp=fp,
        memory_reader=memory_reader,
        r11_anchored=has_r11_entry_anchor(instructions),
    )

    remaining = set(ARG_REGS_CANONICAL)
    resolved: dict[str, CallsiteArg] = {}

    for idx in range(call_index - 1, -1, -1):
        if not remaining:
            break
        # For each instruction, probe it against every arg register
        # still in play. `_resolve_instruction_write` returns None for
        # instructions that don't write the register, so at most one
        # register moves from `remaining` to `resolved` per instruction.
        for reg in list(remaining):
            arg = _resolve_instruction_write(
                instructions, idx, reg, ctx, _MAX_REG_CHASE_DEPTH)
            if arg is None:
                continue
            resolved[reg] = arg
            remaining.discard(reg)

    return resolved
