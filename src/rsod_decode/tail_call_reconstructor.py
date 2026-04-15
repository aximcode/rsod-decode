"""Synthesize stack frames for MSVC/GCC tail-called functions.

When a compiler emits a function as `jmp target` instead of
`call target; ret`, the caller's stack shows the tail-called chain
collapsed into a single hop. For example, if the source says
`fForceCrashIfRequested` → `run_crashtest` → `initialize_test`, but
`run_crashtest` is 5 instructions ending in `jmp initialize_test`,
the runtime stack only shows `fForceCrashIfRequested` directly above
`initialize_test`. `run_crashtest` left no trace.

This module uses the LLDB backend's disassembly-annotation surface
to re-materialize those elided frames. The approach:

1. For each parent/child pair, read the instruction in `parent` that
   returns to `parent.address` (the call that produced the next-down
   frame). LLDB annotates that instruction's target with a symbol
   name if it's a direct call to a known function.
2. If the annotated target matches `child.symbol`, the stack is
   already complete — no work.
3. Otherwise, the annotated target is the "real" callee. Insert a
   synthetic frame for it, then check that target's disassembly: if
   it ends in an unconditional `jmp <known_symbol>`, that's another
   tail hop. Recurse up to `max_hops` until we hit `child.symbol` or
   the chain dead-ends (indirect jump, ret, unknown symbol).

Returned frames have `is_synthetic=True` set so the UI can badge
them. `address` points at the function's tail-call `jmp` instruction,
`source_loc` comes from LLDB's line table, and a `MapSymbol` is built
from the discovered name.

Parameter values for synthetic wrappers are reconstructed via
`LldbBackend.resolve_callsite_args`: we walk backward from the
caller's call/jmp instruction, decode the MSVC x64 argument-register
setup (``RCX``/``RDX``/``R8``/``R9``), and propagate the resolved
values forward through the chain — a wrapper that doesn't modify an
argument register inherits its caller's value, and a wrapper that
does (e.g. ``dispatch_crash`` setting ``$0xd`` before jmp'ing into
``trigger_gp_fault``) overrides that register in the working set.
The result lands on `FrameInfo.callsite_params` and is rendered by
`/api/frame` as the synthetic frame's parameter list.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .callsite_args import ARG_REGS_CANONICAL, KIND_UNKNOWN, CallsiteArg
from .models import FrameInfo, MapSymbol, VarInfo

if TYPE_CHECKING:
    from .lldb_backend import LldbBackend


_MAX_HOPS = 4


def _kind_to_location(arg: CallsiteArg) -> str:
    """Map a resolved callsite arg to a UI-friendly `location` string."""
    return f'{arg.kind} ({arg.source})'


def _callsite_args_to_varinfos(
    backend: LldbBackend,
    function_name: str,
    working_set: dict[str, CallsiteArg],
) -> list[VarInfo]:
    """Build a VarInfo list from the resolved callsite args for a
    function with a known PDB parameter signature.

    The MSVC x64 calling convention passes the first four int-sized
    parameters in ``RCX`` / ``RDX`` / ``R8`` / ``R9``, in declaration
    order. We look up the declared parameter names via
    `LldbBackend.get_function_parameters` so the UI shows
    ``ctx = 0x...`` instead of ``RCX = 0x...``. Fifth+ parameters and
    floating-point arguments are not reconstructed today — they'd
    need stack-spill analysis and XMM state respectively.
    """
    params = backend.get_function_parameters(function_name)
    out: list[VarInfo] = []
    for i, (name, type_name) in enumerate(params[:4]):
        reg = ARG_REGS_CANONICAL[i]
        arg = working_set.get(reg)
        if arg is None or arg.kind == KIND_UNKNOWN or arg.value is None:
            out.append(VarInfo(
                name=name, type_name=type_name,
                location=f'{reg.upper()} (tail-call, unresolved)'))
            continue
        out.append(VarInfo(
            name=name, type_name=type_name,
            value=arg.value,
            location=f'{reg.upper()} ({arg.source})'))
    return out


def reconstruct_tail_calls(
    frames: list[FrameInfo], backend: LldbBackend,
) -> list[FrameInfo]:
    """Return a new frame list with tail-call frames inserted.

    `frames` is in crash-first order (frame 0 = innermost / crash PC).
    For each adjacent `(child, parent)` pair where `parent` is
    further up the stack than `child`, we consult the backend to
    reconstruct any tail-called functions between parent's call
    instruction and child's entry. The synthetic frames are spliced
    in ascending index order and the whole list is re-indexed from 0.

    The function mutates nothing; it returns a new list. If the
    backend has no way to find the call annotation, pairs are
    emitted unchanged.
    """
    if len(frames) < 2:
        return list(frames)

    out: list[FrameInfo] = [frames[0]]
    for i in range(len(frames) - 1):
        child = frames[i]
        parent = frames[i + 1]

        # Skip when either frame has no resolvable symbol. Can't
        # reconstruct a chain without knowing the child's name, and
        # we can't query the call site without parent's function.
        child_sym = child.symbol.name if child.symbol else None
        parent_sym = parent.symbol.name if parent.symbol else None

        if child_sym and parent.address:
            synthetic = _chain_between(
                backend,
                parent=parent,
                child=child,
                parent_function=parent_sym,
                child_symbol=child_sym,
            )
            # Synthetic frames are caller-to-callee order: the first
            # entry is what `parent` directly called, the last entry
            # tail-called `child`. They all sit between parent and
            # child in the backtrace — indices higher than child's
            # (deeper on stack), lower than parent's.
            for s in synthetic:
                out.append(s)

        out.append(parent)

    # Re-index so frame.index matches list position.
    for new_idx, f in enumerate(out):
        f.index = new_idx
    return out


def _chain_between(
    backend: LldbBackend,
    parent: FrameInfo,
    child: FrameInfo,
    parent_function: str | None,
    child_symbol: str,
) -> list[FrameInfo]:
    """Build the intermediate synthetic frames between parent and child.

    Walks at most `_MAX_HOPS` tail calls forward from parent's direct
    callee until the chain meets `child_symbol`. Each synthetic
    frame's location is pinned to its tail-call `jmp` instruction —
    the last thing the function executed before handing control
    off to the next link — rather than the function entry. This is
    what the UI should highlight in Source/Disassembly, because
    "where execution was" at the moment of elision is the jmp, not
    the prologue.

    Callsite argument reconstruction: the physical parent's ``call``
    instruction sets up ``RCX``/``RDX``/``R8``/``R9`` for the first
    wrapper. A "working set" of those register values is carried
    through the chain, and each wrapper's own backward walk (from
    its terminating ``jmp``) overrides any register it modifies
    (e.g. ``dispatch_crash``'s ``movl $0xd, %ecx`` before the
    ``jmp trigger_gp_fault``). Each synthetic frame's
    ``callsite_params`` captures the working set **at the moment
    of entry into that frame** — i.e. *before* its own body runs.
    """
    parent_return_addr = parent.address
    parent_module = parent.module

    direct = backend.find_callee_at_return_addr(
        parent_return_addr, parent_function)
    if direct is None:
        return []
    direct_name, _direct_src = direct

    # Direct callee is already the child — nothing to reconstruct.
    if direct_name == child_symbol:
        return []

    # Walk the tail-call chain starting from `direct_name`. At each
    # step, `tail_call_target` returns the jmp's target symbol plus
    # the (addr, source_loc) of the jmp instruction itself. We
    # record one (name, jmp_addr, jmp_src) tuple per synthetic
    # frame: `name` is the function we're sitting in, `jmp_*` is
    # its tail-call site.
    chain: list[tuple[str, int, str]] = []
    current = direct_name
    for _ in range(_MAX_HOPS):
        tail = backend.tail_call_target(current)
        if tail is None:
            # `current` has a real ret or an indirect jmp — the
            # chain doesn't reach `child_symbol` via tail calls.
            # Drop the whole reconstruction rather than inserting
            # a dangling partial chain.
            return []
        target_name, jmp_addr, jmp_src = tail
        chain.append((current, jmp_addr, jmp_src))
        if target_name == child_symbol:
            break
        current = target_name
    else:
        # Ran out of hops without reaching the child. Drop.
        return []

    # Bootstrap the callsite-arg working set from the physical
    # parent's call instruction (the one that entered the first
    # wrapper). `parent_body_rsp` is the post-prologue RSP at the
    # moment of that call — fetched from LLDB's unwind of the
    # parent frame.
    parent_body_rsp = backend.frame_body_rsp(parent.address)
    parent_call_addr = backend.call_site_addr_for_return(parent.address)
    working_set: dict[str, CallsiteArg] = {}
    if parent_call_addr is not None:
        working_set.update(backend.resolve_callsite_args(
            parent_call_addr, body_rsp=parent_body_rsp))

    # Every wrapper in the chain shares one stack pointer value:
    # the initial `call` pushed a return address (8 bytes), and
    # none of the pure-jmp wrappers touches RSP afterwards. So
    # each wrapper's own body walks with `body_rsp = parent_body_rsp - 8`.
    wrapper_body_rsp = (
        parent_body_rsp - 8 if parent_body_rsp is not None else None)

    # `chain` is in caller-to-callee order. For each entry we know:
    #   - `name`: the function we're sitting in (the wrapper itself)
    #   - `jmp_addr`: the wrapper's own terminating jmp site
    # The working_set captured above holds the args AT ENTRY to the
    # first wrapper. We snapshot that for `chain[0]`, then walk each
    # wrapper's own body from its jmp to pick up any register
    # modifications before recording the NEXT wrapper's entry args.
    per_frame_args: list[dict[str, CallsiteArg]] = []
    for step_idx, (name, jmp_addr, _jmp_src) in enumerate(chain):
        # Entry args for this wrapper = current working_set snapshot.
        per_frame_args.append(dict(working_set))
        # Walk the wrapper's own body from its terminating jmp, and
        # update the working set with anything the wrapper writes.
        # The resolver stops scanning a register once it finds a
        # write, so this gives us "registers modified somewhere in
        # the wrapper before the jmp".
        if step_idx < len(chain) - 1 or True:
            wrapper_args = backend.resolve_callsite_args(
                jmp_addr, body_rsp=wrapper_body_rsp)
            for reg, arg in wrapper_args.items():
                if arg.value is not None and arg.kind != KIND_UNKNOWN:
                    working_set[reg] = arg

    # Build FrameInfo objects. Order: collected chain goes
    # caller→callee, but the backtrace walks innermost→outermost,
    # so we emit in reverse so `synthetic_frames[0]` is the deepest
    # (closest to `child`) and `synthetic_frames[-1]` is closest to
    # `parent`.
    synthetic_frames: list[FrameInfo] = []
    for (name, jmp_addr, jmp_src), entry_args in reversed(
            list(zip(chain, per_frame_args))):
        fake_sym = MapSymbol(
            address=jmp_addr, name=name,
            object_file=parent_module or '', is_function=True)
        callsite_params = _callsite_args_to_varinfos(
            backend, name, entry_args)
        synthetic_frames.append(FrameInfo(
            index=0,  # re-indexed by caller
            address=jmp_addr,
            module=parent_module,
            symbol=fake_sym,
            sym_offset=0,
            source_loc=jmp_src,
            is_crash_frame=False,
            call_addr=jmp_addr,
            is_synthetic=True,
            callsite_params=callsite_params,
        ))

    # Bonus: if the child is the crash frame, also fill its
    # `callsite_params` — its entry registers are what the last
    # wrapper in the chain set up right before its `jmp`. This
    # recovers register-held scalar params (e.g. trigger_gp_fault's
    # `vector=0xd`) that LLDB can't read from the crash-time
    # register snapshot because the callee hasn't spilled them.
    if child.is_crash_frame and child_symbol:
        _attach_crash_frame_callsite_params(
            backend, child, child_symbol, working_set)

    return synthetic_frames


def _attach_crash_frame_callsite_params(
    backend: LldbBackend,
    frame: FrameInfo,
    function_name: str,
    working_set: dict[str, CallsiteArg],
) -> None:
    """Populate the crash frame's `callsite_params` from the tail-call
    chain's final working set (the registers set up by the wrapper
    that jmp'd into it)."""
    frame.callsite_params = _callsite_args_to_varinfos(
        backend, function_name, working_set)
