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
them. They have `address` pointing at the function entry point,
`source_loc` from LLDB's line table, and a `MapSymbol` built from
the discovered name. They do not have valid spill-slot variable
data because no stack frame physically existed for them — param
values, locals, and register state are unrecoverable.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .models import FrameInfo, MapSymbol

if TYPE_CHECKING:
    from .lldb_backend import LldbBackend


_MAX_HOPS = 4


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
                parent_return_addr=parent.address,
                parent_function=parent_sym,
                child_symbol=child_sym,
                parent_module=parent.module,
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
    parent_return_addr: int,
    parent_function: str | None,
    child_symbol: str,
    parent_module: str,
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
    """
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

    # Build FrameInfo objects for each step. The final backtrace
    # order is: child (lower index) ↑ chain ↑ parent (higher
    # index). We collected `chain` in parent-to-child order (the
    # first entry is what parent directly called), so reverse for
    # insertion order.
    synthetic_frames: list[FrameInfo] = []
    for name, jmp_addr, jmp_src in reversed(chain):
        fake_sym = MapSymbol(
            address=jmp_addr, name=name,
            object_file=parent_module or '', is_function=True)
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
        ))
    return synthetic_frames
