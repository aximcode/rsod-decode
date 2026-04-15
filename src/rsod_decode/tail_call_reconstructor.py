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


def _looks_like_char_pointer(type_name: str) -> bool:
    """Heuristic: does this type name denote a pointer to a character
    type whose dereference would produce a NUL-terminated string?
    Matches `const char *`, `char *`, `unsigned char *`, etc., plus
    the MSVC `CHAR *`/`CHAR16 *` aliases.
    """
    t = type_name.replace(' ', '')
    if not t.endswith('*'):
        return False
    return 'char' in t.lower() or 'CHAR' in t


def _strip_pointer_suffix(type_name: str) -> str | None:
    """For a ``T *`` type name, return the canonical ``T``. Strips
    qualifiers (``const``, ``volatile``) and struct/class/union
    prefixes. Returns ``None`` if ``type_name`` isn't a pointer or
    ``char``-ish (those are handled by the C-string preview path).
    """
    t = type_name.strip()
    if not t.endswith('*'):
        return None
    t = t[:-1].strip()
    for prefix in ('const ', 'volatile ',
                   'struct ', 'class ', 'union '):
        while t.startswith(prefix):
            t = t[len(prefix):].strip()
    if not t or 'char' in t.lower():
        return None
    return t


def _callsite_args_to_varinfos(
    backend: LldbBackend,
    function_name: str,
    working_set: dict[str, CallsiteArg],
    frame_pc: int,
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

    Pointer enrichment: for ``char *``-ish params with a resolved
    pointer value, we read a short C-string preview via the backend
    so the UI shows ``build_id = 0x1800f7438 "crashtest-v3"``. For
    pointers to struct/class/union types we create a synthetic
    SBValue at the pointed-at address via
    `LldbBackend.make_struct_pointer_value` and wire up
    ``is_expandable``/``expand_addr``/``var_key`` so the UI's expand
    arrow can walk the struct through the normal `/api/expand`
    path. ``frame_pc`` keys the cache so var_keys are unique across
    frames.
    """
    params = backend.get_function_parameters(function_name)
    out: list[VarInfo] = []
    for i, (name, type_name) in enumerate(params[:4]):
        reg = ARG_REGS_CANONICAL[i]
        arg = working_set.get(reg)
        if arg is None or arg.kind == KIND_UNKNOWN or arg.value is None:
            loc = f'{reg.upper()} (tail-call, unresolved)'
            if arg is not None and arg.source:
                loc = f'{reg.upper()} ({arg.source})'
            out.append(VarInfo(
                name=name, type_name=type_name, location=loc))
            continue
        var = VarInfo(
            name=name, type_name=type_name,
            value=arg.value,
            location=f'{reg.upper()} ({arg.source})')
        if _looks_like_char_pointer(type_name):
            preview = backend._read_cstring_via_process(arg.value)
            if preview:
                var.string_preview = preview
        else:
            pointee = _strip_pointer_suffix(type_name)
            if pointee:
                var_key = backend.make_struct_pointer_value(
                    name, arg.value, pointee, frame_pc)
                if var_key:
                    var.is_expandable = True
                    var.expand_addr = arg.value
                    var.var_key = var_key
        out.append(var)
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

    Every child — whether or not a tail-call chain was inserted —
    also receives ``callsite_params``: the argument-register working
    set that the child sees at entry, derived by walking the parent's
    call instruction backward plus any intermediate wrapper-body
    modifications. This lets ``/api/frame`` surface parameter values
    that LLDB itself can't read (register-held scalars on the crash
    frame, spill-slot-reused pointers on downstream physical frames
    like ``initialize_test``).

    Pairs are resolved **outer-to-inner** (oldest caller first) so
    that when a chase chain bottoms out at an unmodified entry
    argument register, the parent frame's ``callsite_params`` have
    already been computed and can be cross-referenced for cross-frame
    value propagation (recovers ``run_crashtest.argc`` from
    ``fForceCrashIfRequested.callsite_params[0]`` which in turn was
    recovered from ``fUEFIPSAEntry``'s call site).

    The function mutates the child frames' ``callsite_params`` fields
    and returns a new list (synthetics spliced in). Original frame
    objects are updated in place.
    """
    if len(frames) < 2:
        return list(frames)

    synthetics_between: dict[int, list[FrameInfo]] = {}

    # Pass 1: resolve callsite args + synthetic chains outer → inner,
    # so each pair's `parent.callsite_params` is already populated
    # when the next pair's child tries to cross-ref.
    for i in range(len(frames) - 2, -1, -1):
        child = frames[i]
        parent = frames[i + 1]

        child_sym = child.symbol.name if child.symbol else None
        parent_sym = parent.symbol.name if parent.symbol else None

        if not child_sym or not parent.address:
            synthetics_between[i] = []
            continue

        synthetic, child_entry_args = _resolve_chain_and_args(
            backend,
            parent=parent,
            child=child,
            parent_function=parent_sym,
            child_symbol=child_sym,
        )
        synthetics_between[i] = synthetic

        if child_entry_args:
            # Cross-frame propagation: for any arg the chase left
            # flagged as "unmodified entry register N of parent",
            # substitute the parent's own callsite_params[N] (which
            # has already been computed in a prior iteration of
            # this outer-to-inner pass).
            _propagate_entry_args_from_parent(
                child_entry_args, parent)
            child.callsite_params = _callsite_args_to_varinfos(
                backend, child_sym, child_entry_args,
                frame_pc=child.address)

    # Pass 2: build the output frame list in crash-first order with
    # synthetic frames spliced in.
    out: list[FrameInfo] = [frames[0]]
    for i in range(len(frames) - 1):
        for s in synthetics_between.get(i, []):
            out.append(s)
        out.append(frames[i + 1])

    for new_idx, f in enumerate(out):
        f.index = new_idx
    return out


def _propagate_entry_args_from_parent(
    working_set: dict[str, CallsiteArg],
    parent: FrameInfo,
) -> None:
    """Mutate ``working_set``: for any entry whose chain bottomed out
    at an unmodified arg register of the enclosing function, look up
    that register's value in ``parent.callsite_params`` (indexed by
    ``entry_arg_index``) and substitute it.

    Only fires when the parent already has ``callsite_params`` filled
    in (i.e. the outer-to-inner pass has already processed it). No-op
    otherwise — we simply leave the chain unresolved.
    """
    if not parent.callsite_params:
        return
    for reg, arg in list(working_set.items()):
        if arg.value is not None:
            continue
        idx = arg.entry_arg_index
        if idx is None or idx >= len(parent.callsite_params):
            continue
        parent_var = parent.callsite_params[idx]
        if parent_var.value is None:
            continue
        # Substitute the value but keep the original provenance
        # string so tooltips show the full chain.
        working_set[reg] = CallsiteArg(
            reg=reg,
            kind=arg.kind,
            value=parent_var.value,
            source=(
                f'{arg.source} → {parent.symbol.name if parent.symbol else "caller"}'
                f'.{parent_var.name}'),
            entry_arg_index=idx,
        )


def _resolve_chain_and_args(
    backend: LldbBackend,
    parent: FrameInfo,
    child: FrameInfo,
    parent_function: str | None,
    child_symbol: str,
) -> tuple[list[FrameInfo], dict[str, CallsiteArg]]:
    """Build synthetic frames between parent and child AND return the
    argument-register working set the child sees at entry.

    - Bootstraps the working set from the physical parent's ``call``
      instruction (what it loaded into ``RCX``/``RDX``/``R8``/``R9``
      right before entering the first callee).
    - If ``direct_callee == child_symbol`` we return the bootstrap
      working set with no synthetic frames — that's the normal
      "one physical call, no tail-elision" case and the child still
      wants those reconstructed entry registers for backfill.
    - If the chain reaches ``child_symbol`` through 1..N tail-called
      wrappers, builds synthetic FrameInfos for each, snapshots the
      working set at every wrapper's entry (so each synthetic frame
      sees what it was *given*, not what it passes forward), and
      merges in any arg-register writes the wrapper itself made
      before its own terminating ``jmp``.
    - The final working set returned to the caller is what the
      child sees at its entry (after every wrapper in the chain
      has run).
    """
    parent_return_addr = parent.address
    parent_module = parent.module

    direct = backend.find_callee_at_return_addr(
        parent_return_addr, parent_function)

    # Bootstrap the callsite-arg working set from the physical
    # parent's call instruction. ``parent_body_rsp`` is the
    # post-prologue RSP at the moment of that call, fetched from
    # LLDB's unwind of the parent frame.
    parent_body_rsp = backend.frame_body_rsp(parent.address)
    parent_call_addr = backend.call_site_addr_for_return(parent.address)
    working_set: dict[str, CallsiteArg] = {}
    if parent_call_addr is not None:
        working_set.update(backend.resolve_callsite_args(
            parent_call_addr, body_rsp=parent_body_rsp))

    # No parseable call site at all — nothing to return.
    if direct is None:
        return [], working_set

    direct_name, _direct_src = direct

    # Direct call (no tail-elision). The child receives the
    # bootstrap working set verbatim at its entry.
    if direct_name == child_symbol:
        return [], working_set

    # Walk the tail-call chain starting from ``direct_name``. Each
    # step: ``tail_call_target`` returns the jmp's target symbol
    # plus the (addr, source_loc) of the jmp instruction itself.
    chain: list[tuple[str, int, str]] = []
    current = direct_name
    for _ in range(_MAX_HOPS):
        tail = backend.tail_call_target(current)
        if tail is None:
            # ``current`` has a real ret or an indirect jmp — the
            # chain doesn't reach ``child_symbol`` via tail calls.
            # Drop the whole reconstruction rather than inserting a
            # dangling partial chain (the bootstrap working_set
            # still applies to the physical call, so return it).
            return [], working_set
        target_name, jmp_addr, jmp_src = tail
        chain.append((current, jmp_addr, jmp_src))
        if target_name == child_symbol:
            break
        current = target_name
    else:
        return [], working_set

    # Every wrapper in the chain shares one stack-pointer value: the
    # initial ``call`` pushed a return address (8 bytes), and no
    # pure-jmp wrapper touches RSP afterwards. Wrapper body walks
    # therefore use ``body_rsp = parent_body_rsp - 8``.
    wrapper_body_rsp = (
        parent_body_rsp - 8 if parent_body_rsp is not None else None)

    # Cross-frame propagate before we even start building wrapper
    # snapshots: the very first wrapper's entry regs are whatever the
    # physical parent's call instruction set up, and those may
    # themselves depend on the parent's own incoming args.
    _propagate_entry_args_from_parent(working_set, parent)

    # For each wrapper we snapshot the working set *before* walking
    # the wrapper's own body — that's what the wrapper sees at its
    # entry. Then we update the working set with any registers the
    # wrapper writes before its terminating jmp, so the next link
    # in the chain inherits the modified state.
    per_frame_args: list[dict[str, CallsiteArg]] = []
    for (name, jmp_addr, _jmp_src) in chain:
        per_frame_args.append(dict(working_set))
        wrapper_args = backend.resolve_callsite_args(
            jmp_addr, body_rsp=wrapper_body_rsp)
        for reg, arg in wrapper_args.items():
            if arg.value is not None and arg.kind != KIND_UNKNOWN:
                working_set[reg] = arg

    # Build FrameInfo objects. ``chain`` is caller→callee; the
    # backtrace walks innermost→outermost, so emit in reverse so
    # ``synthetic_frames[0]`` is closest to ``child``.
    synthetic_frames: list[FrameInfo] = []
    for (name, jmp_addr, jmp_src), entry_args in reversed(
            list(zip(chain, per_frame_args))):
        fake_sym = MapSymbol(
            address=jmp_addr, name=name,
            object_file=parent_module or '', is_function=True)
        callsite_params = _callsite_args_to_varinfos(
            backend, name, entry_args, frame_pc=jmp_addr)
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

    return synthetic_frames, working_set
