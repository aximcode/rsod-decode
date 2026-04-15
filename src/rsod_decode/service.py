"""Shared analysis pipeline for the CLI and web UI.

Owns the full flow that used to live in `app.py`'s `/api/session`
handler:

  1. Call `decoder.analyze_rsod()` for the pyelftools baseline.
  2. Pick a richer backend (LLDB corefile or PE+PDB minidump, GDB
     corefile, or stay on pyelftools).
  3. Backfill per-frame `source_loc` + `symbol` from the richer
     backend's line-table-aware resolver.
  4. Reconstruct frames elided by compiler tail-call optimization.
  5. Expose a `resolve_frame_vars()` helper that returns the
     params/locals/globals lists the formatters render (web JSON
     serializer, CLI text formatter).

No Flask, no Session store, no serializers, no argparse. Both
`app.create_session` and `decoder.decode_rsod` delegate here.
"""
from __future__ import annotations

import re
import shutil
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from .decoder import AnalysisResult, analyze_rsod
from .models import (
    FrameInfo, MapSymbol, SymbolSource, VarInfo,
    binary_for_frame, find_source_file,
)
from .session import gdb_available, lldb_available

if TYPE_CHECKING:
    from .gdb_backend import GdbBackend
    from .lldb_backend import LldbBackend
    from .models import BinaryBackend


BackendChoice = Literal['auto', 'lldb', 'gdb', 'pyelftools']
# The choices a running context can actually report (no 'auto').
ActiveBackend = Literal['lldb', 'gdb', 'pyelftools']


# =============================================================================
# Source-location normalization (moved from app.py)
# =============================================================================

# Comment prefixes that shouldn't count as the "first real line of the
# function body" when advancing past a bare `{`.
_COMMENT_START_PREFIXES = ('//', '/*')

# `(void)argc;` et al. — MSVC unused-parameter suppression that often
# appears immediately inside a function body. Skip so the highlight
# lands on the first genuinely executable statement.
_UNUSED_PARAM_RE = re.compile(r'^\(void\)\w+\s*;\s*(?://.*)?$')


def advance_past_brace_line(
    source_loc: str, roots: Iterable[Path] | None = None,
) -> str:
    """Normalize a `file:line` past an opening-brace-only line.

    MSVC's PDB frequently maps a faulting or tail-call `jmp` back to
    the function's opening `{`. Walk forward up to 8 lines to find
    the first line with real code. Returns `source_loc` unchanged if
    the file isn't reachable or the line already contains real code.
    """
    if not source_loc or ':' not in source_loc:
        return source_loc
    file_part, line_part = source_loc.rsplit(':', 1)
    try:
        target_line = int(line_part)
    except ValueError:
        return source_loc
    if target_line < 1:
        return source_loc

    root_list = list(roots or [])
    abs_path = Path(file_part)
    src_path: Path | None
    if abs_path.is_absolute() and abs_path.is_file():
        src_path = abs_path
    else:
        src_path = find_source_file(root_list, file_part, target_line)
    if src_path is None:
        return source_loc

    try:
        lines = src_path.read_text(
            encoding='utf-8', errors='replace').splitlines()
    except OSError:
        return source_loc

    def _is_code(text: str) -> bool:
        t = text.strip()
        if not t:
            return False
        if t in ('{', '}'):
            return False
        if t.startswith(_COMMENT_START_PREFIXES):
            return False
        if _UNUSED_PARAM_RE.match(t):
            return False
        return True

    idx = target_line - 1
    if idx >= len(lines):
        return source_loc
    if _is_code(lines[idx]):
        return source_loc

    for delta in range(1, 9):
        probe = idx + delta
        if probe >= len(lines):
            break
        if _is_code(lines[probe]):
            return f'{file_part}:{target_line + delta}'
    return source_loc


# =============================================================================
# Analysis context
# =============================================================================

@dataclass
class AnalysisContext:
    """Holds everything the formatters need after run_analysis.

    The web UI wraps this inside a `Session` (for HTTP state, cache,
    ID). The CLI uses it directly and calls `close()` when done.
    """
    result: AnalysisResult
    source: SymbolSource
    extras: dict[str, SymbolSource] = field(default_factory=dict)
    rsod_text: str = ''
    temp_dir: Path | None = None
    elf_path: Path | None = None
    pe_path: Path | None = None
    pdb_path: Path | None = None
    backend: ActiveBackend = 'pyelftools'
    lldb_backend: LldbBackend | None = None
    gdb_backend: GdbBackend | None = None

    @property
    def image_base(self) -> int:
        """Runtime image base, mirrors Session.img_base."""
        ci = self.result.crash_info
        if ci.image_base:
            return ci.image_base
        frames = self.result.frames
        if ci.crash_pc and frames and frames[0].address:
            return ci.crash_pc - frames[0].address
        return 0

    @property
    def rich_backend(self) -> LldbBackend | GdbBackend | None:
        """Return the richer (LLDB/GDB) backend or None."""
        return self.lldb_backend or self.gdb_backend

    def active_binary_for_frame(
        self, frame: FrameInfo,
    ) -> BinaryBackend | None:
        """Pick the backend to use for a frame's params/locals/disasm.

        When the active backend is LLDB or GDB and the frame belongs
        to the primary module, use the richer backend directly.
        Otherwise fall back to the module's static pyelftools/PE
        binary via `models.binary_for_frame`.
        """
        rich: LldbBackend | GdbBackend | None
        if self.backend == 'lldb':
            rich = self.lldb_backend
        elif self.backend == 'gdb':
            rich = self.gdb_backend
        else:
            rich = None
        static = binary_for_frame(frame, self.source, self.extras)
        if rich is not None and static is self.source.binary:
            return rich
        return static

    def close(self) -> None:
        """Close backends and remove the tempdir.

        The Flask `Session` has its own `cleanup_session` path, so web
        sessions call that instead. The CLI calls this directly.
        """
        for b in (self.lldb_backend, self.gdb_backend):
            if b is None:
                continue
            close = getattr(b, 'close', None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass
        self.lldb_backend = None
        self.gdb_backend = None
        if self.source.binary is not None:
            try:
                self.source.binary.close()
            except Exception:
                pass
        for src in self.extras.values():
            if src.binary is not None:
                try:
                    src.binary.close()
                except Exception:
                    pass
        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)


# =============================================================================
# Pipeline
# =============================================================================

def run_analysis(
    rsod_text: str,
    source: SymbolSource,
    extras: dict[str, SymbolSource] | None = None,
    *,
    base_override: int | None = None,
    symbol_search_paths: list[Path] | None = None,
    temp_dir: Path | None = None,
    elf_path: Path | None = None,
    pe_path: Path | None = None,
    pdb_path: Path | None = None,
    backend: BackendChoice = 'auto',
    source_roots: Iterable[Path] | None = None,
    reconstruct_tail_calls: bool = True,
) -> AnalysisContext:
    """Run the full analysis pipeline and return a populated context.

    `backend='auto'` picks lldb → gdb → pyelftools in that order,
    skipping backends that can't load the session (e.g. GDB on a
    PE+PDB primary). Explicit values force a specific backend and
    silently fall back to pyelftools if initialization fails.
    """
    analysis = analyze_rsod(
        rsod_text, source, extras or {}, base_override,
        symbol_search_paths=symbol_search_paths)
    ctx = AnalysisContext(
        result=analysis,
        source=source,
        extras=extras or {},
        rsod_text=rsod_text,
        temp_dir=temp_dir,
        elf_path=elf_path,
        pe_path=pe_path,
        pdb_path=pdb_path,
    )
    _init_backend(ctx, backend)

    roots = list(source_roots or [])
    _backfill_source_loc(ctx, roots)
    if reconstruct_tail_calls:
        _maybe_reconstruct_tail_calls(ctx, roots)
    return ctx


def reinit_backend(
    ctx: AnalysisContext, target: ActiveBackend,
    source_roots: Iterable[Path] | None = None,
) -> str | None:
    """Lazy-init `target` on an existing context.

    Returns an error message string on failure or None on success.
    Mirrors the behavior of `/api/backend` — used by both the web
    route and any future CLI re-invocation.
    """
    if target not in ('pyelftools', 'gdb', 'lldb'):
        return f'backend must be pyelftools/gdb/lldb, got {target!r}'
    if target == ctx.backend:
        return None

    if target == 'pyelftools':
        ctx.backend = 'pyelftools'
        return None

    if target == 'gdb':
        if not gdb_available():
            return 'GDB/pygdbmi not available'
        if ctx.pe_path is not None:
            return 'GDB backend requires an ELF primary; this session is PE+PDB'
        if ctx.gdb_backend is None:
            err = _init_gdb_backend(ctx)
            if err:
                return err
        ctx.backend = 'gdb'

    elif target == 'lldb':
        if not lldb_available():
            return 'lldb Python module not available'
        if ctx.lldb_backend is None:
            err = _init_lldb_backend(ctx)
            if err:
                return err
        ctx.backend = 'lldb'

    _backfill_source_loc(ctx, list(source_roots or []))
    return None


# =============================================================================
# Per-frame variable resolution (shared by /api/frame and the CLI formatter)
# =============================================================================

def resolve_frame_vars(
    ctx: AnalysisContext, frame_idx: int,
) -> tuple[list[VarInfo], list[VarInfo], list[VarInfo]]:
    """Return (params, locals, globals) for one frame.

    Uses the active backend (lldb > gdb > pyelftools) appropriate to
    the frame's module. Handles synthetic-frame short-circuit,
    callsite_params merge at the VarInfo level, and backend-specific
    globals routing.
    """
    frame = ctx.result.frames[frame_idx]

    # Synthetic tail-call frames have no physical stack; render only
    # whatever the reconstructor recovered from the caller's argreg
    # setup as the param list.
    if frame.is_synthetic:
        return (list(frame.callsite_params), [], [])

    binary = ctx.active_binary_for_frame(frame)
    if binary is None or not frame.address:
        return ([], [], [])

    # For non-crash frames, DWARF/PDB location info at the return
    # address lands in DW_OP_entry_value ranges (unresolvable for
    # caller-saved regs). Subtracting 1 from the call instruction
    # address puts us inside the caller's previous range where the
    # variable is still on the stack (DW_OP_fbreg).
    lookup_pc = frame.address
    if not frame.is_crash_frame and frame.call_addr:
        lookup_pc = frame.call_addr - 1

    params = list(binary.get_params(lookup_pc))
    locals_ = list(binary.get_locals(lookup_pc))

    _merge_callsite_params(params, frame.callsite_params)

    # Globals: pyelftools discovers CU-scope names; richer backends
    # evaluate runtime values via evaluate_globals.
    static_binary = binary_for_frame(frame, ctx.source, ctx.extras)
    if static_binary is not None:
        raw_globals = list(static_binary.get_globals(frame.address))
        rich = ctx.rich_backend
        if rich is not None and hasattr(rich, 'evaluate_globals'):
            try:
                raw_globals = list(rich.evaluate_globals(raw_globals))
            except Exception:
                pass
        globals_ = raw_globals
    else:
        globals_ = list(binary.get_globals(frame.address))

    return (params, locals_, globals_)


def _merge_callsite_params(
    params: list[VarInfo], callsite_params: list[VarInfo],
) -> None:
    """Merge tail-call-recovered values onto the backend's param list.

    Mutates `params` in place. For each recovered param, if a param
    with the same name already exists, fill in any missing value /
    string_preview / expand info from the recovered one. Otherwise
    append the recovered param verbatim.
    """
    if not callsite_params:
        return
    by_name = {p.name: p for p in params}
    for recovered in callsite_params:
        dst = by_name.get(recovered.name)
        if dst is None:
            params.append(recovered)
            continue
        if dst.value is None and recovered.value is not None:
            dst.value = recovered.value
            if recovered.location:
                dst.location = recovered.location
        if not dst.string_preview and recovered.string_preview:
            dst.string_preview = recovered.string_preview
        if recovered.is_expandable and recovered.var_key and not dst.var_key:
            dst.is_expandable = True
            dst.expand_addr = recovered.expand_addr
            dst.var_key = recovered.var_key


# =============================================================================
# Backend init helpers (private)
# =============================================================================

def _frame_data(ctx: AnalysisContext) -> list[tuple[int, int]]:
    return [(f.frame_fp, f.address) for f in ctx.result.frames]


def _init_backend(ctx: AnalysisContext, choice: BackendChoice) -> None:
    """Initialize the chosen backend; on failure fall back to pyelftools."""
    if choice == 'pyelftools':
        ctx.backend = 'pyelftools'
        return

    if choice in ('auto', 'lldb') and lldb_available():
        if _init_lldb_backend(ctx) is None:
            ctx.backend = 'lldb'
            return

    # GDB can only target ELF+DWARF; PE sessions skip it.
    if choice in ('auto', 'gdb') and gdb_available() and ctx.pe_path is None:
        if _init_gdb_backend(ctx) is None:
            ctx.backend = 'gdb'
            return

    ctx.backend = 'pyelftools'


def _init_lldb_backend(ctx: AnalysisContext) -> str | None:
    """Instantiate LldbBackend. Returns error or None."""
    try:
        from .lldb_backend import LldbBackend
    except Exception as e:
        return f'cannot import lldb_backend: {e}'
    ci = ctx.result.crash_info
    frames = _frame_data(ctx)
    try:
        if ctx.pe_path is not None and ctx.pdb_path is not None:
            ctx.lldb_backend = LldbBackend.from_pe_pdb(
                ctx.pe_path, ctx.pdb_path,
                ci.registers, ci.crash_pc,
                ctx.result.stack_base, ctx.result.stack_mem,
                ctx.image_base, frames=frames)
        elif ctx.pe_path is None and ctx.elf_path is not None:
            ctx.lldb_backend = LldbBackend(
                ctx.elf_path,
                ci.registers, ci.crash_pc,
                ctx.result.stack_base, ctx.result.stack_mem,
                ctx.image_base, frames=frames)
        else:
            return 'LLDB needs either (pe_path+pdb_path) or elf_path'
    except Exception as e:
        return f'LLDB backend init failed: {e}'
    return None


def _init_gdb_backend(ctx: AnalysisContext) -> str | None:
    """Instantiate GdbBackend. Returns error or None."""
    try:
        from .gdb_backend import GdbBackend
    except Exception as e:
        return f'cannot import gdb_backend: {e}'
    if ctx.elf_path is None:
        return 'GDB backend requires elf_path'
    ci = ctx.result.crash_info
    try:
        ctx.gdb_backend = GdbBackend(
            ctx.elf_path,
            ci.registers, ci.crash_pc,
            ctx.result.stack_base, ctx.result.stack_mem,
            ctx.image_base, frames=_frame_data(ctx))
    except Exception as e:
        return f'GDB backend init failed: {e}'
    return None


# =============================================================================
# Source-location backfill + tail-call reconstruction (moved from app.py)
# =============================================================================

def _backfill_source_loc(
    ctx: AnalysisContext, roots: list[Path],
) -> None:
    """Fill missing per-frame source_loc / symbol from the richer backend."""
    backend = ctx.rich_backend
    resolve = getattr(backend, 'resolve_address', None)
    if resolve is None:
        return
    for f in ctx.result.frames:
        if f.source_loc and f.symbol:
            continue
        target = (f.call_addr - 1) if f.call_addr else f.address
        if not target:
            continue
        info = resolve(target)
        if info is None:
            continue
        if info.source_loc and not f.source_loc:
            f.source_loc = advance_past_brace_line(info.source_loc, roots)
        if info.function and f.symbol is None:
            f.symbol = MapSymbol(
                address=f.address, name=info.function,
                object_file=f.module or '', is_function=True)


def _maybe_reconstruct_tail_calls(
    ctx: AnalysisContext, roots: list[Path],
) -> None:
    """Synthesize frames elided by MSVC/GCC tail-call optimization.

    Only runs when the LLDB backend is attached (the reconstructor
    reads disassembly annotations from LLDB). Safe to call multiple
    times — synthetic frames are marked `is_synthetic=True` and
    filtered out before feeding the reconstructor again.
    """
    if ctx.lldb_backend is None:
        return
    try:
        from .lldb_backend import LldbBackend
    except Exception:
        return
    if not isinstance(ctx.lldb_backend, LldbBackend):
        return
    from .tail_call_reconstructor import reconstruct_tail_calls

    original = [f for f in ctx.result.frames if not f.is_synthetic]
    rebuilt = reconstruct_tail_calls(original, ctx.lldb_backend)
    if len(rebuilt) == len(original):
        return
    if roots:
        for f in rebuilt:
            if f.is_synthetic and f.source_loc:
                f.source_loc = advance_past_brace_line(f.source_loc, roots)
    ctx.result.frames = rebuilt
