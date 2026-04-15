"""Session state management for the RSOD debugger web UI."""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .decoder import AnalysisResult
from .gdb_bridge import GdbSession, find_gdb
from .lldb_loader import import_lldb
from .models import SymbolSource

if TYPE_CHECKING:
    from .service import AnalysisContext


# =============================================================================
# Session data
# =============================================================================

@dataclass
class Session:
    """In-memory session holding all analysis state."""
    id: str
    result: AnalysisResult
    source: SymbolSource
    extra_sources: dict[str, SymbolSource] = field(default_factory=dict)
    rsod_text: str = ''
    created_at: str = ''
    temp_dir: Path | None = None
    elf_path: Path | None = None
    pe_path: Path | None = None  # MSVC .efi when session is PE+PDB
    pdb_path: Path | None = None  # MSVC .pdb when paired with a PE
    gdb: GdbSession | None = None
    gdb_dwarf: object | None = None  # GdbBackend instance (alternative DWARF backend)
    lldb_dwarf: object | None = None  # LldbBackend instance (alternative DWARF backend)
    backend: str = 'pyelftools'  # 'pyelftools', 'gdb', or 'lldb'
    frame_cache: dict[int, dict] = field(default_factory=dict)

    @property
    def img_base(self) -> int:
        """Runtime image base: maps ELF addresses to runtime addresses."""
        ci = self.result.crash_info
        # Prefer image_base from the decoder (computed from -->PC/-->RIP
        # line which has both absolute address and module offset)
        if ci.image_base:
            return ci.image_base
        # Fallback: derive from crash PC and first frame's ELF offset
        f0 = self.result.frames
        if ci.crash_pc and f0 and f0[0].address:
            return ci.crash_pc - f0[0].address
        return 0

    def as_analysis_context(self) -> AnalysisContext:
        """Create a live view of this session as an AnalysisContext.

        The returned context shares references to the session's
        result/source/extras/backends, so mutations flow both ways.
        Used by /api/backend to call service.reinit_backend on an
        existing session.
        """
        from .service import AnalysisContext
        return AnalysisContext(
            result=self.result,
            source=self.source,
            extras=self.extra_sources,
            rsod_text=self.rsod_text,
            temp_dir=self.temp_dir,
            elf_path=self.elf_path,
            pe_path=self.pe_path,
            pdb_path=self.pdb_path,
            backend=self.backend,
            lldb_backend=self.lldb_dwarf,
            gdb_backend=self.gdb_dwarf,
        )

    @classmethod
    def from_analysis_context(
        cls, ctx: AnalysisContext, session_id: str,
        created_at: str = '',
    ) -> Session:
        """Wrap a service.AnalysisContext in a web Session.

        Used by the Flask upload handler and CLI pre-load path to
        adapt the shared analysis pipeline's output to the web UI's
        session store. The context's backends become the session's
        lldb_dwarf / gdb_dwarf fields verbatim.
        """
        return cls(
            id=session_id,
            result=ctx.result,
            source=ctx.source,
            extra_sources=ctx.extras,
            rsod_text=ctx.rsod_text,
            created_at=created_at,
            temp_dir=ctx.temp_dir,
            elf_path=ctx.elf_path,
            pe_path=ctx.pe_path,
            pdb_path=ctx.pdb_path,
            gdb_dwarf=ctx.gdb_backend,
            lldb_dwarf=ctx.lldb_backend,
            backend=ctx.backend,
        )


# Global session store (Phase 1: in-memory)
_sessions: dict[str, Session] = {}

MAX_SESSIONS = 50


def register_session(session: Session) -> None:
    """Register a pre-built session (used by rsod-debug.py for CLI sessions)."""
    _sessions[session.id] = session


def gdb_available() -> bool:
    """Check if GDB and pygdbmi are available for backend switching."""
    try:
        if not find_gdb():
            return False
        import pygdbmi  # noqa: F401
        return True
    except ImportError:
        return False


def lldb_available() -> bool:
    """Check if the system-installed lldb Python module is importable."""
    return import_lldb() is not None


def get_session(session_id: str) -> Session | None:
    """Look up a session by ID, returning None if not found."""
    return _sessions.get(session_id)


def pop_session(session_id: str) -> Session | None:
    """Remove and return a session by ID, returning None if not found."""
    return _sessions.pop(session_id, None)


def store_session(session: Session) -> None:
    """Store a session, evicting the oldest if at capacity."""
    if len(_sessions) >= MAX_SESSIONS:
        oldest_id = next(iter(_sessions))
        cleanup_session(_sessions.pop(oldest_id))
    _sessions[session.id] = session


def cleanup_session(session: Session) -> None:
    """Close file handles, kill GDB, and remove temp files for a session."""
    if session.gdb:
        session.gdb.close()
        session.gdb = None
    if session.gdb_dwarf is not None:
        close = getattr(session.gdb_dwarf, 'close', None)
        if callable(close):
            try:
                close()
            except Exception:
                pass
        session.gdb_dwarf = None
    if session.lldb_dwarf is not None:
        close = getattr(session.lldb_dwarf, 'close', None)
        if callable(close):
            try:
                close()
            except Exception:
                pass
        session.lldb_dwarf = None
    if session.source.binary:
        session.source.binary.close()
    for src in session.extra_sources.values():
        if src.binary:
            src.binary.close()
    if session.temp_dir and session.temp_dir.exists():
        shutil.rmtree(session.temp_dir, ignore_errors=True)
