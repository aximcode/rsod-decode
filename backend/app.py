"""Flask API for the RSOD debugger web UI.

Phase 1: In-memory session storage, file uploads to temp dir.
"""
from __future__ import annotations

import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request
from werkzeug.utils import secure_filename

from .models import CrashInfo, FrameInfo, SymbolSource, VarInfo, clean_path, find_source_file
from .decoder import AnalysisResult, analyze_rsod
from .dwarf_info import DwarfInfo
from .symbols import SymbolLoadError, load_symbols


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


# Global session store (Phase 1: in-memory)
_sessions: dict[str, Session] = {}

MAX_SESSIONS = 50


# =============================================================================
# Serialization helpers
# =============================================================================

def _crash_info_to_dict(info: CrashInfo) -> dict:
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


def _frame_to_dict(f: FrameInfo) -> dict:
    return {
        'index': f.index,
        'address': f.address,
        'module': f.module,
        'symbol': f.symbol.name if f.symbol else None,
        'sym_offset': f.sym_offset,
        'source_loc': f.source_loc,
        'inlines': [{'function': func, 'source_loc': loc}
                     for func, loc in f.inlines],
    }


def _var_to_dict(v: VarInfo, registers: dict[str, int]) -> dict:
    value = None
    if v.reg_name and v.reg_name in registers:
        value = registers[v.reg_name]
    return {
        'name': v.name,
        'type': v.type_name,
        'location': v.location,
        'reg_name': v.reg_name,
        'value': value,
    }


def _registers_to_dict(regs: dict[str, int]) -> dict:
    return {k: f'0x{v:X}' for k, v in regs.items()}


# =============================================================================
# Multi-module DWARF lookup helper
# =============================================================================

def _get_dwarf_for_frame(
    frame: FrameInfo,
    source: SymbolSource,
    extra_sources: dict[str, SymbolSource],
) -> DwarfInfo | None:
    """Get the correct DwarfInfo for a frame's module."""
    if frame.module:
        mod_key = frame.module.replace('.efi', '').lower()
        extra = extra_sources.get(mod_key)
        if extra and extra.dwarf:
            return extra.dwarf
    return source.dwarf


# =============================================================================
# Flask app factory
# =============================================================================

def create_app(repo_root: Path | None = None,
               dwarf_prefix: str | None = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB
    app.config['REPO_ROOT'] = repo_root
    app.config['DWARF_PREFIX'] = dwarf_prefix

    # -----------------------------------------------------------------
    # POST /api/session — upload RSOD + symbols, create session
    # -----------------------------------------------------------------
    @app.post('/api/session')
    def create_session():
        if 'rsod_log' not in request.files:
            return jsonify(error='rsod_log file required'), 400
        if 'symbol_file' not in request.files:
            return jsonify(error='symbol_file required'), 400

        # Evict oldest session if at capacity
        if len(_sessions) >= MAX_SESSIONS:
            oldest_id = next(iter(_sessions))
            _cleanup_session(_sessions.pop(oldest_id))

        rsod_file = request.files['rsod_log']
        sym_file = request.files['symbol_file']

        # Save uploads to temp dir with sanitized filenames
        temp_dir = Path(tempfile.mkdtemp(prefix='rsod-'))
        rsod_path = temp_dir / secure_filename(rsod_file.filename or 'rsod.txt')
        sym_path = temp_dir / secure_filename(sym_file.filename or 'symbols')
        rsod_file.save(str(rsod_path))
        sym_file.save(str(sym_path))

        # Save extra symbol files
        extra_paths: list[Path] = []
        for f in request.files.getlist('extra_symbols[]'):
            p = temp_dir / secure_filename(f.filename or 'extra')
            f.save(str(p))
            extra_paths.append(p)

        # Load symbols
        try:
            source = load_symbols(sym_path,
                                  dwarf_prefix=app.config['DWARF_PREFIX'],
                                  repo_root=app.config['REPO_ROOT'])
        except SymbolLoadError as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return jsonify(error=str(e)), 400

        extra_sources: dict[str, SymbolSource] = {}
        for p in extra_paths:
            try:
                s = load_symbols(p,
                                 dwarf_prefix=app.config['DWARF_PREFIX'],
                                 repo_root=app.config['REPO_ROOT'])
            except SymbolLoadError as e:
                shutil.rmtree(temp_dir, ignore_errors=True)
                return jsonify(error=str(e)), 400
            extra_sources[p.stem.lower()] = s

        # Read RSOD text
        rsod_text = rsod_path.read_text(encoding='utf-8', errors='replace')

        # Base override from form data
        base_override = None
        base_str = request.form.get('base')
        if base_str:
            try:
                base_override = int(base_str, 16)
            except ValueError:
                shutil.rmtree(temp_dir, ignore_errors=True)
                return jsonify(error=f'invalid base address: {base_str}'), 400

        # Analyze using the shared core
        analysis = analyze_rsod(rsod_text, source, extra_sources, base_override)

        # Store session
        session_id = uuid.uuid4().hex[:12]
        session = Session(
            id=session_id,
            result=analysis,
            source=source,
            extra_sources=extra_sources,
            rsod_text=rsod_text,
            created_at=datetime.now(timezone.utc).isoformat(),
            temp_dir=temp_dir,
        )
        _sessions[session_id] = session

        return jsonify(
            session_id=session_id,
            crash_summary=_crash_info_to_dict(analysis.crash_info),
            frame_count=len(analysis.frames),
        ), 201

    # -----------------------------------------------------------------
    # GET /api/session/<id> — get crash summary + frames + registers
    # -----------------------------------------------------------------
    @app.get('/api/session/<session_id>')
    def get_session(session_id: str):
        session = _sessions.get(session_id)
        if not session:
            return jsonify(error='session not found'), 404
        r = session.result
        return jsonify(
            crash_summary=_crash_info_to_dict(r.crash_info),
            frames=[_frame_to_dict(f) for f in r.frames],
            registers=_registers_to_dict(r.crash_info.registers),
            format=r.rsod_format,
            call_verified={str(k): v for k, v in r.call_verified.items()},
            rsod_text=session.rsod_text,
        )

    # -----------------------------------------------------------------
    # GET /api/frame/<session_id>/<frame_index> — params + locals
    # -----------------------------------------------------------------
    @app.get('/api/frame/<session_id>/<int:frame_index>')
    def get_frame(session_id: str, frame_index: int):
        session = _sessions.get(session_id)
        if not session:
            return jsonify(error='session not found'), 404
        if frame_index < 0 or frame_index >= len(session.result.frames):
            return jsonify(error='frame index out of range'), 404

        frame = session.result.frames[frame_index]
        result: dict = _frame_to_dict(frame)

        # Use the correct DWARF source for this frame's module
        dwarf = _get_dwarf_for_frame(
            frame, session.source, session.extra_sources)
        if dwarf and frame.address:
            params = dwarf.get_params(frame.address)
            locals_ = dwarf.get_locals(frame.address)
            result['params'] = [_var_to_dict(v, session.result.crash_info.registers)
                                for v in params]
            result['locals'] = [_var_to_dict(v, session.result.crash_info.registers)
                                for v in locals_]
        else:
            result['params'] = []
            result['locals'] = []

        result['call_verified'] = session.result.call_verified.get(frame.address)
        return jsonify(result)

    # -----------------------------------------------------------------
    # GET /api/disasm/<session_id>/<frame_index> — disassembly
    # -----------------------------------------------------------------
    @app.get('/api/disasm/<session_id>/<int:frame_index>')
    def get_disasm(session_id: str, frame_index: int):
        session = _sessions.get(session_id)
        if not session:
            return jsonify(error='session not found'), 404
        if frame_index < 0 or frame_index >= len(session.result.frames):
            return jsonify(error='frame index out of range'), 404

        frame = session.result.frames[frame_index]
        dwarf = _get_dwarf_for_frame(
            frame, session.source, session.extra_sources)
        if not dwarf or not frame.address:
            return jsonify(instructions=[])

        context = min(request.args.get('context', 24, type=int), 200)
        insns = dwarf.disassemble_around(frame.address, context)
        src_map = dwarf.source_lines_for_addrs([a for a, _, _ in insns])

        instructions = []
        for addr, mnemonic, op_str in insns:
            instructions.append({
                'address': addr,
                'mnemonic': mnemonic,
                'op_str': op_str,
                'is_target': addr == frame.address,
                'source_line': src_map.get(addr, ''),
            })
        return jsonify(instructions=instructions)

    # -----------------------------------------------------------------
    # GET /api/source/<session_id>/<frame_index> — source context
    # -----------------------------------------------------------------
    @app.get('/api/source/<session_id>/<int:frame_index>')
    def get_source(session_id: str, frame_index: int):
        session = _sessions.get(session_id)
        if not session:
            return jsonify(error='session not found'), 404
        if frame_index < 0 or frame_index >= len(session.result.frames):
            return jsonify(error='frame index out of range'), 404

        frame = session.result.frames[frame_index]
        if not frame.source_loc or ':' not in frame.source_loc:
            return jsonify(file='', target_line=0, lines=[])

        file_part, line_part = frame.source_loc.rsplit(':', 1)
        try:
            target_line = int(line_part)
        except ValueError:
            return jsonify(file='', target_line=0, lines=[])

        context = min(request.args.get('context', 5, type=int), 50)

        # Direct path lookup, with case-insensitive fallback
        root = app.config['REPO_ROOT'] or Path(__file__).resolve().parents[4]
        src_path = find_source_file(root, file_part, target_line)
        if not src_path:
            return jsonify(file=file_part, target_line=target_line, lines=[])
        file_part = str(src_path.relative_to(root))

        try:
            all_lines = src_path.read_text(
                encoding='utf-8', errors='replace').splitlines()
        except OSError:
            return jsonify(file=file_part, target_line=target_line, lines=[])

        start = max(0, target_line - context - 1)
        end = min(len(all_lines), target_line + context)

        result_lines = []
        for i in range(start, end):
            lineno = i + 1
            result_lines.append({
                'number': lineno,
                'text': all_lines[i],
                'is_target': lineno == target_line,
            })
        return jsonify(
            file=file_part,
            target_line=target_line,
            lines=result_lines,
        )

    # -----------------------------------------------------------------
    # POST /api/resolve/<session_id> — resolve arbitrary address
    # -----------------------------------------------------------------
    @app.post('/api/resolve/<session_id>')
    def resolve_address(session_id: str):
        session = _sessions.get(session_id)
        if not session:
            return jsonify(error='session not found'), 404

        data = request.get_json(silent=True) or {}
        addr_str = data.get('address', '')
        try:
            addr = int(addr_str, 16) if isinstance(addr_str, str) else int(addr_str)
        except (ValueError, TypeError):
            return jsonify(error=f'invalid address: {addr_str}'), 400

        table = session.source.table
        result = table.lookup(addr)
        if not result:
            return jsonify(error='address not in image'), 404

        sym, offset = result
        response: dict = {
            'symbol': sym.name,
            'offset': offset,
            'object_file': sym.object_file,
            'is_function': sym.is_function,
        }

        # DWARF source location if available
        dwarf = session.source.dwarf
        if dwarf:
            addr_info = dwarf.resolve_address(addr)
            if addr_info:
                response['source_loc'] = clean_path(addr_info.source_loc) if addr_info.source_loc else ''
                response['function'] = addr_info.function

        return jsonify(response)

    # -----------------------------------------------------------------
    # DELETE /api/session/<id> — cleanup
    # -----------------------------------------------------------------
    @app.delete('/api/session/<session_id>')
    def delete_session(session_id: str):
        session = _sessions.pop(session_id, None)
        if not session:
            return jsonify(error='session not found'), 404
        _cleanup_session(session)
        return jsonify(deleted=True)

    return app


def _cleanup_session(session: Session) -> None:
    """Close file handles and remove temp files for a session."""
    if session.source.dwarf:
        session.source.dwarf.close()
    for src in session.extra_sources.values():
        if src.dwarf:
            src.dwarf.close()
    if session.temp_dir and session.temp_dir.exists():
        shutil.rmtree(session.temp_dir, ignore_errors=True)



# =============================================================================
# Standalone server
# =============================================================================

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)
