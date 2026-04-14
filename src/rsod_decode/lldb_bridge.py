"""In-process LLDB command interpreter for the browser terminal.

Replaces the PTY-driven GDB bridge with a much simpler in-process wrapper
around SBCommandInterpreter. Shares an SBDebugger with the session's
LldbBackend when one is present so commands like `frame select 1` and
`register read` see the loaded target state.

Implements a minimal line editor on top of raw xterm keystrokes: tracks
a per-connection command buffer, echoes printable input, handles
backspace and Ctrl-C, and runs the buffered command on Enter. No arrow-
key history, no tab completion — users who want a full REPL can run
`lldb` in a real terminal.
"""
from __future__ import annotations

from typing import Any

from .lldb_loader import import_lldb


class LldbConsole:
    """Line-buffered LLDB command interpreter for WebSocket bridging."""

    PROMPT: bytes = b'(lldb) '

    def __init__(self, debugger: Any = None) -> None:
        lldb = import_lldb()
        if lldb is None:
            raise RuntimeError('lldb Python module not available')
        self._lldb = lldb
        self._owns_debugger = debugger is None
        if debugger is None:
            debugger = lldb.SBDebugger.Create()
            debugger.SetAsync(False)
        self._debugger = debugger
        self._ci = debugger.GetCommandInterpreter()
        self._buffer: str = ''

    def banner(self) -> bytes:
        """Initial welcome bytes to send on new terminal connection."""
        version = self._lldb.SBDebugger.GetVersionString() or 'lldb'
        first_line = version.splitlines()[0] if version else 'lldb'
        return f'{first_line}\r\n'.encode('utf-8') + self.PROMPT

    def handle_input(self, data: bytes) -> bytes:
        """Process a chunk of input from the browser terminal.

        Returns the bytes to echo back — user characters for printable
        input, `\\b \\b` for backspaces, command output plus a new
        prompt on Enter. Invalid UTF-8 is silently dropped.
        """
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError:
            return b''

        out = bytearray()
        for ch in text:
            if ch in ('\r', '\n'):
                out.extend(b'\r\n')
                cmd = self._buffer
                self._buffer = ''
                if cmd.strip():
                    out.extend(self._run_command(cmd))
                out.extend(self.PROMPT)
            elif ch in ('\x7f', '\b'):
                if self._buffer:
                    self._buffer = self._buffer[:-1]
                    out.extend(b'\b \b')
            elif ch == '\x03':
                # Ctrl-C: abort current line
                self._buffer = ''
                out.extend(b'^C\r\n')
                out.extend(self.PROMPT)
            elif ' ' <= ch < '\x7f':
                self._buffer += ch
                out.append(ord(ch))
            # Ignore everything else (escape sequences, tabs, etc.)
        return bytes(out)

    def _run_command(self, line: str) -> bytes:
        ro = self._lldb.SBCommandReturnObject()
        self._ci.HandleCommand(line, ro)
        chunks: list[str] = []
        if ro.GetOutput():
            chunks.append(ro.GetOutput())
        if ro.GetError():
            chunks.append(ro.GetError())
        body = ''.join(chunks)
        # Terminal needs CRLF line endings; LLDB emits LF.
        body = body.replace('\r\n', '\n').replace('\n', '\r\n')
        return body.encode('utf-8', errors='replace')

    def close(self) -> None:
        """Destroy the underlying debugger if we own it."""
        if self._owns_debugger:
            try:
                self._lldb.SBDebugger.Destroy(self._debugger)
            except Exception:
                pass
