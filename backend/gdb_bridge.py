"""GDB subprocess management via PTY for WebSocket terminal bridging.

Launches GDB with an ELF binary + core file in a pseudo-terminal,
providing read/write access for a web-based terminal emulator.
"""
from __future__ import annotations

import fcntl
import os
import pty
import select
import shutil
import signal
import struct
import subprocess
import termios
from pathlib import Path


def find_gdb() -> str | None:
    """Find a suitable GDB binary."""
    for name in ('gdb-multiarch', 'gdb'):
        path = shutil.which(name)
        if path:
            return path
    return None


class GdbSession:
    """Manages a GDB subprocess connected via PTY."""

    def __init__(
        self, elf_path: Path, core_path: Path, image_base: int = 0,
    ) -> None:
        gdb = find_gdb()
        if not gdb:
            raise RuntimeError('GDB not found')

        # Create PTY pair
        self._master_fd, slave_fd = pty.openpty()

        # Set master to non-blocking
        flags = fcntl.fcntl(self._master_fd, fcntl.F_GETFL)
        fcntl.fcntl(self._master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        # Launch GDB with the ELF + core
        # -q: quiet, -nx: no .gdbinit
        self._proc = subprocess.Popen(
            [gdb, '-q', '-nx', str(elf_path),
             '-ex', f'target core {core_path}',
             '-ex', f'add-symbol-file {elf_path} -o 0x{image_base:X}'],
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            preexec_fn=os.setsid,
        )
        os.close(slave_fd)

    @property
    def alive(self) -> bool:
        return self._proc.poll() is None

    def read(self, timeout: float = 0.1) -> bytes:
        """Read available output from GDB (non-blocking)."""
        readable, _, _ = select.select([self._master_fd], [], [], timeout)
        if not readable:
            return b''
        try:
            return os.read(self._master_fd, 4096)
        except OSError:
            return b''

    def write(self, data: bytes) -> None:
        """Send input to GDB stdin."""
        os.write(self._master_fd, data)

    def send_command(self, cmd: str) -> None:
        """Send a GDB command string (appends newline)."""
        self.write((cmd + '\n').encode())

    def resize(self, rows: int, cols: int) -> None:
        """Update PTY window size (for terminal resize events)."""
        winsize = struct.pack('HHHH', rows, cols, 0, 0)
        fcntl.ioctl(self._master_fd, termios.TIOCSWINSZ, winsize)

    def close(self) -> None:
        """Kill GDB and clean up."""
        if self._proc.poll() is None:
            try:
                os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            self._proc.wait(timeout=3)
        try:
            os.close(self._master_fd)
        except OSError:
            pass
