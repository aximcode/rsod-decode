"""User data directory for persistent session storage.

Default `~/.rsod-debug/`; override via `RSOD_DATA_DIR=/path`. Looked
up on every call so tests can rebind it per-test.
"""
from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    """Return the data dir, creating it if missing."""
    override = os.environ.get('RSOD_DATA_DIR')
    path = Path(override) if override else Path.home() / '.rsod-debug'
    path.mkdir(parents=True, exist_ok=True)
    return path


def sessions_db() -> Path:
    """Return the path to sessions.db (parent dir guaranteed to exist)."""
    return data_dir() / 'sessions.db'


def session_files_dir() -> Path:
    """Return the base dir for per-session file storage."""
    path = data_dir() / 'files'
    path.mkdir(parents=True, exist_ok=True)
    return path


def session_files_dir_for(session_id: str) -> Path:
    """Return the per-session file dir (NOT created automatically)."""
    return session_files_dir() / session_id
