"""SQLite-backed session storage.

Schema v1: stores *inputs* (rsod text + symbol file paths) for each
session, not derived analysis results. On hydrate the caller re-runs
`service.run_analysis` against the same inputs — deterministic, no
serialized result format to version.

File layout under `~/.rsod-debug/`:

    sessions.db
    files/<session_id>/
        rsod.txt              (copy of the upload — rsod_text also
                               lives in the DB for fast history reads)
        <primary symbol file>
        <companion>           (map or pe, if any)
        <pdb>                 (if any)
        <extra symbol files>  (flat; session_files row per file)
"""
from __future__ import annotations

import contextlib
import hashlib
import shutil
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from . import data_dir as _data_dir


CURRENT_SCHEMA_VERSION = 2

# Length of the content-hash prefix used as the session id. 16 hex
# chars = 64 bits; collision probability is ignorable at any realistic
# team scale (a 10K-session team is ~1e-11 collision chance).
SESSION_ID_LEN = 16


# =============================================================================
# Row / input dataclasses
# =============================================================================

@dataclass
class HistoryRow:
    """Shape returned by `list_sessions` for history UI rendering."""
    id: str
    created_at: str
    image_name: str
    exception_desc: str
    crash_pc: int | None
    crash_symbol: str
    frame_count: int
    backend: str
    imported_from: str | None = None


@dataclass
class FileEntry:
    """One file on disk backing a persisted session."""
    filename: str        # original basename for display / form field routing
    file_type: str       # 'primary' | 'companion' | 'pdb' | 'extra'
    rel_path: str        # relative to session_files_dir_for(id)


@dataclass
class HydratedInputs:
    """Everything the caller needs to re-run service.run_analysis."""
    id: str
    created_at: str
    rsod_text: str
    primary_path: Path
    companion_path: Path | None
    pdb_path: Path | None
    extra_paths: list[Path]
    base_override: int | None
    dwarf_prefix: str | None
    imported_from: str | None = None


# =============================================================================
# Content-hash session ids
# =============================================================================

def compute_session_id(files_dir: Path) -> str:
    """Return the stable session id derived from a directory of inputs.

    Hashes every regular file under `files_dir` sorted by basename —
    rsod.txt plus whatever symbol files the caller staged. Including
    the basename in the hash means renaming the primary .efi to
    something else produces a different id (which is correct: the
    symbol file's name flows into the pair/pdb classifier).

    The first `SESSION_ID_LEN` hex chars of sha256 are the id; same
    inputs on any install produce the same id, which is what makes
    cross-team permalinks work.
    """
    h = hashlib.sha256()
    for item in sorted(files_dir.iterdir(), key=lambda p: p.name):
        if not item.is_file():
            continue
        h.update(item.name.encode('utf-8'))
        h.update(b'\0')
        with item.open('rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                h.update(chunk)
        h.update(b'\0')
    return h.hexdigest()[:SESSION_ID_LEN]


# =============================================================================
# Connection / schema
# =============================================================================

@contextlib.contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    """Open a short-lived connection with FK + auto-commit/rollback.

    `with conn:` handles commit on clean exit or rollback on exception;
    the outer `try/finally` ensures the handle is closed so repeated
    calls don't leak file descriptors.
    """
    conn = sqlite3.connect(str(_data_dir.sessions_db()))
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db() -> None:
    """Create tables + run migrations. Idempotent; call on startup."""
    with _connect() as conn:
        version = conn.execute('PRAGMA user_version').fetchone()[0]
        if version == 0:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id              TEXT PRIMARY KEY,
                    created_at      TEXT NOT NULL,
                    rsod_format     TEXT,
                    image_name      TEXT,
                    image_base      INTEGER,
                    exception_desc  TEXT,
                    crash_pc        INTEGER,
                    crash_symbol    TEXT,
                    frame_count     INTEGER,
                    backend         TEXT,
                    rsod_text       TEXT NOT NULL,
                    base_override   INTEGER,
                    dwarf_prefix    TEXT
                ) WITHOUT ROWID;
                CREATE INDEX IF NOT EXISTS idx_sessions_created_at
                    ON sessions(created_at DESC);
                CREATE TABLE IF NOT EXISTS session_files (
                    session_id  TEXT NOT NULL
                        REFERENCES sessions(id) ON DELETE CASCADE,
                    filename    TEXT NOT NULL,
                    file_type   TEXT NOT NULL,
                    rel_path    TEXT NOT NULL,
                    PRIMARY KEY (session_id, rel_path)
                );
            """)
            version = 1
        if version < 2:
            # Schema v2: track cross-install import provenance so Bob
            # can see whose crash he imported from Alice.
            conn.execute('ALTER TABLE sessions ADD COLUMN imported_from TEXT')
            version = 2
        conn.execute(f'PRAGMA user_version = {CURRENT_SCHEMA_VERSION}')


# =============================================================================
# Write path
# =============================================================================

def save_session(
    *,
    session_id: str,
    created_at: str,
    rsod_text: str,
    rsod_format: str,
    image_name: str,
    image_base: int,
    exception_desc: str,
    crash_pc: int | None,
    crash_symbol: str,
    frame_count: int,
    backend: str,
    base_override: int | None,
    dwarf_prefix: str | None,
    files: list[FileEntry],
    imported_from: str | None = None,
) -> None:
    """Insert one session row + its file metadata.

    The caller is responsible for having already copied the actual
    files into `session_files_dir_for(session_id) / rel_path`. On
    failure the caller must roll back that directory.
    """
    with _connect() as conn:
        # INSERT OR IGNORE makes save_session idempotent: a row that
        # already exists (because the caller raced another upload of
        # the same content, or failed to take the dedup fast path
        # before us) silently wins and this call is a no-op. Same
        # treatment for session_files since its PK is (session_id,
        # rel_path) — identical content → identical rows → ignored.
        conn.execute(
            """
            INSERT OR IGNORE INTO sessions (
                id, created_at, rsod_format, image_name, image_base,
                exception_desc, crash_pc, crash_symbol, frame_count,
                backend, rsod_text, base_override, dwarf_prefix,
                imported_from
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (session_id, created_at, rsod_format, image_name, image_base,
             exception_desc, crash_pc, crash_symbol, frame_count,
             backend, rsod_text, base_override, dwarf_prefix, imported_from),
        )
        conn.executemany(
            """
            INSERT OR IGNORE INTO session_files
                (session_id, filename, file_type, rel_path)
            VALUES (?, ?, ?, ?)
            """,
            [(session_id, f.filename, f.file_type, f.rel_path) for f in files],
        )


# =============================================================================
# Read path
# =============================================================================

def list_sessions(
    limit: int = 100, before: str | None = None,
) -> list[HistoryRow]:
    """Return recent sessions ordered newest-first."""
    with _connect() as conn:
        if before:
            cur = conn.execute(
                """
                SELECT id, created_at, image_name, exception_desc,
                       crash_pc, crash_symbol, frame_count, backend,
                       imported_from
                FROM sessions
                WHERE created_at < ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (before, limit),
            )
        else:
            cur = conn.execute(
                """
                SELECT id, created_at, image_name, exception_desc,
                       crash_pc, crash_symbol, frame_count, backend,
                       imported_from
                FROM sessions
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            )
        return [
            HistoryRow(
                id=row['id'],
                created_at=row['created_at'],
                image_name=row['image_name'] or '',
                exception_desc=row['exception_desc'] or '',
                crash_pc=row['crash_pc'],
                crash_symbol=row['crash_symbol'] or '',
                frame_count=row['frame_count'] or 0,
                backend=row['backend'] or 'pyelftools',
                imported_from=row['imported_from'],
            )
            for row in cur.fetchall()
        ]


def session_exists(session_id: str) -> bool:
    with _connect() as conn:
        row = conn.execute(
            'SELECT 1 FROM sessions WHERE id = ?', (session_id,),
        ).fetchone()
    return row is not None


def hydrate_inputs(session_id: str) -> HydratedInputs | None:
    """Load everything needed to re-run `service.run_analysis`.

    Returns None if no row exists. Raises `FileNotFoundError` if the
    row is present but the on-disk primary file has vanished.
    """
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT id, created_at, rsod_text, base_override, dwarf_prefix,
                   imported_from
            FROM sessions WHERE id = ?
            """,
            (session_id,),
        ).fetchone()
        if row is None:
            return None
        file_rows = conn.execute(
            """
            SELECT filename, file_type, rel_path FROM session_files
            WHERE session_id = ?
            """,
            (session_id,),
        ).fetchall()

    base = _data_dir.session_files_dir_for(session_id)
    primary: Path | None = None
    companion: Path | None = None
    pdb: Path | None = None
    extras: list[Path] = []
    for fr in file_rows:
        abs_path = base / fr['rel_path']
        if fr['file_type'] == 'primary':
            primary = abs_path
        elif fr['file_type'] == 'companion':
            companion = abs_path
        elif fr['file_type'] == 'pdb':
            pdb = abs_path
        else:
            extras.append(abs_path)

    if primary is None or not primary.exists():
        raise FileNotFoundError(
            f'session {session_id} missing primary symbol file on disk')

    return HydratedInputs(
        id=row['id'],
        created_at=row['created_at'],
        rsod_text=row['rsod_text'],
        primary_path=primary,
        companion_path=companion,
        pdb_path=pdb,
        extra_paths=extras,
        base_override=row['base_override'],
        dwarf_prefix=row['dwarf_prefix'],
        imported_from=row['imported_from'],
    )


# =============================================================================
# Delete path
# =============================================================================

def delete_session(session_id: str) -> bool:
    """Drop DB row + `files/<session_id>/` directory.

    Returns True if a row was actually deleted.
    """
    with _connect() as conn:
        cur = conn.execute(
            'DELETE FROM sessions WHERE id = ?', (session_id,),
        )
        deleted = cur.rowcount > 0
    files_dir = _data_dir.session_files_dir_for(session_id)
    if files_dir.exists():
        shutil.rmtree(files_dir, ignore_errors=True)
    return deleted
