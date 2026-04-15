"""Unit tests for the SQLite storage layer."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from rsod_decode import data_dir as _data_dir
from rsod_decode import storage


@pytest.fixture()
def isolated_data_dir(tmp_path, monkeypatch) -> Path:
    """Point `RSOD_DATA_DIR` at a throwaway per-test directory."""
    target = tmp_path / 'rsod-data'
    monkeypatch.setenv('RSOD_DATA_DIR', str(target))
    storage.init_db()
    yield target
    # Tempdir cleanup handled by pytest; nothing to do here.


def _fake_file(path: Path, content: bytes = b'stub') -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def test_init_db_idempotent(isolated_data_dir: Path) -> None:
    storage.init_db()
    storage.init_db()
    assert _data_dir.sessions_db().exists()


def test_save_list_hydrate_delete(isolated_data_dir: Path) -> None:
    session_id = 'abc123def456'
    files_dir = _data_dir.session_files_dir_for(session_id)
    _fake_file(files_dir / 'psa_x64.efi', b'\x7fELF fake')
    _fake_file(files_dir / 'psa_x64.pdb', b'pdb fake')

    storage.save_session(
        session_id=session_id,
        created_at='2026-04-15T10:00:00+00:00',
        rsod_text='RSOD stub body',
        rsod_format='uefi_x86',
        image_name='psa_x64',
        image_base=0x140000000,
        exception_desc='General Protection Fault (13)',
        crash_pc=0x140012345,
        crash_symbol='trigger_gp_fault',
        frame_count=7,
        backend='lldb',
        base_override=None,
        dwarf_prefix=None,
        files=[
            storage.FileEntry(
                filename='psa_x64.efi', file_type='primary',
                rel_path='psa_x64.efi'),
            storage.FileEntry(
                filename='psa_x64.pdb', file_type='pdb',
                rel_path='psa_x64.pdb'),
        ],
    )

    rows = storage.list_sessions()
    assert len(rows) == 1
    row = rows[0]
    assert row.id == session_id
    assert row.image_name == 'psa_x64'
    assert row.exception_desc.startswith('General Protection Fault')
    assert row.crash_pc == 0x140012345
    assert row.crash_symbol == 'trigger_gp_fault'
    assert row.frame_count == 7
    assert row.backend == 'lldb'

    assert storage.session_exists(session_id) is True

    hydrated = storage.hydrate_inputs(session_id)
    assert hydrated is not None
    assert hydrated.id == session_id
    assert hydrated.rsod_text == 'RSOD stub body'
    assert hydrated.primary_path == files_dir / 'psa_x64.efi'
    assert hydrated.pdb_path == files_dir / 'psa_x64.pdb'
    assert hydrated.companion_path is None
    assert hydrated.extra_paths == []

    assert storage.delete_session(session_id) is True
    assert storage.session_exists(session_id) is False
    assert storage.list_sessions() == []
    assert not files_dir.exists()
    # Delete on a missing row reports False.
    assert storage.delete_session(session_id) is False


def test_hydrate_missing_primary_raises(isolated_data_dir: Path) -> None:
    session_id = 'deadbeef1111'
    files_dir = _data_dir.session_files_dir_for(session_id)
    _fake_file(files_dir / 'primary.efi')
    storage.save_session(
        session_id=session_id,
        created_at='2026-04-15T11:00:00+00:00',
        rsod_text='body',
        rsod_format='uefi_x86',
        image_name='x',
        image_base=0,
        exception_desc='',
        crash_pc=0,
        crash_symbol='',
        frame_count=0,
        backend='pyelftools',
        base_override=None,
        dwarf_prefix=None,
        files=[storage.FileEntry(
            filename='primary.efi', file_type='primary', rel_path='primary.efi')],
    )
    # Out-of-band removal of the symbol file.
    shutil.rmtree(files_dir)
    with pytest.raises(FileNotFoundError):
        storage.hydrate_inputs(session_id)


def test_list_sessions_newest_first(isolated_data_dir: Path) -> None:
    for i, ts in enumerate([
        '2026-04-15T10:00:00+00:00',
        '2026-04-15T11:00:00+00:00',
        '2026-04-15T12:00:00+00:00',
    ]):
        sid = f'session{i:05d}abc'
        files_dir = _data_dir.session_files_dir_for(sid)
        _fake_file(files_dir / 'p.efi')
        storage.save_session(
            session_id=sid, created_at=ts, rsod_text=f'body {i}',
            rsod_format='uefi_x86', image_name=f'img{i}',
            image_base=0, exception_desc='', crash_pc=None,
            crash_symbol='', frame_count=0, backend='pyelftools',
            base_override=None, dwarf_prefix=None,
            files=[storage.FileEntry(
                filename='p.efi', file_type='primary', rel_path='p.efi')],
        )
    rows = storage.list_sessions()
    assert [r.image_name for r in rows] == ['img2', 'img1', 'img0']

    rows = storage.list_sessions(limit=2)
    assert len(rows) == 2

    rows = storage.list_sessions(before='2026-04-15T11:30:00+00:00')
    assert [r.image_name for r in rows] == ['img1', 'img0']
