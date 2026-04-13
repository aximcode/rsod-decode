"""Phase 1 smoke tests for the LLDB foundation.

Verifies that (a) the lldb Python module can be imported via the shim and
(b) a synthetic corefile written by `write_corefile()` loads cleanly in
LLDB. Neither test wires LLDB into the decoder yet — that comes in Phase 2.
Both tests are marked `lldb` and skip cleanly when the module is missing.
"""
from __future__ import annotations

from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from rsod_decode.corefile import write_corefile
from rsod_decode.lldb_loader import import_lldb

from ._datasets import DatasetRun

pytestmark = pytest.mark.lldb


def _lldb_or_skip() -> ModuleType:
    lldb = import_lldb()
    if lldb is None:
        pytest.skip("lldb Python module not available")
    return lldb


def test_import_lldb_shim() -> None:
    lldb = _lldb_or_skip()
    version = lldb.SBDebugger.GetVersionString()
    assert isinstance(version, str) and version, (
        "SBDebugger.GetVersionString() should return a non-empty string")


def test_corefile_loads_in_lldb(
    load_dataset_run: Any, tmp_path: Path,
) -> None:
    lldb = _lldb_or_skip()
    run: DatasetRun = load_dataset_run("dell_aa64")
    result = run.result
    crash = result.crash_info

    core_path = tmp_path / "dell_aa64.core"
    frame_data = [(f.frame_fp, f.address) for f in result.frames]
    write_corefile(
        registers=crash.registers,
        crash_pc=crash.crash_pc,
        stack_base=result.stack_base,
        stack_mem=result.stack_mem,
        elf_path=run.spec.symbol_path,
        out_path=core_path,
        image_base=crash.image_base,
        frames=frame_data,
    )
    assert core_path.exists() and core_path.stat().st_size > 0

    dbg = lldb.SBDebugger.Create()
    try:
        dbg.SetAsync(False)
        target = dbg.CreateTarget(str(run.spec.symbol_path))
        assert target.IsValid(), "CreateTarget failed for dell_aa64 ELF"
        err = lldb.SBError()
        process = target.LoadCore(str(core_path), err)
        assert err.Success(), f"LoadCore failed: {err.GetCString()}"
        assert process.IsValid(), "LoadCore returned an invalid process"
        assert process.GetNumThreads() >= 1, (
            "expected at least one thread in the loaded core")
        thread = process.GetThreadAtIndex(0)
        assert thread.GetNumFrames() >= 1, (
            "expected at least one frame on the crash thread")
    finally:
        lldb.SBDebugger.Destroy(dbg)
