from __future__ import annotations

import pytest

from ._datasets import DatasetRun


pytestmark = [pytest.mark.parser]


def test_parser_expected_metrics(dataset_run: DatasetRun) -> None:
    spec = dataset_run.spec
    result = dataset_run.result

    assert result.rsod_format == spec.expected_format
    assert len(result.frames) == spec.expected_frames
    assert result.resolved_count == spec.expected_resolved
    assert len(result.modules) == spec.expected_modules
    assert len(result.crash_info.v_registers) == spec.expected_vregs
    assert len(result.stack_mem) == spec.expected_stack_size
    assert len(result.crash_info.lbr) == spec.expected_lbr


def test_parser_frame_zero_shape(dataset_run: DatasetRun) -> None:
    if not dataset_run.result.frames:
        pytest.skip("fixture has no frames (RSOD lacks a stack trace)")
    frame0 = dataset_run.result.frames[0]

    assert frame0.index == 0
    assert frame0.is_crash_frame is True
    assert frame0.address > 0
    assert frame0.module


def test_dell_aa64_image_base_regression(load_dataset_run) -> None:
    run = load_dataset_run("dell_aa64")
    assert run.result.crash_info.image_base == 0x782B122000


def test_stack_and_sp_preconditions(dataset_run: DatasetRun) -> None:
    result = dataset_run.result

    assert result.stack_base > 0
    assert len(result.stack_mem) > 0

    regs = result.crash_info.registers
    assert "SP" in regs or "RSP" in regs


def test_psa_x64_pe_backend_ready(load_dataset_run) -> None:
    """The MSVC/EPSA psa_x64 fixture should load via PEBinary + .map and
    expose a working disassembler + call-site checker, regardless of
    whether the decoder managed to extract frames from the RSOD text."""
    from rsod_decode.pe_backend import PEBinary

    run = load_dataset_run("psa_x64")
    binary = run.source.binary
    assert isinstance(binary, PEBinary)
    assert binary.arch == "x86_64"
    assert binary.image_base == 0x180000000
    assert len(run.source.table.symbols) > 10000
    assert run.source.table.preferred_base == 0x180000000

    # fGndBounce lives at 0x180001600; the crash RIP (runtime 0x01001696
    # = preferred-base 0x180001696) is inside it. Disassembling around
    # that address should return real instructions.
    insns = binary.disassemble_around(0x180001696, context=16)
    assert len(insns) > 0
    assert all(m for _, m, _ in insns)

    # A return address that follows a `call` in the .text should verify.
    # 0x180031ba1 is taken from the stack dump and is known to satisfy
    # is_call_before() for this build.
    assert binary.is_call_before(0x180031BA1) is True
