from __future__ import annotations

import pytest

from tests.conftest import DatasetRun


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
