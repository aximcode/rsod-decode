from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from rsod_decode.decoder import AnalysisResult
from rsod_decode.models import SymbolSource


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = Path(__file__).parent / "fixtures"
SYMBOL_ROOT = Path(
    os.environ.get(
        "RSOD_TEST_SYMBOL_ROOT",
        Path.home() / "projects/aximcode/uefi-devkit/build/crashhandler",
    )
)


@dataclass(frozen=True)
class DatasetSpec:
    key: str
    rsod_file: str
    symbol_path: Path
    expected_format: str
    expected_frames: int
    expected_resolved: int
    expected_modules: int
    expected_vregs: int
    expected_stack_size: int
    expected_lbr: int
    expected_image_base: int | None = None


@dataclass
class DatasetRun:
    spec: DatasetSpec
    rsod_text: str
    source: SymbolSource
    result: AnalysisResult


DATASET_SPECS: dict[str, DatasetSpec] = {
    "edk2_aa64": DatasetSpec(
        key="edk2_aa64",
        rsod_file="rsod_qemu_devkit.txt",
        symbol_path=SYMBOL_ROOT / "aa64" / "CrashTest.so",
        expected_format="edk2_arm64",
        expected_frames=17,
        expected_resolved=9,
        expected_modules=5,
        expected_vregs=32,
        expected_stack_size=512,
        expected_lbr=0,
    ),
    "dell_aa64": DatasetSpec(
        key="dell_aa64",
        rsod_file="rsod_dell_aa64.txt",
        symbol_path=SYMBOL_ROOT / "aa64" / "CrashTest.so",
        expected_format="uefi_arm64",
        expected_frames=25,
        expected_resolved=8,
        expected_modules=324,
        expected_vregs=32,
        expected_stack_size=4096,
        expected_lbr=0,
        expected_image_base=0x782B122000,
    ),
    "dell_x64": DatasetSpec(
        key="dell_x64",
        rsod_file="rsod_dell_x64.txt",
        symbol_path=SYMBOL_ROOT / "x64" / "CrashTest.so",
        expected_format="uefi_x86",
        expected_frames=6,
        expected_resolved=1,
        expected_modules=316,
        expected_vregs=0,
        expected_stack_size=4096,
        expected_lbr=2,
    ),
}
