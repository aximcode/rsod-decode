from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import pytest

from rsod_decode.app import create_app
from rsod_decode.decoder import AnalysisResult, analyze_rsod
from rsod_decode.models import SymbolSource
from rsod_decode.symbols import load_symbols


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


def _require_fixture_file(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"Missing fixture file: {path}")


def _build_dataset_run(key: str) -> DatasetRun:
    spec = DATASET_SPECS[key]
    rsod_path = FIXTURES_DIR / spec.rsod_file
    _require_fixture_file(rsod_path)

    if not spec.symbol_path.exists():
        pytest.skip(f"Required symbol file not found: {spec.symbol_path}")

    rsod_text = rsod_path.read_text(encoding="utf-8", errors="replace")
    source = load_symbols(spec.symbol_path, dwarf_prefix=None, repo_root=REPO_ROOT)
    result = analyze_rsod(rsod_text, source)
    return DatasetRun(spec=spec, rsod_text=rsod_text, source=source, result=result)


@pytest.fixture(scope="session")
def dataset_runs() -> Iterator[dict[str, DatasetRun]]:
    runs: dict[str, DatasetRun] = {}
    for key in DATASET_SPECS:
        try:
            runs[key] = _build_dataset_run(key)
        except pytest.skip.Exception:
            continue
    yield runs
    for run in runs.values():
        if run.source.dwarf:
            run.source.dwarf.close()


@pytest.fixture(scope="session")
def load_dataset_run(dataset_runs: dict[str, DatasetRun]):
    def _loader(key: str) -> DatasetRun:
        if key in dataset_runs:
            return dataset_runs[key]
        spec = DATASET_SPECS[key]
        pytest.skip(f"Required symbol file not found: {spec.symbol_path}")

    return _loader


@pytest.fixture(scope="session")
def app():
    flask_app = create_app(repo_root=REPO_ROOT, dwarf_prefix=None)
    flask_app.config["TESTING"] = True
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture(params=list(DATASET_SPECS.keys()), ids=list(DATASET_SPECS.keys()))
def dataset_run(request, load_dataset_run) -> DatasetRun:
    return load_dataset_run(request.param)
