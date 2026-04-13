from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from rsod_decode.app import create_app
from rsod_decode.decoder import analyze_rsod
from rsod_decode.symbols import load_symbols

from ._datasets import (
    DATASET_SPECS,
    DatasetRun,
    FIXTURES_DIR,
    REPO_ROOT,
)


def _require_fixture_file(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"Missing fixture file: {path}")


def _build_dataset_run(key: str) -> DatasetRun:
    spec = DATASET_SPECS[key]
    rsod_path = FIXTURES_DIR / spec.rsod_file
    _require_fixture_file(rsod_path)

    if not spec.symbol_path.exists():
        pytest.skip(f"Required symbol file not found: {spec.symbol_path}")
    if spec.companion_path is not None and not spec.companion_path.exists():
        pytest.skip(f"Required companion file not found: {spec.companion_path}")

    rsod_text = rsod_path.read_text(encoding="utf-8", errors="replace")
    source = load_symbols(
        spec.symbol_path, dwarf_prefix=None, repo_root=REPO_ROOT,
        companion_path=spec.companion_path)
    result = analyze_rsod(rsod_text, source, base_override=spec.base_override)
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
        if run.source.binary:
            run.source.binary.close()


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
