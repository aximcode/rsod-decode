from __future__ import annotations

import io
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from rsod_decode.app import create_app
from rsod_decode.decoder import analyze_rsod
from rsod_decode.symbols import load_symbols

from ._datasets import (
    DATASET_SPECS,
    DatasetRun,
    DatasetSpec,
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
    # Collect every out-of-tree source root referenced by the
    # dataset specs (e.g. axl-sdk for CrashTest.so frames) and pass
    # them into the Flask app so the /api/source handler can find
    # files that live outside the rsod-decode checkout. Existing
    # roots are silently skipped when the directory isn't present
    # on the dev machine, so CI without axl-sdk still runs.
    source_paths: list[Path] = []
    seen: set[Path] = set()
    for spec in DATASET_SPECS.values():
        for root in spec.source_roots:
            if root in seen:
                continue
            seen.add(root)
            if root.is_dir():
                source_paths.append(root)
    flask_app = create_app(
        repo_root=REPO_ROOT, dwarf_prefix=None,
        source_paths=source_paths or None)
    flask_app.config["TESTING"] = True
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture(params=list(DATASET_SPECS.keys()), ids=list(DATASET_SPECS.keys()))
def dataset_run(request, load_dataset_run) -> DatasetRun:
    return load_dataset_run(request.param)


# =============================================================================
# Shared API-session plumbing (Flask test-client multipart upload)
# =============================================================================


@dataclass
class ApiSessionContext:
    session_id: str
    spec: DatasetSpec


def create_api_session(client, spec: DatasetSpec) -> ApiSessionContext:
    """Upload a dataset via POST /api/session and return its context.

    Handles the full MSVC MAP/EFI/PDB extras plumbing so api tests
    don't have to know about multipart encoding. Skips cleanly when
    any required fixture file is missing.
    """
    rsod_path = FIXTURES_DIR / spec.rsod_file
    if not spec.symbol_path.exists():
        pytest.skip(f"Required symbol file not found: {spec.symbol_path}")
    if spec.companion_path is not None and not spec.companion_path.exists():
        pytest.skip(f"Required companion file not found: {spec.companion_path}")

    extra_fps: list = []
    extras: list = []
    with spec.symbol_path.open("rb") as symbol_fp:
        data: dict = {
            "rsod_log": (io.BytesIO(rsod_path.read_bytes()), spec.rsod_file),
            "symbol_file": (symbol_fp, spec.symbol_path.name),
        }
        if spec.companion_path is not None:
            fp = spec.companion_path.open("rb")
            extra_fps.append(fp)
            extras.append((fp, spec.companion_path.name))
        if spec.pdb_path is not None and spec.pdb_path.exists():
            fp = spec.pdb_path.open("rb")
            extra_fps.append(fp)
            extras.append((fp, spec.pdb_path.name))
        if extras:
            data["extra_symbols[]"] = extras if len(extras) > 1 else extras[0]
        if spec.base_override is not None:
            data["base"] = f"{spec.base_override:X}"
        try:
            response = client.post(
                "/api/session", data=data,
                content_type="multipart/form-data")
        finally:
            for fp in extra_fps:
                fp.close()

    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    assert body["frame_count"] == spec.expected_frames
    return ApiSessionContext(session_id=body["session_id"], spec=spec)


def delete_api_session(client, ctx: ApiSessionContext) -> None:
    client.delete(f"/api/session/{ctx.session_id}")


@pytest.fixture(
    params=list(DATASET_SPECS.keys()),
    ids=list(DATASET_SPECS.keys()),
)
def api_session(client, request):
    """Parameterized Flask-session fixture shared across api test files.

    Yields an ApiSessionContext with the session_id + DatasetSpec;
    cleans up via DELETE /api/session/<id> on teardown.
    """
    spec = DATASET_SPECS[request.param]
    ctx = create_api_session(client, spec)
    try:
        yield ctx
    finally:
        delete_api_session(client, ctx)
