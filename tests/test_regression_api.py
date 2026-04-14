from __future__ import annotations

import io
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from ._datasets import DATASET_SPECS, DatasetSpec


pytestmark = [pytest.mark.api]


@dataclass
class ApiSessionContext:
    session_id: str
    spec: DatasetSpec


def _create_session(client, spec: DatasetSpec) -> ApiSessionContext:
    rsod_path = Path(__file__).parent / "fixtures" / spec.rsod_file
    if not spec.symbol_path.exists():
        pytest.skip(f"Required symbol file not found: {spec.symbol_path}")
    if spec.companion_path is not None and not spec.companion_path.exists():
        pytest.skip(f"Required companion file not found: {spec.companion_path}")

    with spec.symbol_path.open("rb") as symbol_fp:
        data: dict = {
            "rsod_log": (io.BytesIO(rsod_path.read_bytes()), spec.rsod_file),
            "symbol_file": (symbol_fp, spec.symbol_path.name),
        }
        # Upload companion binary (MSVC MAP+EFI pair) and any .pdb for
        # PDB-backed LLDB as extras so the Flask side exercises the
        # _pair_map_with_pe + _pop_pdb_for auto-detection paths.
        extra_fps: list = []
        extras: list = []
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
                "/api/session", data=data, content_type="multipart/form-data"
            )
        finally:
            for fp in extra_fps:
                fp.close()

    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    assert body["frame_count"] == spec.expected_frames

    return ApiSessionContext(session_id=body["session_id"], spec=spec)


def _delete_session(client, ctx: ApiSessionContext) -> None:
    client.delete(f"/api/session/{ctx.session_id}")


@pytest.fixture(params=list(DATASET_SPECS.keys()), ids=list(DATASET_SPECS.keys()))
def api_session(client, request):
    spec = DATASET_SPECS[request.param]
    ctx = _create_session(client, spec)
    try:
        yield ctx
    finally:
        _delete_session(client, ctx)


def _get_frame0(client, session_id: str) -> dict:
    response = client.get(f"/api/frame/{session_id}/0")
    assert response.status_code == 200
    return response.get_json()


def _switch_backend_or_skip(client, session_id: str, backend: str) -> None:
    response = client.post(f"/api/backend/{session_id}", json={"backend": backend})
    if response.status_code != 200:
        pytest.skip(f"Unable to switch backend to {backend}: {response.get_json()}")


def test_api_session_get(api_session: ApiSessionContext, client) -> None:
    response = client.get(f"/api/session/{api_session.session_id}")
    assert response.status_code == 200

    body = response.get_json()
    assert body["format"] == api_session.spec.expected_format
    assert len(body["frames"]) == api_session.spec.expected_frames
    assert body["backend"] in ("pyelftools", "gdb", "lldb")
    assert body["gdb_available"] in (True, False)
    assert body["lldb_available"] in (True, False)


def test_api_frame_and_expand(api_session: ApiSessionContext, client) -> None:
    if api_session.spec.expected_frames == 0:
        pytest.skip("fixture has no frames")
    frame = _get_frame0(client, api_session.session_id)

    assert frame["index"] == 0
    assert isinstance(frame["params"], list)
    assert isinstance(frame["locals"], list)
    assert isinstance(frame["globals"], list)

    expandable = None
    for section in ("params", "locals", "globals"):
        for candidate in frame[section]:
            if candidate.get("is_expandable") and candidate.get("expand_addr") is not None:
                expandable = candidate
                break
        if expandable:
            break

    if expandable is None:
        pytest.skip("No expandable variable found in frame 0")

    addr = expandable["expand_addr"]
    query = f"addr=0x{addr:X}&offset=0&count=16"
    var_key = expandable.get("var_key", "")
    if var_key:
        query += f"&var_key={var_key}"
    else:
        if expandable.get("type_offset") is None or expandable.get("cu_offset") is None:
            pytest.skip("Expandable variable missing type_offset/cu_offset")
        query += f"&type_offset={expandable['type_offset']}&cu_offset={expandable['cu_offset']}"

    response = client.get(f"/api/expand/{api_session.session_id}/0?{query}")
    assert response.status_code == 200

    body = response.get_json()
    assert isinstance(body["fields"], list)
    assert isinstance(body["total_count"], int)


def test_api_disasm_and_source(api_session: ApiSessionContext, client) -> None:
    if api_session.spec.expected_frames == 0:
        pytest.skip("fixture has no frames")
    disasm = client.get(f"/api/disasm/{api_session.session_id}/0")
    assert disasm.status_code == 200
    disasm_body = disasm.get_json()
    assert isinstance(disasm_body["instructions"], list)

    source = client.get(f"/api/source/{api_session.session_id}/0")
    assert source.status_code == 200
    source_body = source.get_json()
    assert "file" in source_body
    assert "target_line" in source_body
    assert isinstance(source_body["lines"], list)


def test_api_memory_and_regions(api_session: ApiSessionContext, client) -> None:
    session_data = client.get(f"/api/session/{api_session.session_id}").get_json()
    registers = session_data["registers"]
    sp_hex = registers.get("SP") or registers.get("RSP")
    if not sp_hex:
        pytest.skip("No SP/RSP register available")

    sp_addr = int(sp_hex, 16)
    response = client.get(f"/api/memory/{api_session.session_id}?addr=0x{sp_addr:X}&size=64")
    assert response.status_code == 200
    body = response.get_json()

    assert body["address"] == sp_addr
    # Stack dump memory read may return N/A sentinels (None) outside the
    # dumped window for some fixtures; just assert shape + size.
    assert len(body["bytes"]) == 64

    regions = client.get(f"/api/regions/{api_session.session_id}")
    assert regions.status_code == 200
    regions_body = regions.get_json()["regions"]

    assert any(
        r["name"] == "Stack dump" and r["size"] == api_session.spec.expected_stack_size
        for r in regions_body
    )
    assert regions_body == sorted(regions_body, key=lambda r: r["start"])


def test_api_backend_endpoint_validation(api_session: ApiSessionContext, client) -> None:
    invalid = client.post(f"/api/backend/{api_session.session_id}", json={"backend": "bad"})
    assert invalid.status_code == 400


@pytest.mark.gdb
def test_frame0_parity_pyelftools_vs_gdb(api_session: ApiSessionContext, client) -> None:
    if api_session.spec.expected_frames == 0:
        pytest.skip("fixture has no frames")
    session_meta = client.get(f"/api/session/{api_session.session_id}").get_json()
    if not session_meta["gdb_available"]:
        pytest.skip("GDB backend not available")

    _switch_backend_or_skip(client, api_session.session_id, "pyelftools")
    pyelf_frame = _get_frame0(client, api_session.session_id)

    _switch_backend_or_skip(client, api_session.session_id, "gdb")
    gdb_frame = _get_frame0(client, api_session.session_id)

    assert gdb_frame["index"] == pyelf_frame["index"]
    assert gdb_frame["address"] == pyelf_frame["address"]
    assert gdb_frame["symbol"] == pyelf_frame["symbol"]
    assert len(gdb_frame["params"]) == len(pyelf_frame["params"])
    assert len(gdb_frame["locals"]) == len(pyelf_frame["locals"])
    assert len(gdb_frame["globals"]) == len(pyelf_frame["globals"])


@pytest.mark.lldb
def test_frame0_parity_pyelftools_vs_lldb(api_session: ApiSessionContext, client) -> None:
    if api_session.spec.expected_frames == 0:
        pytest.skip("fixture has no frames")
    session_meta = client.get(f"/api/session/{api_session.session_id}").get_json()
    if not session_meta["lldb_available"]:
        pytest.skip("LLDB backend not available")

    _switch_backend_or_skip(client, api_session.session_id, "pyelftools")
    pyelf_frame = _get_frame0(client, api_session.session_id)

    _switch_backend_or_skip(client, api_session.session_id, "lldb")
    lldb_frame = _get_frame0(client, api_session.session_id)

    assert lldb_frame["index"] == pyelf_frame["index"]
    assert lldb_frame["address"] == pyelf_frame["address"]
    assert lldb_frame["symbol"] == pyelf_frame["symbol"]
    assert len(lldb_frame["params"]) == len(pyelf_frame["params"])
    assert len(lldb_frame["locals"]) == len(pyelf_frame["locals"])
    assert len(lldb_frame["globals"]) == len(pyelf_frame["globals"])


@pytest.mark.gdb
def test_api_eval_ctx_pointer_with_gdb(api_session: ApiSessionContext, client) -> None:
    if api_session.spec.key != "dell_aa64":
        pytest.skip("ctx frame-0 expression is validated only for Dell AA64 fixture")

    session_meta = client.get(f"/api/session/{api_session.session_id}").get_json()
    if not session_meta["gdb_available"]:
        pytest.skip("GDB backend not available")

    _switch_backend_or_skip(client, api_session.session_id, "gdb")

    response = client.post(f"/api/eval/{api_session.session_id}/0", json={"expr": "ctx"})
    assert response.status_code == 200
    body = response.get_json()
    assert "error" not in body
    assert re.search(r"0x[0-9a-fA-F]+", body.get("value", ""))


@pytest.mark.lldb
def test_psa_x64_forcecrash_ground_truth_via_api(
    api_session: ApiSessionContext, client,
) -> None:
    """PDB-backed struct expansion ground-truth.

    Uploads psa_x64.efi + .map + .pdb and hits /api/expand with the
    same `pe_type:` var_keys the frontend sends, asserting the
    deterministic CrashContext/CrashTestConfig field values documented
    in tests/fixtures/psa_x64_forcecrash/BUILD.md.

    Struct addresses are computed relative to the crash RSP from the
    BUILD.md stack offset table — no CFI unwinding involved.
    """
    if api_session.spec.key != "psa_x64_forcecrash":
        pytest.skip("ground-truth assertions only for psa_x64_forcecrash")

    meta = client.get(f"/api/session/{api_session.session_id}").get_json()
    if not meta["lldb_available"]:
        pytest.skip("LLDB backend not available")
    if meta["backend"] != "lldb":
        pytest.skip(f"session backend is {meta['backend']!r}, expected lldb")

    rsp = int(meta["registers"]["RSP"], 16)
    # BUILD.md: ctx.cookie partial at RSP+0x38, cookie@CrashContext+16 →
    # ctx starts at RSP+0x28 (= RSP + 40).
    ctx_addr = rsp + 40

    def expand(addr: int, var_key: str) -> list[dict]:
        resp = client.get(
            f"/api/expand/{api_session.session_id}/0"
            f"?addr=0x{addr:X}&var_key={var_key}&offset=0&count=32")
        assert resp.status_code == 200, resp.get_json()
        return resp.get_json()["fields"]

    ctx_fields = {f["name"]: f for f in expand(ctx_addr, "pe_type:CrashContext")}
    assert ctx_fields["depth"]["value"] == 1
    assert ctx_fields["cookie"]["value"] == (
        0xDEAD0000CAFE0000 ^ 0xDEFFBABECAFE0000)
    assert ctx_fields["tag"]["string_preview"] == "crashtest-v3"
    # attempts[1] was bumped by validate_environment before the tail-call
    # chain continued — preview string lists the array contents.
    assert ctx_fields["attempts"]["string_preview"] == "[0, 1, 0, 0]"

    config_ptr = ctx_fields["config"]["expand_addr"]
    config_key = ctx_fields["config"]["var_key"]
    assert config_ptr is not None and config_key.startswith("pe_type:")

    cfg_fields = {f["name"]: f for f in expand(config_ptr, config_key)}
    assert cfg_fields["session_id"]["value"] == 0xDEAD0000CAFE0000
    assert cfg_fields["flags"]["value"] == 0x1234
    assert cfg_fields["version"]["value"] == 3
    assert cfg_fields["mode"]["value"] == 1

    origin_addr = cfg_fields["origin"]["expand_addr"]
    origin_key = cfg_fields["origin"]["var_key"]
    assert origin_addr is not None and origin_key.startswith("pe_type:")
    pt_fields = {f["name"]: f for f in expand(origin_addr, origin_key)}
    assert pt_fields["x"]["value"] == 100
    assert pt_fields["y"]["value"] == 200


def test_eval_rejected_without_gdb(api_session: ApiSessionContext, client) -> None:
    if api_session.spec.expected_frames == 0:
        pytest.skip("fixture has no frames")
    _switch_backend_or_skip(client, api_session.session_id, "pyelftools")

    response = client.post(f"/api/eval/{api_session.session_id}/0", json={"expr": "ctx"})
    assert response.status_code == 400
