from __future__ import annotations

import re

import pytest

from ._datasets import DATASET_SPECS
from .conftest import ApiSessionContext, create_api_session


pytestmark = [pytest.mark.api]


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
    expected_count = (
        api_session.spec.expected_api_frames
        or api_session.spec.expected_frames)
    assert len(body["frames"]) == expected_count
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
    if api_session.spec.pdb_path is not None:
        # PDB-backed PE sessions gain variable info pyelftools can't
        # see (PE has no DWARF), so the "LLDB matches pyelftools"
        # parity contract doesn't apply — covered by the dedicated
        # ground-truth test below.
        pytest.skip("PE+PDB session; parity not applicable")
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

    Drives /api/expand through the same flow the frontend uses:
    /api/frame/<init_idx> discovers the `ctx` local and its var_key;
    we then walk the CrashContext → CrashTestConfig → Point pointer
    chain asserting the deterministic field values documented in
    tests/fixtures/psa_x64_forcecrash/BUILD.md. LLDB's PE+PDB
    minidump path resolves the per-frame RSP via the unwinder's
    .pdata reader, so no manual stack-offset math is needed.
    """
    if api_session.spec.key != "psa_x64_forcecrash":
        pytest.skip("ground-truth assertions only for psa_x64_forcecrash")

    meta = client.get(f"/api/session/{api_session.session_id}").get_json()
    if not meta["lldb_available"]:
        pytest.skip("LLDB backend not available")
    if meta["backend"] != "lldb":
        pytest.skip(f"session backend is {meta['backend']!r}, expected lldb")

    # Find initialize_test in the frame list; its `ctx` local holds
    # the ground-truth CrashContext we want to validate.
    init_idx = next(
        (i for i, f in enumerate(meta["frames"])
         if f["symbol"] == "initialize_test"),
        None)
    assert init_idx is not None, "initialize_test not in frame list"

    frame_body = client.get(
        f"/api/frame/{api_session.session_id}/{init_idx}").get_json()
    locals_ = {v["name"]: v for v in frame_body["locals"]}
    ctx_var = locals_["ctx"]
    assert ctx_var["is_expandable"]
    ctx_addr = ctx_var["expand_addr"]
    ctx_key = ctx_var["var_key"]
    assert ctx_addr is not None and ctx_key

    def expand(
        addr: int, var_key: str, frame_idx: int = init_idx,
    ) -> list[dict]:
        resp = client.get(
            f"/api/expand/{api_session.session_id}/{frame_idx}"
            f"?addr=0x{addr:X}&var_key={var_key}&offset=0&count=32")
        assert resp.status_code == 200, resp.get_json()
        return resp.get_json()["fields"]

    ctx_fields = {f["name"]: f for f in expand(ctx_addr, ctx_key)}
    assert ctx_fields["depth"]["value"] == 1
    assert ctx_fields["cookie"]["value"] == (
        0xDEAD0000CAFE0000 ^ 0xDEFFBABECAFE0000)
    assert ctx_fields["tag"]["string_preview"] == "crashtest-v3"
    # attempts[1] was bumped by validate_environment before the tail-call
    # chain continued — preview string lists the array contents.
    assert ctx_fields["attempts"]["string_preview"] == "[0, 1, 0, 0]"

    config_ptr = ctx_fields["config"]["expand_addr"]
    config_key = ctx_fields["config"]["var_key"]
    assert config_ptr is not None and config_key

    cfg_fields = {f["name"]: f for f in expand(config_ptr, config_key)}
    assert cfg_fields["session_id"]["value"] == 0xDEAD0000CAFE0000
    assert cfg_fields["flags"]["value"] == 0x1234
    assert cfg_fields["version"]["value"] == 3
    assert cfg_fields["mode"]["value"] == 1

    origin_addr = cfg_fields["origin"]["expand_addr"]
    origin_key = cfg_fields["origin"]["var_key"]
    assert origin_addr is not None and origin_key
    pt_fields = {f["name"]: f for f in expand(origin_addr, origin_key)}
    assert pt_fields["x"]["value"] == 100
    assert pt_fields["y"]["value"] == 200


@pytest.mark.lldb
def test_psa_x64_forcecrash_frame1_locals_via_api(
    api_session: ApiSessionContext, client,
) -> None:
    """Per-frame PDB variable listing for the initialize_test frame.

    Exercises the full /api/frame -> get_locals -> pe_type: var_key
    pipeline in PE+PDB mode: frame 1 (initialize_test) must return
    `config` + `build_id` as params and `ctx` as a local with the
    CrashContext var_key, and the round-trip /api/expand using that
    var_key must resolve ctx.depth = 1.
    """
    if api_session.spec.key != "psa_x64_forcecrash":
        pytest.skip("PE+PDB frame listing assertions only for forcecrash")

    meta = client.get(f"/api/session/{api_session.session_id}").get_json()
    if meta["backend"] != "lldb":
        pytest.skip(f"session backend is {meta['backend']!r}, expected lldb")

    # Find the initialize_test frame in the frame list.
    frames = meta["frames"]
    init_idx = next(
        (i for i, f in enumerate(frames) if f["symbol"] == "initialize_test"),
        None)
    assert init_idx is not None, "initialize_test not in frame list"

    frame_body = client.get(
        f"/api/frame/{api_session.session_id}/{init_idx}").get_json()
    params = {p["name"]: p for p in frame_body["params"]}
    locals_ = {v["name"]: v for v in frame_body["locals"]}

    assert "config" in params, f"params missing config: {list(params)}"
    assert "build_id" in params, f"params missing build_id: {list(params)}"
    assert params["config"]["type"] == "CrashTestConfig *"

    assert "ctx" in locals_, f"locals missing ctx: {list(locals_)}"
    ctx_var = locals_["ctx"]
    assert ctx_var["type"] == "CrashContext"
    assert ctx_var["is_expandable"] is True
    # var_key is an opaque routing token — unified backend emits the
    # SBValue-cache form `v_<pc>_<name>` for every mode, so assert
    # it's present rather than format-pinning.
    assert ctx_var["var_key"], "ctx missing var_key for /api/expand"
    assert ctx_var["expand_addr"] is not None

    # Round-trip through /api/expand to prove var_key wires correctly.
    addr = ctx_var["expand_addr"]
    vkey = ctx_var["var_key"]
    resp = client.get(
        f"/api/expand/{api_session.session_id}/{init_idx}"
        f"?addr=0x{addr:X}&var_key={vkey}&offset=0&count=32")
    assert resp.status_code == 200, resp.get_json()
    fields = {f["name"]: f for f in resp.get_json()["fields"]}
    assert fields["depth"]["value"] == 1


def test_eval_rejected_without_gdb(api_session: ApiSessionContext, client) -> None:
    if api_session.spec.expected_frames == 0:
        pytest.skip("fixture has no frames")
    _switch_backend_or_skip(client, api_session.session_id, "pyelftools")

    response = client.post(f"/api/eval/{api_session.session_id}/0", json={"expr": "ctx"})
    assert response.status_code == 400


def test_session_persistence_across_restart(client, app) -> None:
    """Upload → simulate restart → hydrate → assert frames match.

    Uses the edk2_aa64 dataset because it does not require an MSVC
    PDB (PDB path is conditional on LLDB) so the pyelftools hydration
    path is exercised even when system lldb is absent.
    """
    spec = DATASET_SPECS["edk2_aa64"]
    ctx = create_api_session(client, spec)
    session_id = ctx.session_id

    first = client.get(f"/api/session/{session_id}")
    assert first.status_code == 200
    first_body = first.get_json()

    # Hydration path: drop the in-memory session, then hit the same
    # endpoint on a FRESH Flask app (same storage dir), simulating
    # a process restart. The new client must recover the session from
    # SQLite and re-run service.run_analysis against the stored inputs.
    from rsod_decode.session import _sessions, evict_from_memory
    from rsod_decode.app import create_app
    evicted = _sessions.pop(session_id, None)
    assert evicted is not None
    evict_from_memory(evicted)

    fresh_app = create_app(
        repo_root=app.config["REPO_ROOT"],
        dwarf_prefix=app.config["DWARF_PREFIX"],
        source_paths=app.config.get("SOURCE_PATHS") or None,
    )
    fresh_app.config["TESTING"] = True
    fresh_client = fresh_app.test_client()

    hydrated = fresh_client.get(f"/api/session/{session_id}")
    assert hydrated.status_code == 200, hydrated.get_json()
    hydrated_body = hydrated.get_json()

    # Frames should round-trip: same count, same addresses, same symbols.
    assert len(hydrated_body["frames"]) == len(first_body["frames"])
    for a, b in zip(first_body["frames"], hydrated_body["frames"]):
        assert a["address"] == b["address"]
        assert a.get("symbol") == b.get("symbol")

    # History endpoint should list the session.
    hist = fresh_client.get("/api/history").get_json()
    assert any(s["id"] == session_id for s in hist["sessions"])

    # Cleanup via DELETE — should also remove the files dir.
    from rsod_decode import data_dir as _data_dir
    files_dir = _data_dir.session_files_dir_for(session_id)
    assert files_dir.exists()
    resp = fresh_client.delete(f"/api/session/{session_id}")
    assert resp.status_code == 200
    assert not files_dir.exists()
