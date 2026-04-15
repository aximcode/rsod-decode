"""API-level value pinning tests.

Where test_regression_api.py asserts shape ("is this endpoint a list
with these keys"), this file asserts specific values ("frame 0's first
param is named `ctx` with type CrashContext*, and the crash source
line is crashtest.c:156"). The ground-truth values come from:

  - uefi-devkit/crashtest/crashtest.c (edk2_aa64, dell_aa64)
  - tests/fixtures/psa_x64_forcecrash/BUILD.md (psa_x64_forcecrash)
  - the decoder's own deterministic output on frozen fixtures
    (dell_x64, psa_x64 — no source-level ground truth)

Per-fixture expectations are declared via _ApiExpectations dataclasses.
Fields are optional: only fixtures where we have a known-good value
set them, and the tests skip assertions that don't apply.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from ._datasets import DATASET_SPECS
from .conftest import ApiSessionContext


pytestmark = [pytest.mark.api]


# =============================================================================
# Per-fixture ground-truth declarations
# =============================================================================


@dataclass(frozen=True)
class _Frame:
    """Per-frame ground truth.

    `symbol` is a substring match against the frame's resolved symbol
    name; `None` means the decoder leaves this frame's symbol unset
    (e.g. crash frame with a leaf that the FP walker couldn't tie to
    a known function) — we still pin variables via /api/frame/<idx>.
    `params`/`locals_` are lists of (name, type_contains) where
    type_contains is a substring match so minor backend-to-backend
    type-name variation doesn't break the test.

    `expand_values` pins actual memory-read values for specific
    fields of a struct param/local. Format:

        {var_name: {field_path: expected_value}}

    field_path is dot-separated so nested structs walk naturally
    ('origin.x' first expands 'origin' then reads 'x'). expected
    is an int for scalar comparison or str for string_preview
    substring match (used for `char *` fields).
    """
    symbol: str | None = None
    source_file: str | None = None
    source_line: int | None = None
    params: tuple[tuple[str, str], ...] = ()
    locals_: tuple[tuple[str, str], ...] = ()
    expand_values: dict[str, dict[str, int | str]] = field(
        default_factory=dict)


@dataclass(frozen=True)
class _ApiExpectations:
    format: str
    backend_is: tuple[str, ...]  # acceptable values after auto-detect
    # Per-frame expectations keyed by frame index.
    frames: dict[int, _Frame] = field(default_factory=dict)
    # Subset of globals that must be present (by name). Globals are
    # module-scope so we only pin them once, via frame 0.
    globals_subset: tuple[str, ...] = ()
    # Decoded crash_info.crash_symbol (may be "" for fixtures where
    # the crash_pc isn't in the loaded module).
    crash_symbol: str | None = None
    # LBR expectations
    lbr_count: int = 0
    lbr_first_module: str | None = None
    lbr_first_from_symbol: str | None = None
    lbr_first_to_symbol: str | None = None


# CrashTest.so ground truth comes from uefi-devkit/crashtest/crashtest.c.
# Call chain on ARM64: main → run_crashtest → initialize_test →
# prepare_crash_context → validate_environment → dispatch_crash →
# trigger_page_fault. For the EDK2 fixture the FP chain walks all the
# way down to the leaf; dell_aa64's FP chain stops at dispatch_crash.
# Values from crashtest.c's main() + initialize_test() that the
# CrashTest ELF and PSA forcecrash hook all share verbatim:
#   main:            config.version/flags/session_id/origin set
#   initialize_test: ctx.depth=1, ctx.cookie, ctx.tag="crashtest-v3"
# The mode field differs per fixture because it's parse_mode(argv[1]):
#   "pf" -> 0 (CRASH_MODE_PF)
#   "gp" -> 1 (CRASH_MODE_GP)
_CTX_VALUES: dict[str, int | str] = {
    "depth": 1,
    "cookie": 0xDEAD0000CAFE0000 ^ 0xDEFFBABECAFE0000,  # 0x52BABE00000000
    "tag": "crashtest-v3",
}
_CONFIG_BASE_VALUES: dict[str, int | str] = {
    "version": 3,
    "flags": 0x1234,
    "session_id": 0xDEAD0000CAFE0000,
    "origin.x": 100,
    "origin.y": 200,
}


def _config_values(mode: int) -> dict[str, int | str]:
    return {**_CONFIG_BASE_VALUES, "mode": mode}


_CRASHTEST_FRAMES_EDK2 = {
    0: _Frame("trigger_page_fault", "crashtest.c", 78,
              params=(("addr", "void"),)),
    1: _Frame("dispatch_crash", "crashtest.c", 153,
              params=(("ctx", "CrashContext"),),
              locals_=(("mode", "char"),)),
    2: _Frame("validate_environment", "crashtest.c", 162,
              params=(("ctx", "CrashContext"),)),
    3: _Frame("prepare_crash_context", "crashtest.c", 168,
              params=(("ctx", "CrashContext"),)),
    4: _Frame("initialize_test", "crashtest.c", 186,
              params=(("config", "TestConfig"),
                      ("build_id", "char")),
              locals_=(("ctx", "CrashContext"),),
              expand_values={
                  "ctx": _CTX_VALUES,
                  # edk2 fixture was invoked with "pf" (page fault
                  # default branch of parse_mode) → mode = 0.
                  "config": _config_values(mode=0),
              }),
    5: _Frame("run_crashtest", "crashtest.c", 194,
              params=(("config", "TestConfig"),
                      ("argc", "int"))),
    6: _Frame("main", "crashtest.c", 252,
              params=(("argc", "int"), ("argv", "char")),
              locals_=(("config", "TestConfig"),),
              expand_values={
                  "config": _config_values(mode=0),
              }),
    7: _Frame("_AxlEntry", "axl-crt0-native.c", 38,
              params=(("ImageHandle", "EFI_HANDLE"),
                      ("SystemTable", "EFI_SYSTEM_TABLE")),
              locals_=(("argc", "int"), ("argv", "char"),
                       ("rc", "int"))),
}

_CRASHTEST_FRAMES_DELL_AA64 = {
    0: _Frame("dispatch_crash", "crashtest.c", 156,
              params=(("ctx", "CrashContext"),),
              locals_=(("mode", "char"),)),
    1: _Frame("validate_environment", "crashtest.c", 162,
              params=(("ctx", "CrashContext"),)),
    2: _Frame("prepare_crash_context", "crashtest.c", 168,
              params=(("ctx", "CrashContext"),)),
    3: _Frame("initialize_test", "crashtest.c", 186,
              params=(("config", "TestConfig"),
                      ("build_id", "char")),
              locals_=(("ctx", "CrashContext"),),
              expand_values={
                  "ctx": _CTX_VALUES,
                  # dell_aa64 fixture was invoked with "gp" → mode = 1.
                  "config": _config_values(mode=1),
              }),
    4: _Frame("run_crashtest", "crashtest.c", 194,
              params=(("config", "TestConfig"),
                      ("argc", "int"))),
    5: _Frame("main", "crashtest.c", 252,
              params=(("argc", "int"), ("argv", "char")),
              locals_=(("config", "TestConfig"),),
              expand_values={
                  "config": _config_values(mode=1),
              }),
    6: _Frame("_AxlEntry", "axl-crt0-native.c", 38,
              params=(("ImageHandle", "EFI_HANDLE"),
                      ("SystemTable", "EFI_SYSTEM_TABLE")),
              locals_=(("argc", "int"), ("argv", "char"),
                       ("rc", "int"))),
}


_EXPECTATIONS: dict[str, _ApiExpectations] = {
    "edk2_aa64": _ApiExpectations(
        format="edk2_arm64",
        backend_is=("lldb", "gdb", "pyelftools"),
        frames=_CRASHTEST_FRAMES_EDK2,
        globals_subset=(
            "g_run_count", "g_default_config", "g_crash_cookie"),
    ),
    "dell_aa64": _ApiExpectations(
        format="uefi_arm64",
        backend_is=("lldb", "gdb", "pyelftools"),
        frames=_CRASHTEST_FRAMES_DELL_AA64,
        globals_subset=(
            "g_run_count", "g_default_config", "g_crash_cookie"),
    ),
    "dell_x64": _ApiExpectations(
        format="uefi_x86",
        backend_is=("lldb", "gdb", "pyelftools"),
        lbr_count=2,
        lbr_first_module="CpuDxe.efi",
        frames={5: _Frame("axl_backend_free",
                          "axl-backend-native.c", 90)},
    ),
    "psa_x64": _ApiExpectations(
        format="uefi_x86",
        backend_is=("pyelftools",),  # PE without .pdb, no richer backend
        # R470 production crash — deep C++ call chain, known by symbol
        # name (no debug info, no var expectations).
        frames={1: _Frame("fMpLibRunWithJustBSP")},
    ),
    "psa_x64_forcecrash": _ApiExpectations(
        format="uefi_x86",
        backend_is=("lldb",),  # auto-init from .efi + .pdb
        crash_symbol="trigger_gp_fault",
        lbr_count=2,
        lbr_first_module="psa.efi",
        lbr_first_from_symbol="dispatch_crash",
        lbr_first_to_symbol="trigger_gp_fault",
        # Frame 0's `vector` parameter is held in XMM9 (MSVC DWARF
        # register 26), which isn't part of Dell's RSOD register
        # dump — LLDB reports the name + type but no value. We still
        # pin the declaration. Frame 1+ come from the PDB with stack
        # locations resolved through LldbBackend's image-lookup -va
        # parser and the per-frame RSP scan.
        frames={
            # Frame 0 is trigger_gp_fault in crash_symbol but the
            # decoder's FP/scan walker doesn't set frame[0].symbol
            # since trigger_gp_fault is a tail-called leaf — we pin
            # the `vector` param via the richer backend instead.
            # Frame 0 crashes inside trigger_gp_fault; the PDB line
            # table maps that PC back to the assignment at psaentry.c
            # line 212 (`int* null_ptr = nullptr;`).
            0: _Frame(source_file="psaentry.c",
                      params=(("vector", "unsigned"),)),
            1: _Frame("initialize_test",
                      source_file="psaentry.c",
                      params=(("config", "CrashTestConfig"),
                              ("build_id", "char")),
                      locals_=(("ctx", "CrashContext"),),
                      # Only pin `ctx` here. initialize_test's `config`
                      # param spill slot [RSP+96] gets reused by MSVC
                      # after the initial read — the stored pointer
                      # is stale garbage by the time we crash. The
                      # genuine TestConfig struct still lives in
                      # fForceCrashIfRequested's frame (see frame 2).
                      expand_values={"ctx": _CTX_VALUES}),
            2: _Frame("fForceCrashIfRequested",
                      source_file="psaentry.c",
                      params=(("argc", "int"), ("argv", "char")),
                      locals_=(("config", "CrashTestConfig"),),
                      # In PsaEntry.c's adapted hook fForceCrashIfRequested
                      # holds the TestConfig as a LOCAL struct (not
                      # a pointer), so [RSP+32] reads the exact same
                      # values that main() sets in the ELF fixture.
                      expand_values={
                          "config": _config_values(mode=1),
                      }),
            3: _Frame("fUEFIPSAEntry",
                      source_file="psaentry.c",
                      params=(("originalTxtAttr", "uint64_t"),
                              ("originalTxtMode", "uint64_t")),
                      locals_=(("argv", "char"),
                               ("imageHandle", "void"),
                               ("psSystemTable", "EFI_SYSTEM_TABLE"),
                               ("argc", "int"))),
        },
    ),
}


def _expect(ctx: ApiSessionContext) -> _ApiExpectations:
    exp = _EXPECTATIONS.get(ctx.spec.key)
    if exp is None:
        pytest.skip(f"No API expectations for {ctx.spec.key}")
    return exp


# =============================================================================
# /api/session — top-level session metadata
# =============================================================================


def test_api_session_values(api_session: ApiSessionContext, client) -> None:
    exp = _expect(api_session)
    body = client.get(f"/api/session/{api_session.session_id}").get_json()

    assert body["format"] == exp.format
    assert len(body["frames"]) == api_session.spec.expected_frames
    assert body["backend"] in exp.backend_is, (
        f"unexpected backend {body['backend']!r}; "
        f"expected one of {exp.backend_is}")
    assert isinstance(body["gdb_available"], bool)
    assert isinstance(body["lldb_available"], bool)

    if exp.crash_symbol is not None:
        assert body["crash_summary"]["crash_symbol"] == exp.crash_symbol


_FRAME_TEST_IDS = {
    (key, idx): f"{key}-f{idx}"
    for key, exp in _EXPECTATIONS.items()
    for idx in exp.frames
}
_FRAME_TEST_CASES = list(_FRAME_TEST_IDS.keys())


def _collect_var_names(items: list[dict]) -> list[tuple[str, str]]:
    return [(v["name"], v.get("type") or "") for v in items]


def _assert_var_match(
    frame_idx: int,
    kind: str,
    actual: list[tuple[str, str]],
    expected: tuple[tuple[str, str], ...],
) -> None:
    for name, type_contains in expected:
        matches = [t for n, t in actual if n == name]
        assert matches, (
            f"frame {frame_idx} {kind} {name!r} missing; "
            f"{kind}={actual}")
        assert any(type_contains in t for t in matches), (
            f"frame {frame_idx} {kind} {name!r} type does not "
            f"contain {type_contains!r}; types={matches}")


# =============================================================================
# Backtrace — per-frame symbol + source pinning
# =============================================================================


def test_api_frame_symbols_and_source(
    api_session: ApiSessionContext, client,
) -> None:
    """Every frame in the per-fixture expectations map must match.

    Pins the FP/RBP walker output (symbol per index) and the source
    location metadata (file + line) in one pass through the frame
    list returned by GET /api/session.
    """
    exp = _expect(api_session)
    if not exp.frames:
        pytest.skip("no frame expectations")

    body = client.get(f"/api/session/{api_session.session_id}").get_json()
    frames = body["frames"]
    for idx, fe in exp.frames.items():
        assert idx < len(frames), f"no frame {idx}"
        frame = frames[idx]
        if fe.symbol is not None:
            got_symbol = frame["symbol"]
            assert got_symbol is not None and fe.symbol in got_symbol, (
                f"frame {idx}: expected symbol containing "
                f"{fe.symbol!r}, got {got_symbol!r}")
        if fe.source_file is not None:
            src = frame["source_loc"] or ""
            assert fe.source_file in src, (
                f"frame {idx} source_loc {src!r} does not contain "
                f"{fe.source_file!r}")
            if fe.source_line is not None:
                assert f":{fe.source_line}" in src, (
                    f"frame {idx} source_loc {src!r} does not "
                    f"contain line {fe.source_line}")


# =============================================================================
# /api/frame/<idx> — per-frame variable pinning (params + locals)
# =============================================================================


@pytest.mark.parametrize(
    "fixture_key,frame_idx",
    _FRAME_TEST_CASES,
    ids=[_FRAME_TEST_IDS[k] for k in _FRAME_TEST_CASES],
)
def test_api_per_frame_variables(
    fixture_key: str, frame_idx: int, client,
) -> None:
    """Per-frame params + locals match the fixture's ground truth.

    Parameterized over every (fixture, frame-index) entry in
    _EXPECTATIONS.frames so the full call chain is covered one
    assertion at a time — a regression in any specific frame's
    variable extraction is pinpointed directly.
    """
    from .conftest import create_api_session, delete_api_session

    spec = DATASET_SPECS[fixture_key]
    ctx = create_api_session(client, spec)
    try:
        exp = _EXPECTATIONS[fixture_key]
        fe = exp.frames[frame_idx]
        if not (fe.params or fe.locals_):
            pytest.skip(f"frame {frame_idx}: no variable expectations")

        body = client.get(
            f"/api/frame/{ctx.session_id}/{frame_idx}").get_json()
        _assert_var_match(
            frame_idx, "param",
            _collect_var_names(body["params"]),
            fe.params,
        )
        _assert_var_match(
            frame_idx, "local",
            _collect_var_names(body["locals"]),
            fe.locals_,
        )
    finally:
        delete_api_session(client, ctx)


# Parameterize over every (fixture, frame) that has value expectations
_VALUE_TEST_CASES = [
    (key, idx)
    for key, exp in _EXPECTATIONS.items()
    for idx, f in exp.frames.items()
    if f.expand_values
]
_VALUE_TEST_IDS = [f"{k}-f{i}" for k, i in _VALUE_TEST_CASES]


def _walk_expansion(
    client, session_id: str, frame_idx: int,
    start_var: dict, field_path: str,
) -> dict:
    """Walk /api/expand one or more levels deep to reach `field_path`.

    `field_path` is dot-separated: 'origin.x' expands 'origin' first,
    then finds 'x' in its children. Returns the final field dict.
    """
    parts = field_path.split(".")
    current_addr = start_var["expand_addr"]
    current_key = start_var.get("var_key", "") or ""
    current_tof = start_var.get("type_offset", 0)
    current_cuof = start_var.get("cu_offset", 0)

    for i, part in enumerate(parts):
        assert current_addr is not None, (
            f"cannot expand {field_path!r}: addr is None at "
            f"part {i}={part!r}")
        query = f"addr=0x{current_addr:X}&offset=0&count=64"
        if current_key:
            query += f"&var_key={current_key}"
        else:
            query += (f"&type_offset={current_tof}"
                      f"&cu_offset={current_cuof}")
        resp = client.get(
            f"/api/expand/{session_id}/{frame_idx}?{query}")
        assert resp.status_code == 200, resp.get_json()
        fields = resp.get_json()["fields"]
        match = next((f for f in fields if f["name"] == part), None)
        assert match is not None, (
            f"field {part!r} not found in expansion of {field_path!r} "
            f"at depth {i}; available: "
            f"{[f['name'] for f in fields]}")

        if i == len(parts) - 1:
            return match

        current_addr = match.get("expand_addr")
        current_key = match.get("var_key", "") or ""
        current_tof = match.get("type_offset", 0) or 0
        current_cuof = match.get("cu_offset", 0) or 0

    raise AssertionError("unreachable")


@pytest.mark.parametrize(
    "fixture_key,frame_idx",
    _VALUE_TEST_CASES,
    ids=_VALUE_TEST_IDS,
)
def test_api_per_frame_variable_values(
    fixture_key: str, frame_idx: int, client,
) -> None:
    """Source-code-derived value pinning across the call chain.

    For every (fixture, frame) with `expand_values`, re-creates a
    session, fetches the frame detail, then walks /api/expand for
    each pinned var/field pair to assert the decoded value matches
    the CrashTest source-code ground truth:

      main():       config.{version, flags, session_id, origin.x,
                            origin.y, mode}
      initialize_test(): ctx.{depth, cookie, tag}

    A bug in stack walking, frame lookup, type resolution, memory
    read, or expand-endpoint routing surfaces here at the specific
    (fixture, frame, field) that regressed.
    """
    from .conftest import create_api_session, delete_api_session

    spec = DATASET_SPECS[fixture_key]
    ctx = create_api_session(client, spec)
    try:
        fe = _EXPECTATIONS[fixture_key].frames[frame_idx]
        body = client.get(
            f"/api/frame/{ctx.session_id}/{frame_idx}").get_json()
        all_vars = {v["name"]: v for v in body["params"] + body["locals"]}

        for var_name, field_map in fe.expand_values.items():
            start_var = all_vars.get(var_name)
            assert start_var is not None, (
                f"variable {var_name!r} missing from frame "
                f"{frame_idx}; present: {sorted(all_vars)}")
            assert start_var.get("expand_addr") is not None, (
                f"variable {var_name!r} is not expandable "
                f"(expand_addr=None)")

            for field_path, expected in field_map.items():
                field = _walk_expansion(
                    client, ctx.session_id, frame_idx,
                    start_var, field_path)
                if isinstance(expected, str):
                    preview = field.get("string_preview") or ""
                    assert expected in preview, (
                        f"{var_name}.{field_path} string_preview "
                        f"{preview!r} does not contain "
                        f"{expected!r}")
                else:
                    got = field.get("value")
                    assert got == expected, (
                        f"{var_name}.{field_path}: expected "
                        f"{expected} (0x{expected:X}), got "
                        f"{got} (0x{got:X})"
                        if got is not None
                        else f"{var_name}.{field_path}: expected "
                             f"{expected} (0x{expected:X}), got None")
    finally:
        delete_api_session(client, ctx)


def test_api_globals_subset(
    api_session: ApiSessionContext, client,
) -> None:
    """Globals subset should surface on frame 0 when the fixture has them."""
    exp = _expect(api_session)
    if not exp.globals_subset:
        pytest.skip("no globals expectations")

    body = client.get(
        f"/api/frame/{api_session.session_id}/0").get_json()
    globals_names = {v["name"] for v in body["globals"]}
    missing = set(exp.globals_subset) - globals_names
    assert not missing, (
        f"globals missing {missing}; present={sorted(globals_names)}")


# =============================================================================
# /api/regions — stack-dump size comes from the fixture spec directly
# =============================================================================


def test_api_regions_stack_dump_size(
    api_session: ApiSessionContext, client,
) -> None:
    body = client.get(
        f"/api/regions/{api_session.session_id}").get_json()
    stack = [r for r in body["regions"] if r["name"] == "Stack dump"]
    assert stack, "Stack dump region missing"
    assert stack[0]["size"] == api_session.spec.expected_stack_size


# =============================================================================
# /api/memory — read 64 bytes at SP (or RSP for x86)
# =============================================================================


def test_api_memory_at_stack_pointer(
    api_session: ApiSessionContext, client,
) -> None:
    meta = client.get(f"/api/session/{api_session.session_id}").get_json()
    regs = meta["registers"]
    sp_hex = regs.get("SP") or regs.get("RSP")
    if not sp_hex:
        pytest.skip("fixture has no SP/RSP register")
    sp = int(sp_hex, 16)

    body = client.get(
        f"/api/memory/{api_session.session_id}"
        f"?addr=0x{sp:X}&size=64").get_json()
    assert body["address"] == sp
    assert len(body["bytes"]) == 64
    # At least one real byte readable from the stack dump top.
    assert any(b is not None for b in body["bytes"])


# =============================================================================
# /api/disasm — non-empty for frames whose binary we have
# =============================================================================


def test_api_disasm_has_instructions_for_resolved_frame(
    api_session: ApiSessionContext, client,
) -> None:
    exp = _expect(api_session)
    # Only fixtures whose frame 0 has a known symbol will have a
    # non-empty disasm (the DWARF/PE binary needs to own that module).
    f0 = exp.frames.get(0)
    if f0 is None:
        pytest.skip("frame 0 has no known symbol; disasm may be empty")

    body = client.get(
        f"/api/disasm/{api_session.session_id}/0").get_json()
    insns = body["instructions"]
    assert len(insns) > 0, "disasm returned no instructions"
    target_hits = [i for i in insns if i["is_target"]]
    assert target_hits, "no instruction flagged is_target=True"


def test_api_disasm_target_highlight_all_resolved_frames(
    api_session: ApiSessionContext, client,
) -> None:
    """Every frame in the expectations map should disassemble with
    the target instruction highlighted. This was previously broken
    on variable-length x86 (psa_x64 / psa_x64_forcecrash) because
    the backward alignment scan wasn't anchored on an instruction
    boundary, so the `is_target` flag never matched."""
    exp = _expect(api_session)
    if not exp.frames:
        pytest.skip("no frame expectations")
    sid = api_session.session_id
    body = client.get(f"/api/session/{sid}").get_json()
    total_frames = len(body["frames"])
    for idx in exp.frames:
        if idx >= total_frames:
            continue
        disasm = client.get(f"/api/disasm/{sid}/{idx}").get_json()
        insns = disasm["instructions"]
        assert insns, (
            f"frame {idx}: disasm returned no instructions "
            f"(expected at least one around the target)")
        hit = [i for i in insns if i["is_target"]]
        assert hit, (
            f"frame {idx}: no instruction flagged is_target=True "
            f"(backward alignment scan failed)")


def test_api_disasm_empty_for_unmatched_module(
    api_session: ApiSessionContext, client,
) -> None:
    """Frames whose module has no loaded symbols must render an
    empty disassembly instead of silently disassembling the primary
    CrashTest.so binary at the same byte offset and mislabeling it.
    Picks the first non-CrashTest frame (Shell.*, DxeCore.*, etc.)
    and pins its /api/disasm response to an empty list."""
    if api_session.spec.key not in ("edk2_aa64", "dell_aa64"):
        pytest.skip("only AArch64 fixtures with cross-module frames")
    sid = api_session.session_id
    body = client.get(f"/api/session/{sid}").get_json()
    frames = body["frames"]
    candidate_idx: int | None = None
    for f in frames:
        module = (f.get("module") or "").lower()
        if module and not module.startswith("crashtest"):
            candidate_idx = f["index"]
            break
    if candidate_idx is None:
        pytest.skip("no cross-module frame in this fixture")
    disasm = client.get(f"/api/disasm/{sid}/{candidate_idx}").get_json()
    assert disasm["instructions"] == [], (
        f"frame {candidate_idx} ({frames[candidate_idx].get('module')}) "
        f"should have empty disasm because its module is not the "
        f"primary binary and no extra_sources binary is loaded for "
        f"it, but got {len(disasm['instructions'])} instructions "
        f"(cross-module mislabeling bug)")


# =============================================================================
# /api/source — content pulled from the actual source file
# =============================================================================


def test_api_source_renders_expected_file(
    api_session: ApiSessionContext, client,
) -> None:
    exp = _expect(api_session)
    f0 = exp.frames.get(0)
    if f0 is None or f0.source_file is None:
        pytest.skip("no frame-0 source expectations")

    body = client.get(
        f"/api/source/{api_session.session_id}/0").get_json()
    assert f0.source_file in body["file"]
    if f0.source_line is not None:
        assert body["target_line"] == f0.source_line
    if not body["lines"]:
        # The DWARF/PDB path resolved the source_loc metadata but
        # the file itself isn't present on this machine (common for
        # out-of-tree checkouts like the Dell EPSA tree). That's a
        # `--source-path` configuration concern, not a backend bug —
        # skip cleanly so CI without the sibling trees still passes.
        pytest.skip(
            f"source file {body['file']!r} not reachable on this "
            f"machine (add its tree via --source-path)")
    target_lines = [ln for ln in body["lines"] if ln["is_target"]]
    assert target_lines, "no source line flagged is_target=True"


# =============================================================================
# LBR — Dell x86 RSODs and psa_x64_forcecrash expose LBR entries
# =============================================================================


def test_api_lbr_values(api_session: ApiSessionContext, client) -> None:
    exp = _expect(api_session)
    if exp.lbr_count == 0 and not exp.lbr_first_module:
        pytest.skip("no LBR expectations")

    body = client.get(f"/api/session/{api_session.session_id}").get_json()
    lbr = body["lbr"]
    assert len(lbr) == exp.lbr_count
    if exp.lbr_first_module:
        assert lbr[0]["module"] == exp.lbr_first_module

    if exp.lbr_first_from_symbol or exp.lbr_first_to_symbol:
        by_type = {e["type"]: e for e in lbr}
        if exp.lbr_first_from_symbol:
            fr = client.post(
                f"/api/resolve/{api_session.session_id}",
                json={"address": f"0x{by_type['LBRfr0']['addr']:X}"})
            assert fr.status_code == 200
            assert exp.lbr_first_from_symbol in fr.get_json()["symbol"]
        if exp.lbr_first_to_symbol:
            to = client.post(
                f"/api/resolve/{api_session.session_id}",
                json={"address": f"0x{by_type['LBRto0']['addr']:X}"})
            assert to.status_code == 200
            assert exp.lbr_first_to_symbol in to.get_json()["symbol"]


# =============================================================================
# /api/resolve — validator coverage for arbitrary addresses
# =============================================================================


def test_api_resolve_frame_addresses(
    api_session: ApiSessionContext, client,
) -> None:
    """Each named frame's runtime address must resolve via /api/resolve.

    Validates that the POST /api/resolve endpoint correctly maps a
    runtime address back to the expected symbol — the same lookup the
    frontend uses when the user clicks a HexAddress in the registers
    panel.
    """
    exp = _expect(api_session)
    if not exp.frames:
        pytest.skip("no frame expectations")

    meta = client.get(f"/api/session/{api_session.session_id}").get_json()
    frames = meta["frames"]
    image_base = meta["crash_summary"]["image_base"]

    for idx, fe in exp.frames.items():
        if idx >= len(frames):
            continue
        if fe.symbol is None:
            continue
        frame_addr = frames[idx]["address"]
        # Frame addresses are already runtime for PE fixtures and ELF
        # offsets for ELF. /api/resolve expects a raw image address —
        # same units as preferred_base. We try both forms.
        candidates = [frame_addr]
        if image_base and frame_addr < image_base:
            candidates.append(frame_addr + image_base)

        hit = None
        for addr in candidates:
            resp = client.post(
                f"/api/resolve/{api_session.session_id}",
                json={"address": f"0x{addr:X}"})
            if resp.status_code == 200:
                body = resp.get_json()
                if fe.symbol in body["symbol"]:
                    hit = body
                    break
        assert hit is not None, (
            f"frame {idx} ({fe.symbol}) did not resolve via "
            f"/api/resolve from any of {[hex(a) for a in candidates]}")
