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
    """
    symbol: str | None = None
    source_file: str | None = None
    source_line: int | None = None
    params: tuple[tuple[str, str], ...] = ()
    locals_: tuple[tuple[str, str], ...] = ()


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
              locals_=(("ctx", "CrashContext"),)),
    5: _Frame("run_crashtest", "crashtest.c", 194,
              params=(("config", "TestConfig"),
                      ("argc", "int"))),
    6: _Frame("main", "crashtest.c", 252,
              params=(("argc", "int"), ("argv", "char")),
              locals_=(("config", "TestConfig"),)),
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
              locals_=(("ctx", "CrashContext"),)),
    4: _Frame("run_crashtest", "crashtest.c", 194,
              params=(("config", "TestConfig"),
                      ("argc", "int"))),
    5: _Frame("main", "crashtest.c", 252,
              params=(("argc", "int"), ("argv", "char")),
              locals_=(("config", "TestConfig"),)),
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
            0: _Frame(params=(("vector", "unsigned"),)),
            1: _Frame("initialize_test",
                      params=(("config", "CrashTestConfig"),
                              ("build_id", "char")),
                      locals_=(("ctx", "CrashContext"),)),
            2: _Frame("fForceCrashIfRequested",
                      params=(("argc", "int"), ("argv", "char")),
                      locals_=(("config", "CrashTestConfig"),)),
            3: _Frame("fUEFIPSAEntry",
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
    assert body["lines"], "source endpoint returned no lines"
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
