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
class _ApiExpectations:
    # /api/session
    format: str
    backend_is: tuple[str, ...]  # acceptable values after auto-detect
    # Frame 0 (crash frame)
    frame0_symbol: str | None = None
    frame0_source_file: str | None = None   # substring of the full path
    frame0_source_line: int | None = None
    # Expected params/locals on frame 0. Each entry is (name, type_contains).
    # type_contains is a substring match so minor type-name variations
    # between backends don't break the test.
    frame0_params: tuple[tuple[str, str], ...] = ()
    frame0_locals: tuple[tuple[str, str], ...] = ()
    # Subset of globals that must be present (by name).
    frame0_globals_subset: tuple[str, ...] = ()
    # Other frames we can recognize. Key is frame index, value is
    # expected symbol name substring. Used to pin the walk beyond
    # frame 0 for the CrashTest chain.
    named_frames: dict[int, str] = field(default_factory=dict)
    # Decoded crash_info.crash_symbol (may be "" for fixtures where
    # the crash_pc isn't in the loaded module).
    crash_symbol: str | None = None
    # LBR expectations
    lbr_count: int = 0
    lbr_first_module: str | None = None
    lbr_first_from_symbol: str | None = None
    lbr_first_to_symbol: str | None = None
    # /api/resolve against the preferred_base symbol table: (addr, name)
    resolve_known: tuple[tuple[int, str], ...] = ()


_EXPECTATIONS: dict[str, _ApiExpectations] = {
    "edk2_aa64": _ApiExpectations(
        format="edk2_arm64",
        backend_is=("lldb", "gdb", "pyelftools"),
        frame0_symbol="trigger_page_fault",
        frame0_source_file="crashtest.c",
        frame0_source_line=78,
        frame0_params=(("addr", "void"),),
        frame0_globals_subset=(
            "g_run_count", "g_default_config", "g_crash_cookie"),
        named_frames={
            1: "dispatch_crash",
            2: "validate_environment",
            3: "prepare_crash_context",
            4: "initialize_test",
            5: "run_crashtest",
        },
    ),
    "dell_aa64": _ApiExpectations(
        format="uefi_arm64",
        backend_is=("lldb", "gdb", "pyelftools"),
        frame0_symbol="dispatch_crash",
        frame0_source_file="crashtest.c",
        frame0_source_line=156,
        frame0_params=(("ctx", "CrashContext"),),
        frame0_locals=(("mode", "char"),),
        frame0_globals_subset=(
            "g_run_count", "g_default_config", "g_crash_cookie"),
        named_frames={
            1: "validate_environment",
            2: "prepare_crash_context",
            3: "initialize_test",
            4: "run_crashtest",
            5: "main",
        },
    ),
    "dell_x64": _ApiExpectations(
        format="uefi_x86",
        backend_is=("lldb", "gdb", "pyelftools"),
        lbr_count=2,
        lbr_first_module="CpuDxe.efi",
        named_frames={5: "axl_backend_free"},
    ),
    "psa_x64": _ApiExpectations(
        format="uefi_x86",
        backend_is=("pyelftools",),  # PE without .pdb, no richer backend
        # R470 production crash — deep C++ call chain, known by symbol name.
        named_frames={1: "fMpLibRunWithJustBSP"},
    ),
    "psa_x64_forcecrash": _ApiExpectations(
        format="uefi_x86",
        backend_is=("lldb",),  # auto-init from .efi + .pdb
        crash_symbol="trigger_gp_fault",
        lbr_count=2,
        lbr_first_module="psa.efi",
        lbr_first_from_symbol="dispatch_crash",
        lbr_first_to_symbol="trigger_gp_fault",
        named_frames={
            1: "initialize_test",
            2: "fForceCrashIfRequested",
            3: "fUEFIPSAEntry",
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


# =============================================================================
# Backtrace — per-frame symbol resolution beyond frame 0
# =============================================================================


def test_api_named_frames(api_session: ApiSessionContext, client) -> None:
    """Frames we know the symbol for must resolve to that symbol.

    Covers the FP/RBP chain walker and the stack-scan fallback together:
    every ground-truth frame must match by index, which pins the walk.
    """
    exp = _expect(api_session)
    if not exp.named_frames:
        pytest.skip("no named-frame expectations")

    body = client.get(f"/api/session/{api_session.session_id}").get_json()
    frames = body["frames"]
    for idx, expected_symbol in exp.named_frames.items():
        assert idx < len(frames), f"no frame {idx}"
        got = frames[idx]["symbol"]
        assert got is not None and expected_symbol in got, (
            f"frame {idx}: expected symbol containing "
            f"{expected_symbol!r}, got {got!r}")


# =============================================================================
# /api/frame/<id>/0 — crash-frame variable pinning
# =============================================================================


def test_api_frame0_symbol_and_source(
    api_session: ApiSessionContext, client,
) -> None:
    exp = _expect(api_session)
    if exp.frame0_symbol is None and exp.frame0_source_file is None:
        pytest.skip("no frame-0 symbol/source expectations")

    body = client.get(f"/api/session/{api_session.session_id}").get_json()
    assert body["frames"], "fixture has no frames"
    f0 = body["frames"][0]
    assert f0["is_crash_frame"] is True

    if exp.frame0_symbol is not None:
        assert f0["symbol"] is not None and exp.frame0_symbol in f0["symbol"]
    if exp.frame0_source_file is not None:
        src = f0["source_loc"] or ""
        assert exp.frame0_source_file in src, (
            f"frame 0 source_loc {src!r} does not contain "
            f"{exp.frame0_source_file!r}")
    if exp.frame0_source_line is not None:
        src = f0["source_loc"] or ""
        assert f":{exp.frame0_source_line}" in src, (
            f"frame 0 source_loc {src!r} does not contain line "
            f"{exp.frame0_source_line}")


def _collect_var_names(
    items: list[dict],
) -> list[tuple[str, str]]:
    return [(v["name"], v.get("type") or "") for v in items]


def test_api_frame0_variables(
    api_session: ApiSessionContext, client,
) -> None:
    exp = _expect(api_session)
    if not (exp.frame0_params or exp.frame0_locals
            or exp.frame0_globals_subset):
        pytest.skip("no frame-0 variable expectations")

    body = client.get(
        f"/api/frame/{api_session.session_id}/0").get_json()

    if exp.frame0_params:
        params = _collect_var_names(body["params"])
        for name, type_contains in exp.frame0_params:
            matches = [t for n, t in params if n == name]
            assert matches, (
                f"param {name!r} missing; params={params}")
            assert any(type_contains in t for t in matches), (
                f"param {name!r} type does not contain "
                f"{type_contains!r}; types={matches}")

    if exp.frame0_locals:
        locals_ = _collect_var_names(body["locals"])
        for name, type_contains in exp.frame0_locals:
            matches = [t for n, t in locals_ if n == name]
            assert matches, (
                f"local {name!r} missing; locals={locals_}")
            assert any(type_contains in t for t in matches)

    if exp.frame0_globals_subset:
        globals_names = {v["name"] for v in body["globals"]}
        missing = set(exp.frame0_globals_subset) - globals_names
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
    # Only fixtures whose frame 0 resolved to a symbol will have a
    # non-empty disasm (the DWARF/PE binary needs to own that module).
    if exp.frame0_symbol is None:
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
    if exp.frame0_source_file is None:
        pytest.skip("no frame-0 source expectations")

    body = client.get(
        f"/api/source/{api_session.session_id}/0").get_json()
    assert exp.frame0_source_file in body["file"]
    if exp.frame0_source_line is not None:
        assert body["target_line"] == exp.frame0_source_line
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
    if not exp.named_frames:
        pytest.skip("no named-frame expectations")

    meta = client.get(f"/api/session/{api_session.session_id}").get_json()
    frames = meta["frames"]
    image_base = meta["crash_summary"]["image_base"]

    for idx, expected_symbol in exp.named_frames.items():
        if idx >= len(frames):
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
                if expected_symbol in body["symbol"]:
                    hit = body
                    break
        assert hit is not None, (
            f"frame {idx} ({expected_symbol}) did not resolve via "
            f"/api/resolve from any of {[hex(a) for a in candidates]}")
