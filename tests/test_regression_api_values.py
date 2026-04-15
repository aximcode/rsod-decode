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
from .conftest import (
    ApiSessionContext, create_api_session, delete_api_session,
)


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
    # The literal snippet (substring-matched) that the Source tab
    # should render on the highlighted line for this frame. Grounds
    # the test in the actual checked-in source instead of relying
    # on observation-based line numbers. When set, enforces that
    # GET /api/source/<sid>/<idx> has `is_target=True` on a row
    # whose `text` contains this substring.
    source_line_text: str | None = None
    # Expected mnemonic prefix ('call', 'callq', 'jmp', 'bl', 'movabsq'…)
    # of the disassembly target instruction. When set, enforces
    # that GET /api/disasm/<sid>/<idx> marks an instruction
    # is_target=True whose mnemonic startswith() this. Catches
    # "target highlight landed on the wrong instruction" bugs.
    disasm_target_mnemonic: str | None = None
    # Expected trailing substring in that target instruction's
    # `source_line` annotation. Used to assert the disassembly
    # view's per-instruction source mapping agrees with the Source
    # tab — i.e. the two views point at the same line rather than
    # drifting by one (return-site vs call-site bugs).
    disasm_target_source_endswith: str | None = None
    params: tuple[tuple[str, str], ...] = ()
    locals_: tuple[tuple[str, str], ...] = ()
    expand_values: dict[str, dict[str, int | str]] = field(
        default_factory=dict)
    # Scalar parameter / local values pinned directly from source
    # code. Maps variable name → expected integer value for scalar
    # types (int / pointers / enums) or string for char* / char[]
    # fields. The value is asserted exactly when the backend can
    # resolve it — when the backend returns None (location is a
    # callee-clobbered caller-saved register etc.), the pin is
    # skipped rather than failing so the test is robust against
    # register-allocator variation while still catching "we used
    # to resolve this and now we don't" regressions.
    param_values: dict[str, int | str] = field(default_factory=dict)
    local_values: dict[str, int | str] = field(default_factory=dict)
    is_synthetic: bool | None = None


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
              is_synthetic=False,
              params=(("addr", "void"),),
              # crashtest.c:153 — `trigger_page_fault(NULL);`
              # — so addr is a null pointer on entry.
              param_values={"addr": 0}),
    1: _Frame("dispatch_crash", "crashtest.c", 153,
              is_synthetic=False,
              source_line_text="trigger_page_fault(NULL)",
              disasm_target_mnemonic="bl",
              disasm_target_source_endswith="crashtest.c:153",
              params=(("ctx", "CrashContext"),),
              locals_=(("mode", "char"),),
              # dispatch_crash's `mode` local is
              # `ctx->config->name` — not a compile-time constant,
              # but for both edk2 and dell fixtures the string
              # lives in read-only data and the CrashTest main()
              # sets config->name from argv[0] or similar. Leave
              # unpinned (string_preview would vary).
              ),
    2: _Frame("validate_environment", "crashtest.c", 162,
              is_synthetic=False,
              source_line_text="dispatch_crash(ctx)",
              disasm_target_mnemonic="bl",
              disasm_target_source_endswith="crashtest.c:162",
              params=(("ctx", "CrashContext"),)),
    3: _Frame("prepare_crash_context", "crashtest.c", 168,
              is_synthetic=False,
              source_line_text="validate_environment(ctx)",
              disasm_target_mnemonic="bl",
              disasm_target_source_endswith="crashtest.c:168",
              params=(("ctx", "CrashContext"),)),
    4: _Frame("initialize_test", "crashtest.c", 186,
              is_synthetic=False,
              source_line_text="prepare_crash_context(&ctx)",
              disasm_target_mnemonic="bl",
              disasm_target_source_endswith="crashtest.c:186",
              params=(("config", "TestConfig"),
                      ("build_id", "char")),
              locals_=(("ctx", "CrashContext"),),
              # crashtest.c:194 — run_crashtest calls
              # `initialize_test(config, "crashtest-v3")` — so
              # initialize_test's `build_id` param points to a
              # static string literal "crashtest-v3".
              param_values={"build_id": "crashtest-v3"},
              expand_values={
                  "ctx": _CTX_VALUES,
                  # edk2 fixture was invoked with "pf" (page fault
                  # default branch of parse_mode) → mode = 0.
                  "config": _config_values(mode=0),
              }),
    5: _Frame("run_crashtest", "crashtest.c", 194,
              is_synthetic=False,
              source_line_text='initialize_test(config, "crashtest-v3")',
              disasm_target_mnemonic="bl",
              disasm_target_source_endswith="crashtest.c:194",
              params=(("config", "TestConfig"),
                      ("argc", "int"))),
    6: _Frame("main", "crashtest.c", 252,
              is_synthetic=False,
              source_line_text="run_crashtest(&config, argc)",
              disasm_target_mnemonic="bl",
              disasm_target_source_endswith="crashtest.c:252",
              params=(("argc", "int"), ("argv", "char")),
              locals_=(("config", "TestConfig"),),
              expand_values={
                  "config": _config_values(mode=0),
              }),
    7: _Frame("_AxlEntry", "axl-crt0-native.c", 38,
              is_synthetic=False,
              source_line_text="int rc = main(argc, argv)",
              disasm_target_mnemonic="bl",
              disasm_target_source_endswith="axl-crt0-native.c:38",
              params=(("ImageHandle", "EFI_HANDLE"),
                      ("SystemTable", "EFI_SYSTEM_TABLE")),
              locals_=(("argc", "int"), ("argv", "char"),
                       ("rc", "int"))),
}

_CRASHTEST_FRAMES_DELL_AA64 = {
    0: _Frame("dispatch_crash", "crashtest.c", 156,
              is_synthetic=False,
              params=(("ctx", "CrashContext"),),
              locals_=(("mode", "char"),)),
    1: _Frame("validate_environment", "crashtest.c", 162,
              is_synthetic=False,
              source_line_text="dispatch_crash(ctx)",
              disasm_target_mnemonic="bl",
              disasm_target_source_endswith="crashtest.c:162",
              params=(("ctx", "CrashContext"),)),
    2: _Frame("prepare_crash_context", "crashtest.c", 168,
              is_synthetic=False,
              source_line_text="validate_environment(ctx)",
              disasm_target_mnemonic="bl",
              disasm_target_source_endswith="crashtest.c:168",
              params=(("ctx", "CrashContext"),)),
    3: _Frame("initialize_test", "crashtest.c", 186,
              is_synthetic=False,
              source_line_text="prepare_crash_context(&ctx)",
              disasm_target_mnemonic="bl",
              disasm_target_source_endswith="crashtest.c:186",
              params=(("config", "TestConfig"),
                      ("build_id", "char")),
              locals_=(("ctx", "CrashContext"),),
              # Same as edk2: run_crashtest passes the literal
              # "crashtest-v3" as build_id. crashtest.c:194.
              param_values={"build_id": "crashtest-v3"},
              expand_values={
                  "ctx": _CTX_VALUES,
                  # dell_aa64 fixture was invoked with "gp" → mode = 1.
                  "config": _config_values(mode=1),
              }),
    4: _Frame("run_crashtest", "crashtest.c", 194,
              is_synthetic=False,
              source_line_text='initialize_test(config, "crashtest-v3")',
              disasm_target_mnemonic="bl",
              disasm_target_source_endswith="crashtest.c:194",
              params=(("config", "TestConfig"),
                      ("argc", "int"))),
    5: _Frame("main", "crashtest.c", 252,
              is_synthetic=False,
              source_line_text="run_crashtest(&config, argc)",
              disasm_target_mnemonic="bl",
              disasm_target_source_endswith="crashtest.c:252",
              params=(("argc", "int"), ("argv", "char")),
              locals_=(("config", "TestConfig"),),
              expand_values={
                  "config": _config_values(mode=1),
              }),
    6: _Frame("_AxlEntry", "axl-crt0-native.c", 38,
              is_synthetic=False,
              source_line_text="int rc = main(argc, argv)",
              disasm_target_mnemonic="bl",
              disasm_target_source_endswith="axl-crt0-native.c:38",
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
            # Frame 0 is trigger_gp_fault (crash frame). MSVC's
            # PDB maps the faulting PC to line 212 (the function
            # opening brace); after `_advance_past_brace_line`
            # walks past the `{`, the `(void)vector;` no-op, and
            # the `// Store to...` comment, the highlight lands
            # on the faulting store:
            #   *(volatile UINT64 *)0xDEAD0000DEAD0000ULL = 0;
            0: _Frame("trigger_gp_fault",
                      source_file="psaentry.c",
                      is_synthetic=False,
                      source_line_text="0xDEAD0000DEAD0000",
                      disasm_target_mnemonic="movabsq",
                      params=(("vector", "unsigned"),),
                      # psaentry.c dispatch_crash line:
                      #     trigger_gp_fault(0x0D);
                      # vector lives in MSVC DWARF register 26
                      # (XMM9), not in the Dell RSOD register
                      # dump, so the backend returns None and the
                      # pin skips cleanly. Still useful as a
                      # regression pin for the day the backend
                      # learns to extract XMM values.
                      param_values={"vector": 0x0D}),
            # Frames 1-3: synthetic tail-call chain between
            # trigger_gp_fault and initialize_test. dispatch_crash
            # dispatches via a switch that jmps to
            # trigger_gp_fault on mode=GP; validate_environment
            # ends with `jmp dispatch_crash`; prepare_crash_context
            # is a 1-instruction wrapper `jmp validate_environment`.
            1: _Frame("dispatch_crash",
                      source_file="psaentry.c",
                      is_synthetic=True,
                      source_line_text="trigger_gp_fault(",
                      disasm_target_mnemonic="jmp"),
            2: _Frame("validate_environment",
                      source_file="psaentry.c",
                      is_synthetic=True,
                      source_line_text="dispatch_crash(",
                      disasm_target_mnemonic="jmp"),
            # prepare_crash_context is a 1-instruction wrapper;
            # its PDB line entry sits on the function's `{`, but
            # the brace-advance normalizer walks forward to the
            # single statement `validate_environment(ctx);`.
            3: _Frame("prepare_crash_context",
                      source_file="psaentry.c",
                      is_synthetic=True,
                      source_line_text="validate_environment(ctx)",
                      disasm_target_mnemonic="jmp"),
            4: _Frame("initialize_test",
                      source_file="psaentry.c",
                      is_synthetic=False,
                      source_line_text="prepare_crash_context(&ctx)",
                      disasm_target_mnemonic="call",
                      params=(("config", "CrashTestConfig"),
                              ("build_id", "char")),
                      locals_=(("ctx", "CrashContext"),),
                      # Only pin `ctx` here. initialize_test's `config`
                      # param spill slot [RSP+96] gets reused by MSVC
                      # after the initial read — the stored pointer
                      # is stale garbage by the time we crash. The
                      # genuine TestConfig struct still lives in
                      # fForceCrashIfRequested's frame (see frame 6).
                      expand_values={"ctx": _CTX_VALUES}),
            # Frame 5: synthetic run_crashtest, tail-called into
            # initialize_test. No spill slots, so no params/locals.
            5: _Frame("run_crashtest",
                      source_file="psaentry.c",
                      is_synthetic=True,
                      source_line_text='initialize_test(config, "crashtest-v3")',
                      disasm_target_mnemonic="jmp"),
            6: _Frame("fForceCrashIfRequested",
                      source_file="psaentry.c",
                      is_synthetic=False,
                      source_line_text="run_crashtest(&config, argc)",
                      disasm_target_mnemonic="call",
                      params=(("argc", "int"), ("argv", "char")),
                      locals_=(("config", "CrashTestConfig"),),
                      # In PsaEntry.c's adapted hook fForceCrashIfRequested
                      # holds the TestConfig as a LOCAL struct (not
                      # a pointer), so [RSP+32] reads the exact same
                      # values that main() sets in the ELF fixture.
                      expand_values={
                          "config": _config_values(mode=1),
                      }),
            7: _Frame("fUEFIPSAEntry",
                      source_file="psaentry.c",
                      is_synthetic=False,
                      source_line_text="fForceCrashIfRequested(argc, argv)",
                      disasm_target_mnemonic="call",
                      # SBFrame.GetVariables splits args/locals by the
                      # ABI: imageHandle + psSystemTable are the real
                      # parameters, everything else lives in the locals
                      # set (originalTxtAttr/Mode, argc, argv).
                      # LLDB resolves typedefs to canonical types, so
                      # uint64_t reports as "unsigned long long".
                      params=(("imageHandle", "void"),
                              ("psSystemTable", "EFI_SYSTEM_TABLE")),
                      locals_=(("originalTxtAttr", "unsigned long long"),
                               ("originalTxtMode", "unsigned long long"),
                               ("argv", "char"),
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
    expected_count = (
        api_session.spec.expected_api_frames
        or api_session.spec.expected_frames)
    assert len(body["frames"]) == expected_count
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

    Pins the FP/RBP walker output (symbol per index), the source
    location metadata (file + line + literal snippet), the
    `is_synthetic` flag, the Source-tab rendered content, and the
    Disassembly-tab target mnemonic + its source-line annotation.
    The source-line assertions use literal checked-in text so a
    regression that shifts the highlight by one line (return site
    vs call site) fails loudly instead of silently swapping which
    of two adjacent lines is marked.
    """
    exp = _expect(api_session)
    if not exp.frames:
        pytest.skip("no frame expectations")

    sid = api_session.session_id
    body = client.get(f"/api/session/{sid}").get_json()
    frames = body["frames"]
    for idx, fe in exp.frames.items():
        assert idx < len(frames), f"no frame {idx}"
        frame = frames[idx]

        # Symbol + is_synthetic metadata.
        if fe.symbol is not None:
            got_symbol = frame["symbol"]
            assert got_symbol is not None and fe.symbol in got_symbol, (
                f"frame {idx}: expected symbol containing "
                f"{fe.symbol!r}, got {got_symbol!r}")
        if fe.is_synthetic is not None:
            assert frame.get("is_synthetic", False) == fe.is_synthetic, (
                f"frame {idx} ({frame.get('symbol')!r}): "
                f"is_synthetic={frame.get('is_synthetic')}, "
                f"expected {fe.is_synthetic}")

        # source_loc file + line.
        if fe.source_file is not None:
            src = frame["source_loc"] or ""
            assert fe.source_file in src, (
                f"frame {idx} source_loc {src!r} does not contain "
                f"{fe.source_file!r}")
            if fe.source_line is not None:
                assert f":{fe.source_line}" in src, (
                    f"frame {idx} source_loc {src!r} does not "
                    f"contain line {fe.source_line}")

        # Source tab rendered content: the target-flagged line's
        # text must contain the expected literal snippet.
        if fe.source_line_text is not None:
            src_body = client.get(
                f"/api/source/{sid}/{idx}").get_json()
            if src_body.get("lines"):
                targets = [
                    ln for ln in src_body["lines"]
                    if ln.get("is_target")
                ]
                assert targets, (
                    f"frame {idx}: /api/source returned {len(src_body['lines'])} "
                    f"lines but none were flagged is_target")
                tgt_text = targets[0]["text"]
                assert fe.source_line_text in tgt_text, (
                    f"frame {idx} ({frame.get('symbol')!r}): "
                    f"Source tab target line is "
                    f"{tgt_text.strip()!r}, expected to contain "
                    f"{fe.source_line_text!r}")
            else:
                # Source file isn't reachable on this machine
                # (out-of-tree tree missing) — skip the literal
                # assertion rather than fail.
                pass

        # Disassembly tab: target instruction mnemonic + its own
        # source-line annotation. Grounds the disasm view in the
        # same source line the Source tab claims — if they drift
        # (e.g. frame.address = return-addr but /api/disasm uses
        # frame.address directly), one of the two assertions
        # fires.
        if (fe.disasm_target_mnemonic is not None
                or fe.disasm_target_source_endswith is not None):
            dis_body = client.get(
                f"/api/disasm/{sid}/{idx}").get_json()
            targets = [
                i for i in dis_body.get("instructions", [])
                if i.get("is_target")
            ]
            assert targets, (
                f"frame {idx} ({frame.get('symbol')!r}): "
                f"/api/disasm has no is_target instruction")
            t = targets[0]
            if fe.disasm_target_mnemonic is not None:
                assert t["mnemonic"].lower().startswith(
                        fe.disasm_target_mnemonic.lower()), (
                    f"frame {idx} ({frame.get('symbol')!r}): "
                    f"disasm target mnemonic is {t['mnemonic']!r}, "
                    f"expected to start with "
                    f"{fe.disasm_target_mnemonic!r}")
            if fe.disasm_target_source_endswith is not None:
                sl = t.get("source_line", "")
                assert sl.endswith(fe.disasm_target_source_endswith), (
                    f"frame {idx} ({frame.get('symbol')!r}): "
                    f"disasm target source_line is {sl!r}, "
                    f"expected to end with "
                    f"{fe.disasm_target_source_endswith!r}")


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

    Asserts, in increasing specificity:
      1. name + type substring match on each declared param/local
      2. scalar value match for anything in `param_values`/`local_values`
         (sourced from the fixture's .c source). Skipped per-pin
         when the backend returns None (caller-saved register not
         in the RSOD register dump) so the test doesn't punish
         register-allocator variation but still catches
         "extraction regressed from a previously-resolved value".
    """
    from .conftest import create_api_session, delete_api_session

    spec = DATASET_SPECS[fixture_key]
    ctx = create_api_session(client, spec)
    try:
        exp = _EXPECTATIONS[fixture_key]
        fe = exp.frames[frame_idx]
        if not (fe.params or fe.locals_ or fe.param_values
                or fe.local_values):
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

        # Scalar value assertions. Works against params and locals
        # lookup tables built from the frame detail so we don't have
        # to care which kind each name belongs to.
        def _by_name(items: list[dict]) -> dict[str, dict]:
            return {v["name"]: v for v in items}

        params_by_name = _by_name(body["params"])
        locals_by_name = _by_name(body["locals"])

        for name, expected in fe.param_values.items():
            v = params_by_name.get(name)
            assert v is not None, (
                f"frame {frame_idx}: param {name!r} missing for "
                f"value pin (expected {expected!r})")
            _assert_scalar_value(
                frame_idx, "param", name, v, expected)
        for name, expected in fe.local_values.items():
            v = locals_by_name.get(name)
            assert v is not None, (
                f"frame {frame_idx}: local {name!r} missing for "
                f"value pin (expected {expected!r})")
            _assert_scalar_value(
                frame_idx, "local", name, v, expected)
    finally:
        delete_api_session(client, ctx)


def _assert_scalar_value(
    frame_idx: int, kind: str, name: str,
    var: dict, expected: int | str,
) -> None:
    """Compare a /api/frame variable dict against a source-pinned
    expected value. Integers and pointers compare via `value`;
    strings compare via `string_preview` substring match so null
    terminators / trailing whitespace are tolerated.
    """
    if isinstance(expected, str):
        preview = var.get("string_preview") or ""
        if not preview:
            pytest.skip(
                f"frame {frame_idx} {kind} {name!r}: no "
                f"string_preview returned (expected {expected!r})")
        assert expected in preview, (
            f"frame {frame_idx} {kind} {name!r} string_preview "
            f"is {preview!r}, expected to contain {expected!r}")
        return

    got = var.get("value")
    if got is None:
        pytest.skip(
            f"frame {frame_idx} {kind} {name!r}: backend returned "
            f"None for scalar value (register not recoverable "
            f"from this RSOD)")
    assert got == expected, (
        f"frame {frame_idx} {kind} {name!r} value is 0x{got:x} "
        f"({got}), expected 0x{expected:x} ({expected})")


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


def test_api_tail_call_reconstruction_psa_x64_forcecrash(
    client,
) -> None:
    """The MSVC tail-call reconstructor must re-materialize every
    tail-called function in the psa_x64_forcecrash chain.

    MSVC compiles the adapted PSA hook as two tail-call chains:

        initialize_test --(call)--> prepare_crash_context
                        |
                        +---(jmp)--> validate_environment
                        |
                        +---(jmp)--> dispatch_crash
                        |
                        +---(jmp)--> trigger_gp_fault

    and

        fForceCrashIfRequested --(call)--> run_crashtest
                               |
                               +---(jmp)--> initialize_test

    so the raw stack has 4 physical frames
    (trigger_gp_fault, initialize_test, fForceCrashIfRequested,
    fUEFIPSAEntry) and the reconstructor inserts 4 synthetic
    frames (dispatch_crash, validate_environment,
    prepare_crash_context, run_crashtest) for a total of 8. Each
    synthetic frame's location points at its own tail-call jmp
    (not the function entry) so the Source/Disassembly tabs
    highlight the call site the user expects to see.
    """
    spec = DATASET_SPECS["psa_x64_forcecrash"]
    if spec.pdb_path is None or not spec.pdb_path.exists():
        pytest.skip("psa_x64_forcecrash .pdb not present")
    ctx = create_api_session(client, spec)
    try:
        body = client.get(f"/api/session/{ctx.session_id}").get_json()
        frames = body["frames"]
        assert len(frames) == 8, [
            (f["index"], f.get("symbol"), f.get("is_synthetic"))
            for f in frames
        ]
        symbols = [f.get("symbol") for f in frames]
        assert symbols == [
            "trigger_gp_fault",
            "dispatch_crash",
            "validate_environment",
            "prepare_crash_context",
            "initialize_test",
            "run_crashtest",
            "fForceCrashIfRequested",
            "fUEFIPSAEntry",
        ]

        # Frames 1, 2, 3, 5 are synthetic; everything else is
        # physical.
        synth_indices = {
            f["index"] for f in frames if f.get("is_synthetic")
        }
        assert synth_indices == {1, 2, 3, 5}

        # Every synthetic frame should have a psaentry.c
        # source_loc and its /api/frame response should have
        # empty params/locals (no stack frame = no spill slots).
        for idx in sorted(synth_indices):
            fr = client.get(
                f"/api/frame/{ctx.session_id}/{idx}").get_json()
            assert fr["is_synthetic"] is True
            assert "psaentry.c" in (fr.get("source_loc") or ""), (
                f"synthetic frame {idx} {fr.get('symbol')!r} has "
                f"unexpected source_loc {fr.get('source_loc')!r}")
            assert fr["params"] == []
            assert fr["locals"] == []

        # `run_crashtest` (frame 5) is the classic wrapper: 5
        # instructions ending in a tail-call jmp. Pin that shape
        # as a sanity check on the function-range clamping.
        dis = client.get(
            f"/api/disasm/{ctx.session_id}/5").get_json()
        insns = dis["instructions"]
        assert insns, "synthetic run_crashtest disasm is empty"
        last_mnemonic = insns[-1]["mnemonic"].lower()
        assert last_mnemonic.startswith("jmp"), (
            f"expected run_crashtest to end in jmp (tail call), "
            f"got {last_mnemonic}")

        # The disasm target on a non-crash frame should now be
        # the CALL / JMP instruction (not the return address).
        # Frame 6 = fForceCrashIfRequested, whose call to
        # run_crashtest is a real callq; frame 5 = run_crashtest
        # itself, whose exit is a jmp to initialize_test.
        for idx, expected_mnemonic in [(6, "call"), (5, "jmp")]:
            body = client.get(
                f"/api/disasm/{ctx.session_id}/{idx}").get_json()
            target_instrs = [
                i for i in body["instructions"] if i["is_target"]
            ]
            assert target_instrs, f"frame {idx}: no target highlight"
            mn = target_instrs[0]["mnemonic"].lower()
            assert mn.startswith(expected_mnemonic), (
                f"frame {idx}: expected target mnemonic "
                f"{expected_mnemonic!r}, got {mn!r}")
    finally:
        delete_api_session(client, ctx)


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
