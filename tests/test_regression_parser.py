from __future__ import annotations

import pytest

from ._datasets import DatasetRun


pytestmark = [pytest.mark.parser]


def test_parser_expected_metrics(dataset_run: DatasetRun) -> None:
    spec = dataset_run.spec
    result = dataset_run.result

    assert result.rsod_format == spec.expected_format
    assert len(result.frames) == spec.expected_frames
    assert result.resolved_count == spec.expected_resolved
    assert len(result.modules) == spec.expected_modules
    assert len(result.crash_info.v_registers) == spec.expected_vregs
    assert len(result.stack_mem) == spec.expected_stack_size
    assert len(result.crash_info.lbr) == spec.expected_lbr


def test_parser_frame_zero_shape(dataset_run: DatasetRun) -> None:
    if not dataset_run.result.frames:
        pytest.skip("fixture has no frames (RSOD lacks a stack trace)")
    frame0 = dataset_run.result.frames[0]

    assert frame0.index == 0
    assert frame0.is_crash_frame is True
    assert frame0.address > 0
    assert frame0.module


def test_dell_aa64_image_base_regression(load_dataset_run) -> None:
    run = load_dataset_run("dell_aa64")
    assert run.result.crash_info.image_base == 0x782B122000


def test_stack_and_sp_preconditions(dataset_run: DatasetRun) -> None:
    result = dataset_run.result

    assert result.stack_base > 0
    assert len(result.stack_mem) > 0

    regs = result.crash_info.registers
    assert "SP" in regs or "RSP" in regs


@pytest.mark.lldb
def test_psa_x64_forcecrash_symbols_from_pdb_only() -> None:
    """load_symbols(.efi, pdb_path=.pdb) — no .map.

    Exercises the LLDB-driven PDB symbol enumerator in symbols.py so
    users can upload just `.efi + .pdb` (no `.map`) and still get a
    resolving backtrace. Asserts that the key forcecrash hook
    functions are present and that analyze_rsod resolves frame 1 to
    initialize_test using only the PDB-derived table.
    """
    from pathlib import Path
    from rsod_decode.lldb_loader import import_lldb
    from rsod_decode.symbols import load_symbols
    from rsod_decode.decoder import analyze_rsod

    if import_lldb() is None:
        pytest.skip("lldb Python module not available")

    base = Path(__file__).parent / "fixtures" / "psa_x64_forcecrash"
    pe = base / "psa_x64.efi"
    pdb = base / "psa_x64.pdb"
    rsod = base / "rsod_psa_x64.txt"
    if not pdb.exists():
        pytest.skip("psa_x64_forcecrash.pdb not present")

    source = load_symbols(pe, pdb_path=pdb)
    # The PDB CU iteration should find several thousand functions.
    assert len(source.table.symbols) >= 1000
    assert source.table.preferred_base == 0x180000000

    # Key functions the decoder needs for the forcecrash backtrace
    for addr, expected in (
        (0x18000618a, 'trigger_gp_fault'),
        (0x180006100, 'initialize_test'),
        (0x180005afc, 'fForceCrashIfRequested'),
    ):
        hit = source.table.lookup(addr)
        assert hit is not None and hit[0].name == expected, \
            f'lookup 0x{addr:x} -> {hit}'

    # End-to-end: analyze_rsod should still find the real frames.
    result = analyze_rsod(
        rsod.read_text(encoding='utf-8', errors='replace'), source)
    symbols = [f.symbol.name for f in result.frames if f.symbol is not None]
    assert 'initialize_test' in symbols
    assert 'fForceCrashIfRequested' in symbols


@pytest.mark.lldb
def test_psa_x64_forcecrash_cli_pdb_routing(tmp_path) -> None:
    """decode_rsod must thread a .pdb extra through to load_symbols.

    Regression pin for the CLI path: prior to the fix, `rsod-decode
    rsod.txt psa_x64.efi -s psa_x64.pdb` ignored the .pdb and returned
    0 symbols. Exercises decode_rsod end-to-end (not just analyze_rsod)
    to cover the PDB-routing branch in decoder.decode_rsod.
    """
    from pathlib import Path
    from rsod_decode.lldb_loader import import_lldb
    from rsod_decode.decoder import decode_rsod

    if import_lldb() is None:
        pytest.skip("lldb Python module not available")

    base = Path(__file__).parent / "fixtures" / "psa_x64_forcecrash"
    pdb = base / "psa_x64.pdb"
    if not pdb.exists():
        pytest.skip("psa_x64_forcecrash.pdb not present")

    out = tmp_path / "out.txt"
    decode_rsod(
        log_path=base / "rsod_psa_x64.txt",
        sym_path=base / "psa_x64.efi",
        out_path=out,
        base_override=None,
        verbose=False,
        extra_sym_paths=[pdb],
        source_root=None,
    )
    text = out.read_text()
    assert 'initialize_test' in text
    assert 'fForceCrashIfRequested' in text


def test_psa_x64_pe_backend_ready(load_dataset_run) -> None:
    """The MSVC/EPSA psa_x64 fixture should load via PEBinary + .map and
    expose a working disassembler + call-site checker, regardless of
    whether the decoder managed to extract frames from the RSOD text."""
    from rsod_decode.pe_backend import PEBinary

    run = load_dataset_run("psa_x64")
    binary = run.source.binary
    assert isinstance(binary, PEBinary)
    assert binary.arch == "x86_64"
    assert binary.image_base == 0x180000000
    assert len(run.source.table.symbols) > 10000
    assert run.source.table.preferred_base == 0x180000000

    # fGndBounce lives at 0x180001600; the crash RIP (runtime 0x01001696
    # = preferred-base 0x180001696) is inside it. Disassembling around
    # that address should return real instructions.
    insns = binary.disassemble_around(0x180001696, context=16)
    assert len(insns) > 0
    assert all(m for _, m, _ in insns)

    # A return address that follows a `call` in the .text should verify.
    # 0x180031ba1 is taken from the stack dump and is known to satisfy
    # is_call_before() for this build.
    assert binary.is_call_before(0x180031BA1) is True


def test_pe_backend_arm64() -> None:
    """Smoke test PEBinary against an ARM64 PE file from uefi-devkit's
    CrashTest. Exercises the aarch64 capstone path through the shared
    disasm helpers so both x86-64 and ARM64 stay regression-covered."""
    from rsod_decode.pe_backend import PEBinary
    from ._datasets import FIXTURES_DIR

    pe_path = FIXTURES_DIR / "pe_aa64_crashtest.efi"
    binary = PEBinary(pe_path)
    try:
        assert binary.arch == "aarch64"
        # EDK2 AArch64 builds set ImageBase=0; .text starts after the
        # PE headers (~0x4000 for this toolchain).
        assert binary.image_base == 0
        assert len(binary._text_data) > 0
        assert binary._text_addr > 0

        # Disassemble a window inside .text and confirm capstone emits
        # valid ARM64 instructions (4-byte fixed length).
        probe_addr = binary._text_addr + 0x200
        insns = binary.disassemble_around(probe_addr, context=16)
        assert len(insns) > 0
        for addr, mnemonic, _ in insns:
            assert mnemonic, f"empty mnemonic at 0x{addr:x}"
            assert addr % 4 == 0, (
                f"ARM64 instructions must be 4-byte aligned; got 0x{addr:x}")

        # Find at least one bl/blr in .text and verify is_call_before()
        # returns True for the address right after it.
        call_mnems = {"bl", "blr"}
        found_call = False
        for insn in binary._cs.disasm(
                binary._text_data[:0x4000], binary._text_addr):
            if insn.mnemonic in call_mnems:
                after_call = insn.address + insn.size
                assert binary.is_call_before(after_call) is True
                found_call = True
                break
        assert found_call, "no call instruction found in first 16 KB of .text"
    finally:
        binary.close()


def test_psa_x64_forcecrash_ground_truth(load_dataset_run) -> None:
    """Strict assertions against the deterministic EPSA forcecrash fixture.

    Source-level ground-truth values come from
    tests/fixtures/psa_x64_forcecrash/BUILD.md — the -forcecrash hook in
    PsaEntry.c and the adapted crashtest.c generator set every struct
    field to a known magic value, so the decoded backtrace, LBR, and
    image base can be pinned exactly without worrying about build drift.
    """
    run = load_dataset_run("psa_x64_forcecrash")
    result = run.result
    crash = result.crash_info

    # Exception kind: #GP (13) from -forcecrash gp
    assert "General Protection Fault" in crash.exception_desc
    assert "13" in crash.exception_desc

    # Faulting PC must resolve to trigger_gp_fault. The actual fault is
    # at +2 (the store to the non-canonical address) — we care about
    # the function name, not the exact offset.
    assert crash.crash_symbol == "trigger_gp_fault"
    assert crash.crash_pc == 0x18000618A

    # No relocation for this build — linked base == load base.
    assert crash.image_base == 0x180000000

    # The LBR one-frame hint pairs the last branch source and target.
    # Source lives inside dispatch_crash (the tail-call jmp to
    # trigger_gp_fault) and target lands on trigger_gp_fault's entry.
    lbr_by_type = {e["type"]: e for e in crash.lbr}
    assert "LBRfr0" in lbr_by_type, f"LBR missing LBRfr0: {crash.lbr}"
    assert "LBRto0" in lbr_by_type, f"LBR missing LBRto0: {crash.lbr}"

    lbr_from = run.source.table.lookup(lbr_by_type["LBRfr0"]["addr"])
    assert lbr_from is not None
    assert lbr_from[0].name == "dispatch_crash"

    lbr_to = run.source.table.lookup(lbr_by_type["LBRto0"]["addr"])
    assert lbr_to is not None
    assert lbr_to[0].name == "trigger_gp_fault"

    # Walked stack: at least one frame must resolve to initialize_test
    # (it owns `CrashContext ctx` so MSVC can't tail-call it) and at
    # least one must resolve to fForceCrashIfRequested (the EPSA entry
    # gate for -forcecrash). Tail-called functions (prepare_crash_context,
    # validate_environment, dispatch_crash) won't appear as frames.
    frame_syms = {
        f.symbol.name for f in result.frames if f.symbol is not None
    }
    assert "initialize_test" in frame_syms, f"frames: {frame_syms}"
    assert "fForceCrashIfRequested" in frame_syms, f"frames: {frame_syms}"

    # Ground-truth CrashContext/CrashTestConfig struct values are
    # asserted through the public /api/expand endpoint in
    # tests/test_regression_api.py::test_psa_x64_forcecrash_ground_truth_via_api
    # — keeping the parser-level assertions (above) separate from the
    # PDB-backed LLDB path which requires the lldb Python module.
