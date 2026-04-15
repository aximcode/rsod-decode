"""Unit tests for the hand-packed Windows minidump writer.

The layout tests verify ``write_minidump`` emits the exact byte layout
LLVM's minidump parser accepts: LLVM ``MagicVersion`` (``0xA793`` in the
low 16 bits of ``Header.Version``), four streams in the directory, a
1232-byte ``CONTEXT_AMD64`` blob with integer registers at the correct
offsets, and a ``Memory64List`` range covering the stack dump.

The LoadCore smoke test drives the writer end-to-end through
``SBTarget.LoadCore`` against the ``psa_x64_forcecrash`` fixture — the
same ground truth the refactor's accepance tests use.
"""
from __future__ import annotations

import struct
from pathlib import Path
from types import ModuleType

import pytest

from rsod_decode.lldb_loader import import_lldb
from rsod_decode.minidump import (
    CONTEXT_AMD64_SIZE,
    MDMP_SIGNATURE,
    MDMP_VERSION,
    STREAM_MEMORY64_LIST,
    STREAM_MODULE_LIST,
    STREAM_SYSTEM_INFO,
    STREAM_THREAD_LIST,
    write_minidump,
)

FIXTURE_DIR = (
    Path(__file__).parent / 'fixtures' / 'psa_x64_forcecrash')
PE_PATH = FIXTURE_DIR / 'psa_x64.efi'
PDB_PATH = FIXTURE_DIR / 'psa_x64.pdb'
RSOD_PATH = FIXTURE_DIR / 'rsod_psa_x64.txt'

# A realistic register set — matches what analyze_rsod() extracts from
# rsod_psa_x64.txt for this fixture. Pinning these values in the test
# means the byte-layout assertions don't need a live RSOD parse.
PSA_REGS: dict[str, int] = {
    'RIP': 0x18000618A,
    'RSP': 0x25FFF108,
    'RBP': 0x2F412F28,
    'RAX': 0x0,
    'RBX': 0x2F412F00,
    'RCX': 0xD,
    'RDX': 0xFF98,
    'RSI': 0x1800F745B,
    'RDI': 0x3,
    'R8':  0x180193C88,
    'R9':  0x28,
    'R10': 0xFFFFFFFEAFBDF420,
    'R11': 0x25FFF090,
    'R12': 0x0,
    'R13': 0x2F4A4E20,
    'R14': 0x2F412F30,
    'R15': 0x68,
    'RFLAGS': 0x202,
}
PSA_STACK_BASE = 0x25FFF108
PSA_IMAGE_BASE = 0x180000000


def _lldb_or_skip() -> ModuleType:
    lldb = import_lldb()
    if lldb is None:
        pytest.skip('lldb Python module not available')
    return lldb


def _sample_stack() -> bytes:
    """4 KB of recognizable filler so memory-read checks have targets."""
    return bytes(range(256)) * 16  # 4096 bytes


def _require_pe_fixture() -> None:
    if not PE_PATH.exists():
        pytest.skip('psa_x64_forcecrash.efi fixture not present')


def test_minidump_header_and_directory(tmp_path: Path) -> None:
    _require_pe_fixture()
    out = write_minidump(
        PSA_REGS, PSA_STACK_BASE, _sample_stack(),
        PE_PATH, PSA_IMAGE_BASE, tmp_path / 'test.dmp',
    )
    blob = out.read_bytes()

    sig, version, num_streams, dir_rva = struct.unpack_from(
        '<IIII', blob, 0)
    assert sig == MDMP_SIGNATURE, f'bad signature 0x{sig:x}'
    assert version == MDMP_VERSION
    # LLVM parser check: (version & 0xFFFF) must equal MagicVersion.
    assert (version & 0xFFFF) == 0xA793
    assert num_streams == 4
    assert dir_rva == 32

    # Directory entries are {u32 type, u32 size, u32 rva}.
    types = []
    for i in range(4):
        stype, size, rva = struct.unpack_from(
            '<III', blob, dir_rva + i * 12)
        types.append(stype)
        assert size > 0
        assert rva >= 32 + 4 * 12
        assert rva + size <= len(blob)
    assert set(types) == {
        STREAM_SYSTEM_INFO,
        STREAM_THREAD_LIST,
        STREAM_MODULE_LIST,
        STREAM_MEMORY64_LIST,
    }


def test_minidump_context_amd64_registers(tmp_path: Path) -> None:
    _require_pe_fixture()
    out = write_minidump(
        PSA_REGS, PSA_STACK_BASE, _sample_stack(),
        PE_PATH, PSA_IMAGE_BASE, tmp_path / 'test.dmp',
    )
    blob = out.read_bytes()

    # Locate the ThreadList stream to find ThreadContext.Rva.
    _sig, _ver, _n, dir_rva = struct.unpack_from('<IIII', blob, 0)
    thread_list_rva = None
    for i in range(4):
        stype, _size, rva = struct.unpack_from(
            '<III', blob, dir_rva + i * 12)
        if stype == STREAM_THREAD_LIST:
            thread_list_rva = rva
            break
    assert thread_list_rva is not None

    # MINIDUMP_THREAD starts after the u32 count, ThreadContext descriptor
    # sits at offset 40 within the 48-byte record (after the 16-byte Stack
    # MINIDUMP_MEMORY_DESCRIPTOR).
    ctx_size, ctx_rva = struct.unpack_from(
        '<II', blob, thread_list_rva + 4 + 40)
    assert ctx_size == CONTEXT_AMD64_SIZE
    assert ctx_rva + ctx_size <= len(blob)

    # Integer registers — offsets from winnt.h CONTEXT_AMD64.
    checks = [
        (0x78, 'RAX'), (0x80, 'RCX'), (0x88, 'RDX'), (0x90, 'RBX'),
        (0x98, 'RSP'), (0xA0, 'RBP'), (0xA8, 'RSI'), (0xB0, 'RDI'),
        (0xB8, 'R8'),  (0xC0, 'R9'),  (0xC8, 'R10'), (0xD0, 'R11'),
        (0xD8, 'R12'), (0xE0, 'R13'), (0xE8, 'R14'), (0xF0, 'R15'),
        (0xF8, 'RIP'),
    ]
    for off, name in checks:
        got, = struct.unpack_from('<Q', blob, ctx_rva + off)
        expected = PSA_REGS[name] & 0xFFFFFFFFFFFFFFFF
        assert got == expected, f'{name}: got 0x{got:x}, want 0x{expected:x}'


def test_minidump_memory64_covers_stack(tmp_path: Path) -> None:
    _require_pe_fixture()
    stack = _sample_stack()
    out = write_minidump(
        PSA_REGS, PSA_STACK_BASE, stack,
        PE_PATH, PSA_IMAGE_BASE, tmp_path / 'test.dmp',
    )
    blob = out.read_bytes()

    _sig, _ver, _n, dir_rva = struct.unpack_from('<IIII', blob, 0)
    mem_rva = None
    for i in range(4):
        stype, _size, rva = struct.unpack_from(
            '<III', blob, dir_rva + i * 12)
        if stype == STREAM_MEMORY64_LIST:
            mem_rva = rva
            break
    assert mem_rva is not None

    count, base_rva = struct.unpack_from('<QQ', blob, mem_rva)
    assert count == 1
    start, size = struct.unpack_from('<QQ', blob, mem_rva + 16)
    assert start == PSA_STACK_BASE
    assert size == len(stack)
    assert blob[base_rva:base_rva + size] == stack


@pytest.mark.lldb
def test_minidump_load_core_smoke(tmp_path: Path) -> None:
    """End-to-end: the packed minidump loads in LLDB as a live process.

    The assertion suite mirrors the probe recommendation: LoadCore must
    succeed, the thread unwinder must produce >=4 frames, and frame 1
    (``initialize_test``) must expose the ``ctx`` local struct with a
    ``depth=1`` child — the ground truth from the forcecrash fixture.
    """
    lldb = _lldb_or_skip()
    if not PE_PATH.exists() or not PDB_PATH.exists():
        pytest.skip('psa_x64_forcecrash PE/PDB fixture not present')

    # Parse the real RSOD so we feed LLDB the same registers/stack
    # the decoder would.
    from rsod_decode.decoder import analyze_rsod
    from rsod_decode.symbols import load_symbols

    source = load_symbols(PE_PATH, pdb_path=PDB_PATH)
    result = analyze_rsod(
        RSOD_PATH.read_text(encoding='utf-8', errors='replace'),
        source)
    regs = result.crash_info.registers
    assert regs, 'no registers parsed from RSOD fixture'

    dump_path = tmp_path / 'psa_x64.dmp'
    write_minidump(
        regs, result.stack_base, result.stack_mem,
        PE_PATH, result.crash_info.image_base or PSA_IMAGE_BASE,
        dump_path)

    dbg = lldb.SBDebugger.Create()
    dbg.SetAsync(False)
    ci = dbg.GetCommandInterpreter()
    ro = lldb.SBCommandReturnObject()
    ci.HandleCommand(f'target create --arch x86_64 {PE_PATH}', ro)
    assert ro.Succeeded(), ro.GetError()
    ci.HandleCommand(f'target symbols add "{PDB_PATH}"', ro)
    assert ro.Succeeded(), ro.GetError()

    target = dbg.GetSelectedTarget()
    err = lldb.SBError()
    process = target.LoadCore(str(dump_path), err)
    assert err.Success(), f'LoadCore failed: {err.GetCString()}'
    assert process.IsValid()
    assert process.GetNumThreads() >= 1

    thread = process.GetThreadAtIndex(0)
    assert thread.GetNumFrames() >= 4

    init_frame = None
    for i in range(thread.GetNumFrames()):
        frame = thread.GetFrameAtIndex(i)
        if (frame.GetFunctionName() or '') == 'initialize_test':
            init_frame = frame
            break
    assert init_frame is not None, (
        'initialize_test not in backtrace — unwinder broken')

    # Walk GetVariables and pick the entry with a real load address;
    # FindVariable('ctx') picks a range-scoped ghost that reads None.
    good_ctx = None
    for v in init_frame.GetVariables(True, True, False, True):
        if (v.GetName() == 'ctx'
                and v.GetLoadAddress() != 0xFFFFFFFFFFFFFFFF):
            good_ctx = v
            break
    assert good_ctx is not None, 'ctx not resolvable in initialize_test'

    depth = None
    for idx in range(good_ctx.GetNumChildren()):
        child = good_ctx.GetChildAtIndex(idx)
        if child.GetName() == 'depth':
            depth = child.GetValue()
            break
    assert depth == '1', (
        f'ground-truth check: ctx.depth={depth!r}, want "1"')
