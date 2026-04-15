"""Generate a minimal Windows minidump for LLDB's ProcessMinidump plugin.

The PE+PDB path in :mod:`lldb_backend` feeds `SBTarget.LoadCore` a hand-
packed minidump so that LLDB unwinds via the PE's embedded `.pdata`
records, reads variables through SBValue, and auto-maps every PE section
from the on-disk `.efi` file. Only four streams are needed:

1. ``SystemInfo``    — architecture / OS identification
2. ``ThreadList``    — one thread with a ``CONTEXT_AMD64`` blob
3. ``ModuleList``    — one entry for the PE; makes LLDB file-back
                       ``.text``/``.rdata``/``.data``/``.pdata``/... from
                       the on-disk binary
4. ``Memory64List``  — one range covering the RSOD's stack dump

The total output is around 5.8 KB for a 4-KB stack dump.

Two LLVM-specific gotchas to note:

* ``MINIDUMP_HEADER.Version`` low 16 bits must be ``0xA793`` (LLVM's
  ``MagicVersion``), not the Windows ``MINIDUMP_VERSION = 42``. LLVM's
  parser in ``llvm/include/llvm/BinaryFormat/Minidump.h`` rejects the
  Windows value.
* The XMM save area is left zeroed. Dell RSODs do not capture XMM state,
  so MSVC-optimized params living in XMM registers (e.g. ``vector`` in
  ``trigger_gp_fault`` at ``DW_OP_reg26 XMM9``) remain unavailable — the
  same limitation as the old process-less path.
"""
from __future__ import annotations

import struct
from pathlib import Path

MDMP_SIGNATURE = 0x504D444D  # 'MDMP'
MDMP_VERSION = 0x0000A793    # LLVM MagicVersion (low 16 bits only)

STREAM_THREAD_LIST = 3
STREAM_MODULE_LIST = 4
STREAM_SYSTEM_INFO = 7
STREAM_MEMORY64_LIST = 9

_CONTEXT_AMD64 = 0x100000
_CONTEXT_CONTROL = _CONTEXT_AMD64 | 0x1
_CONTEXT_INTEGER = _CONTEXT_AMD64 | 0x2
_CONTEXT_SEGMENTS = _CONTEXT_AMD64 | 0x4
_CONTEXT_FLOATING_POINT = _CONTEXT_AMD64 | 0x8
_CONTEXT_FULL = (
    _CONTEXT_CONTROL | _CONTEXT_INTEGER
    | _CONTEXT_SEGMENTS | _CONTEXT_FLOATING_POINT
)

# sizeof(CONTEXT_AMD64) from winnt.h
CONTEXT_AMD64_SIZE = 1232

# MINIDUMP_HEADER (32 bytes) + 4 × MINIDUMP_DIRECTORY (12 bytes each)
_HEADER_SIZE = 32
_DIRECTORY_ENTRY_SIZE = 12
_NUM_STREAMS = 4

# MINIDUMP_THREAD: u32 id + u32 suspend + u32 priority_class +
# u32 priority + u64 teb + MINIDUMP_MEMORY_DESCRIPTOR (16 bytes) +
# MINIDUMP_LOCATION_DESCRIPTOR (8 bytes) = 48 bytes
_THREAD_RECORD_SIZE = 48

# MINIDUMP_MODULE: u64 base + u32 size + u32 checksum + u32 timestamp +
# u32 name_rva + 52 bytes VS_FIXEDFILEINFO + 2 × 8 bytes location
# descriptors + 16 bytes reserved = 108 bytes
_MODULE_RECORD_SIZE = 108


def _pack_context_amd64(registers: dict[str, int]) -> bytes:
    """Pack a 1232-byte ``CONTEXT_AMD64`` blob from a register dict.

    Offsets are from winnt.h ``CONTEXT``. Only GPRs, segment selectors,
    and EFLAGS are populated; the FP save area and debug registers are
    left zeroed.
    """
    buf = bytearray(CONTEXT_AMD64_SIZE)

    def put_u16(off: int, val: int) -> None:
        struct.pack_into('<H', buf, off, val & 0xFFFF)

    def put_u32(off: int, val: int) -> None:
        struct.pack_into('<I', buf, off, val & 0xFFFFFFFF)

    def put_u64(off: int, val: int) -> None:
        struct.pack_into('<Q', buf, off, val & 0xFFFFFFFFFFFFFFFF)

    put_u32(0x30, _CONTEXT_FULL)
    put_u32(0x34, 0x1F80)  # MxCsr

    # Segment selectors — Windows user-mode defaults. LLDB's unwinder
    # does not care about the exact values on x86_64, but zeros confuse
    # some consumers.
    put_u16(0x38, 0x33)  # SegCs
    put_u16(0x3A, 0x2B)  # SegDs
    put_u16(0x3C, 0x2B)  # SegEs
    put_u16(0x3E, 0x53)  # SegFs
    put_u16(0x40, 0x2B)  # SegGs
    put_u16(0x42, 0x2B)  # SegSs

    eflags = (
        registers.get('EFLAGS') or registers.get('RFLAGS') or 0x202)
    put_u32(0x44, eflags)

    # 0x48..0x78: Dr0..Dr7 (zeroed)

    put_u64(0x78, registers.get('RAX', 0))
    put_u64(0x80, registers.get('RCX', 0))
    put_u64(0x88, registers.get('RDX', 0))
    put_u64(0x90, registers.get('RBX', 0))
    put_u64(0x98, registers.get('RSP', 0))
    put_u64(0xA0, registers.get('RBP', 0))
    put_u64(0xA8, registers.get('RSI', 0))
    put_u64(0xB0, registers.get('RDI', 0))
    put_u64(0xB8, registers.get('R8', 0))
    put_u64(0xC0, registers.get('R9', 0))
    put_u64(0xC8, registers.get('R10', 0))
    put_u64(0xD0, registers.get('R11', 0))
    put_u64(0xD8, registers.get('R12', 0))
    put_u64(0xE0, registers.get('R13', 0))
    put_u64(0xE8, registers.get('R14', 0))
    put_u64(0xF0, registers.get('R15', 0))
    put_u64(0xF8, registers.get('RIP', 0))

    # 0x100..0x4D0: XMM save area + vector + debug registers — zero.
    return bytes(buf)


def _pack_mdmp_string(s: str) -> bytes:
    """Pack a ``MINIDUMP_STRING``: u32 byte length + UTF-16LE bytes + NUL."""
    utf16 = s.encode('utf-16-le')
    return struct.pack('<I', len(utf16)) + utf16 + b'\x00\x00'


def _pack_system_info() -> bytes:
    """Pack a 56-byte ``MINIDUMP_SYSTEM_INFO`` for AMD64 / Windows 10."""
    blob = struct.pack(
        '<HHHBBIIIIIHH24s',
        9,      # ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64
        6,      # ProcessorLevel
        0,      # ProcessorRevision
        1,      # NumberOfProcessors
        1,      # ProductType = VER_NT_WORKSTATION
        10,     # MajorVersion
        0,      # MinorVersion
        19041,  # BuildNumber (Win10 2004)
        2,      # PlatformId = VER_PLATFORM_WIN32_NT
        0,      # CSDVersionRVA
        0,      # SuiteMask
        0,      # Reserved2
        b'\x00' * 24,  # CPU_INFORMATION (other-CPU layout)
    )
    assert len(blob) == 56, len(blob)
    return blob


def write_minidump(
    registers: dict[str, int],
    stack_base: int,
    stack_mem: bytes,
    pe_path: Path,
    image_base: int,
    out_path: Path,
) -> Path:
    """Write a minimal minidump covering the RSOD's crash state.

    Parameters
    ----------
    registers:
        Uppercase register dict (``RIP``, ``RSP``, ``RBP``, ``RAX``..
        ``R15``, optional ``EFLAGS``/``RFLAGS``). Usually from
        :attr:`CrashInfo.registers`.
    stack_base:
        Runtime base address of the stack dump bytes.
    stack_mem:
        The RSOD's captured stack bytes (typically 4 KB).
    pe_path:
        Path to the PE ``.efi`` whose ``ImageBase`` matches
        ``image_base``. LLDB file-backs every section from this file.
    image_base:
        Runtime load address of the PE (for Dell EPSA fixtures, usually
        ``0x180000000``).
    out_path:
        Where to write the minidump bytes. Parent is created if needed.

    Returns
    -------
    Path
        ``out_path`` for chainability.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)

    sysinfo = _pack_system_info()
    context_blob = _pack_context_amd64(registers)
    module_name_blob = _pack_mdmp_string(str(pe_path.resolve()))
    size_of_image = pe_path.stat().st_size

    # ---- Layout pass -------------------------------------------------
    # Build offsets for each block in file order. Two passes: first
    # compute RVAs, then write with correct cross-references.

    cursor = _HEADER_SIZE + _NUM_STREAMS * _DIRECTORY_ENTRY_SIZE

    sysinfo_rva = cursor
    cursor += len(sysinfo)

    thread_list_rva = cursor
    thread_list_size = 4 + _THREAD_RECORD_SIZE  # u32 count + 1 thread
    cursor += thread_list_size

    context_rva = cursor
    cursor += len(context_blob)

    module_list_rva = cursor
    module_list_size = 4 + _MODULE_RECORD_SIZE  # u32 count + 1 module
    cursor += module_list_size

    module_name_rva = cursor
    cursor += len(module_name_blob)

    # MINIDUMP_MEMORY64_LIST header: u64 count + u64 BaseRva +
    # MINIDUMP_MEMORY_DESCRIPTOR64 (16 bytes).
    mem64_list_rva = cursor
    mem64_list_size = 16 + 16
    cursor += mem64_list_size

    mem64_payload_rva = cursor
    cursor += len(stack_mem)

    total_size = cursor

    # ---- Build pass --------------------------------------------------
    out = bytearray(total_size)

    # MINIDUMP_HEADER (32 bytes)
    struct.pack_into(
        '<IIIIIIQ',
        out, 0,
        MDMP_SIGNATURE,
        MDMP_VERSION,
        _NUM_STREAMS,
        _HEADER_SIZE,   # StreamDirectoryRva
        0,              # CheckSum
        0,              # TimeDateStamp
        0,              # Flags (u64)
    )

    # Directory — one 12-byte entry per stream
    def write_dir(idx: int, stype: int, size: int, rva: int) -> None:
        off = _HEADER_SIZE + idx * _DIRECTORY_ENTRY_SIZE
        struct.pack_into('<III', out, off, stype, size, rva)

    write_dir(0, STREAM_SYSTEM_INFO, len(sysinfo), sysinfo_rva)
    write_dir(1, STREAM_THREAD_LIST, thread_list_size, thread_list_rva)
    write_dir(2, STREAM_MODULE_LIST, module_list_size, module_list_rva)
    write_dir(3, STREAM_MEMORY64_LIST, mem64_list_size, mem64_list_rva)

    # SystemInfo blob
    out[sysinfo_rva:sysinfo_rva + len(sysinfo)] = sysinfo

    # ThreadList: u32 count = 1, then one MINIDUMP_THREAD record
    struct.pack_into('<I', out, thread_list_rva, 1)
    struct.pack_into(
        '<IIIIQQIIII',
        out, thread_list_rva + 4,
        1,                  # ThreadId
        0,                  # SuspendCount
        0,                  # PriorityClass
        0,                  # Priority
        0,                  # Teb
        stack_base,         # Stack.StartOfMemoryRange
        len(stack_mem),     # Stack.Memory.DataSize
        mem64_payload_rva,  # Stack.Memory.Rva
        len(context_blob),  # ThreadContext.DataSize
        context_rva,        # ThreadContext.Rva
    )

    # CONTEXT blob
    out[context_rva:context_rva + len(context_blob)] = context_blob

    # ModuleList: u32 count = 1, then one MINIDUMP_MODULE record
    struct.pack_into('<I', out, module_list_rva, 1)
    struct.pack_into(
        '<QIIII52sIIIIQQ',
        out, module_list_rva + 4,
        image_base,         # BaseOfImage
        size_of_image,      # SizeOfImage
        0,                  # CheckSum
        0,                  # TimeDateStamp
        module_name_rva,    # ModuleNameRva
        b'\x00' * 52,       # VS_FIXEDFILEINFO
        0, 0,               # CvRecord (DataSize, Rva)
        0, 0,               # MiscRecord (DataSize, Rva)
        0,                  # Reserved0
        0,                  # Reserved1
    )

    # Module name string
    out[module_name_rva:module_name_rva + len(module_name_blob)] = (
        module_name_blob)

    # Memory64List header + descriptor
    struct.pack_into(
        '<QQ', out, mem64_list_rva, 1, mem64_payload_rva)
    struct.pack_into(
        '<QQ', out, mem64_list_rva + 16,
        stack_base, len(stack_mem))

    # Memory64 payload = the stack bytes themselves
    out[mem64_payload_rva:mem64_payload_rva + len(stack_mem)] = stack_mem

    out_path.write_bytes(bytes(out))
    return out_path
