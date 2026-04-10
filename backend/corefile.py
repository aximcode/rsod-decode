"""Generate minimal ELF core files from RSOD crash data.

Produces a core file with NT_PRSTATUS (registers) and one PT_LOAD
(stack memory) so GDB can load the crash state.  Supports AARCH64
and x86-64.
"""
from __future__ import annotations

import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile

# ELF constants
ET_CORE = 4
PT_NOTE = 4
PT_LOAD = 1
PF_R = 4
PF_W = 2
NT_PRSTATUS = 1

# Architecture-specific constants
EM_AARCH64 = 183
EM_X86_64 = 62

# AARCH64 register order in NT_PRSTATUS elf_gregset_t (34 × 8 bytes)
_AARCH64_REGS = [
    *(f'X{i}' for i in range(31)),  # X0-X30
    'SP', 'PC', 'PSTATE',
]

# x86-64 register order in struct user_regs_struct (27 × 8 bytes)
_X86_64_REGS = [
    'R15', 'R14', 'R13', 'R12', 'RBP', 'RBX', 'R11', 'R10',
    'R9', 'R8', 'RAX', 'RCX', 'RDX', 'RSI', 'RDI', 'ORIG_RAX',
    'RIP', 'CS', 'EFLAGS', 'RSP', 'SS',
    'FS_BASE', 'GS_BASE', 'DS', 'ES', 'FS', 'GS',
]


def _detect_arch(elf_path: Path) -> int:
    """Return e_machine from the ELF file."""
    with elf_path.open('rb') as f:
        elf = ELFFile(f)
        arch = elf['e_machine']
        if arch == 'EM_AARCH64':
            return EM_AARCH64
        if arch in ('EM_X86_64', 'EM_386'):
            return EM_X86_64
        # Try numeric
        if isinstance(arch, int):
            return arch
    return EM_AARCH64


def _pack_registers(
    registers: dict[str, int],
    crash_pc: int | None,
    arch: int,
) -> bytes:
    """Pack registers into NT_PRSTATUS gregset format."""
    if arch == EM_AARCH64:
        reg_order = _AARCH64_REGS
    else:
        reg_order = _X86_64_REGS

    # Alias map: core file register name → RSOD register key(s)
    aliases: dict[str, list[str]] = {
        'X29': ['X29', 'FP'],
        'X30': ['X30', 'LR'],
        'PC': ['ELR', 'PC', 'RIP'],
        'PSTATE': ['SPSR', 'PSTATE', 'CPSR'],
        'RIP': ['RIP', 'ELR'],
        'EFLAGS': ['EFLAGS', 'RFLAGS'],
        'RBP': ['RBP', 'FP'],
    }

    values: list[int] = []
    for name in reg_order:
        if name == 'ORIG_RAX':
            values.append(0)
            continue
        # Check aliases first, then direct name
        candidates = aliases.get(name, [name])
        val = 0
        for key in candidates:
            if key in registers:
                val = registers[key]
                break
        # Override PC with crash_pc if available
        if name in ('PC', 'RIP') and crash_pc is not None and val == 0:
            val = crash_pc
        values.append(val)

    return struct.pack(f'<{len(values)}Q', *values)


def _build_note(name: bytes, desc: bytes, note_type: int) -> bytes:
    """Build an ELF note entry (namesz, descsz, type, name, desc)."""
    namesz = len(name)
    descsz = len(desc)
    # Pad name and desc to 4-byte alignment
    name_padded = name + b'\x00' * ((4 - namesz % 4) % 4)
    desc_padded = desc + b'\x00' * ((4 - descsz % 4) % 4)
    header = struct.pack('<III', namesz, descsz, note_type)
    return header + name_padded + desc_padded


def _build_prstatus(gregset: bytes, arch: int) -> bytes:
    """Build NT_PRSTATUS note with register data.

    The prstatus struct has fields before the gregset (signal info,
    pid, etc.) that we zero-fill.
    """
    # BFD expects specific prstatus descriptor sizes:
    #   AARCH64: 392 bytes (prefix=112, gregset=272, suffix=8)
    #   x86-64:  336 bytes (prefix=112, gregset=216, suffix=8)
    # The suffix is pr_fpvalid (4 bytes) + struct alignment padding (4 bytes).
    prefix = b'\x00' * 112
    suffix = b'\x00' * 8

    desc = prefix + gregset + suffix
    return _build_note(b'CORE\x00', desc, NT_PRSTATUS)


def _load_elf_sections(
    elf_path: Path, image_base: int,
) -> list[tuple[int, bytes, int]]:
    """Load ELF sections mapped to runtime addresses.

    Returns list of (runtime_vaddr, data, flags) for PT_LOAD segments.
    """
    segments: list[tuple[int, bytes, int]] = []
    with elf_path.open('rb') as f:
        elf = ELFFile(f)
        for name in ('.text', '.rodata', '.data'):
            sec = elf.get_section_by_name(name)
            if sec and sec['sh_size'] > 0:
                data = sec.data()
                vaddr = sec['sh_addr'] + image_base
                flags = PF_R
                if name == '.text':
                    flags |= 1  # PF_X
                elif name == '.data':
                    flags |= PF_W
                segments.append((vaddr, data, flags))
    return segments


def write_corefile(
    registers: dict[str, int],
    crash_pc: int | None,
    stack_base: int,
    stack_mem: bytes,
    elf_path: Path,
    out_path: Path,
    image_base: int = 0,
) -> Path:
    """Write a minimal ELF core from crash registers + stack dump.

    Includes ELF .text/.rodata/.data sections at runtime addresses so
    GDB can resolve symbols and read code/data.  Detects architecture
    from elf_path.  Returns path to the core file.
    """
    arch = _detect_arch(elf_path)
    ei_class = 2  # ELFCLASS64

    # Build the NOTE segment
    gregset = _pack_registers(registers, crash_pc, arch)
    note_data = _build_prstatus(gregset, arch)

    # Collect PT_LOAD segments: stack + ELF sections at runtime addresses
    load_segments: list[tuple[int, bytes, int]] = []
    if stack_mem:
        load_segments.append((stack_base, stack_mem, PF_R | PF_W))
    load_segments.extend(_load_elf_sections(elf_path, image_base))

    # ELF header (64 bytes)
    e_phentsize = 56  # sizeof(Elf64_Phdr)
    e_phnum = 1 + len(load_segments)  # PT_NOTE + PT_LOADs

    elf_header = struct.pack(
        '<4sBBBBB7sHHIQQQIHHHHHH',
        b'\x7fELF',       # e_ident magic
        ei_class,          # EI_CLASS = ELFCLASS64
        1,                 # EI_DATA = ELFDATA2LSB
        1,                 # EI_VERSION
        0,                 # EI_OSABI = ELFOSABI_NONE
        0,                 # EI_ABIVERSION
        b'\x00' * 7,      # EI_PAD
        ET_CORE,           # e_type
        arch,              # e_machine
        1,                 # e_version
        0,                 # e_entry
        64,                # e_phoff
        0,                 # e_shoff
        0,                 # e_flags
        64,                # e_ehsize
        e_phentsize,       # e_phentsize
        e_phnum,           # e_phnum
        0,                 # e_shentsize
        0,                 # e_shnum
        0,                 # e_shstrndx
    )

    # Compute data offsets
    phdrs_size = e_phnum * e_phentsize
    data_start = 64 + phdrs_size
    note_offset = data_start

    # Build program headers and track data positions
    phdrs = struct.pack(
        '<IIQQQQQQ',
        PT_NOTE, 0, note_offset, 0, 0,
        len(note_data), len(note_data), 4,
    )

    file_offset = note_offset + len(note_data)
    for vaddr, data, flags in load_segments:
        phdrs += struct.pack(
            '<IIQQQQQQ',
            PT_LOAD, flags, file_offset, vaddr, 0,
            len(data), len(data), 1,
        )
        file_offset += len(data)

    # Write
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('wb') as f:
        f.write(elf_header)
        f.write(phdrs)
        f.write(note_data)
        for _, data, _ in load_segments:
            f.write(data)

    return out_path
