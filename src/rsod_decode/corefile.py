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


def _apply_relocations(
    elf: ELFFile, data: bytearray, sec_addr: int, image_base: int,
) -> None:
    """Apply R_*_RELATIVE relocations to a .data section copy.

    UEFI position-independent ELFs have RELATIVE relocations that say
    "add the load base to the 8-byte value at this offset."  The ELF
    file has pre-relocation values; we fix them up for the core file.
    """
    rela = elf.get_section_by_name('.rela') or elf.get_section_by_name('.rela.dyn')
    if not rela:
        return
    sec_end = sec_addr + len(data)
    for rel in rela.iter_relocations():
        offset = rel['r_offset']
        if offset < sec_addr or offset + 8 > sec_end:
            continue
        rel_type = rel['r_info_type']
        # R_AARCH64_RELATIVE=1027, R_X86_64_RELATIVE=8
        if rel_type in (1027, 8, 0x403):
            addend = rel['r_addend']
            idx = offset - sec_addr
            struct.pack_into('<Q', data, idx, addend + image_base)


def _load_elf_sections(
    elf_path: Path, image_base: int,
) -> list[tuple[int, bytes, int]]:
    """Load ELF sections mapped to runtime addresses.

    Applies RELATIVE relocations to .data so pointers are correct
    at the runtime load address.

    Returns list of (runtime_vaddr, data, flags) for PT_LOAD segments.
    """
    segments: list[tuple[int, bytes, int]] = []
    with elf_path.open('rb') as f:
        elf = ELFFile(f)
        for name in ('.text', '.rodata', '.data'):
            sec = elf.get_section_by_name(name)
            if sec and sec['sh_size'] > 0:
                data = bytearray(sec.data())
                vaddr = sec['sh_addr'] + image_base
                flags = PF_R
                if name == '.text':
                    flags |= 1  # PF_X
                elif name == '.data':
                    flags |= PF_W
                    _apply_relocations(elf, data, sec['sh_addr'],
                                       image_base)
                segments.append((vaddr, bytes(data), flags))
    return segments


def _build_synthetic_stack(
    frames: list[tuple[int, int]],
    stack_base: int,
    stack_size: int,
    image_base: int,
) -> tuple[int, bytes] | None:
    """Build synthetic FP chain entries for frames beyond the stack dump.

    ARM64 FP chain: at FP[N], the data is [FP[N+1], LR[N+1]] — pointing
    to the NEXT frame's FP and return address.

    frames: list of (frame_fp, return_addr_elf) ordered by frame index.
    Returns (base_addr, data) for a new PT_LOAD, or None if not needed.
    """
    stack_end = stack_base + stack_size

    # Find the first frame whose FP is beyond the dump.
    # We need to write data at that FP for the next frame in the chain.
    entries: list[tuple[int, int, int]] = []  # (write_addr, next_fp, next_lr)
    synth_fp_base = stack_end + 0x1000  # synthetic FPs go here

    for i in range(len(frames) - 1):
        fp = frames[i][0]
        if not fp or fp < stack_end:
            continue
        # This FP is beyond the dump — write [next_fp, next_lr] at it
        next_fp = frames[i + 1][0]
        next_lr = frames[i + 1][1] + image_base
        # If next frame has no known FP, assign a synthetic one
        if not next_fp:
            next_fp = synth_fp_base
            synth_fp_base += 16
            # Also need to write an entry at the synthetic FP for the
            # frame after that
            frames[i + 1] = (next_fp, frames[i + 1][1])
        entries.append((fp, next_fp, next_lr))

    if not entries:
        return None

    # Build contiguous regions (entries may be scattered)
    all_addrs = sorted(set(e[0] for e in entries))
    base = all_addrs[0]
    end = all_addrs[-1] + 16
    data = bytearray(end - base)
    for write_addr, next_fp, next_lr in entries:
        offset = write_addr - base
        if 0 <= offset <= len(data) - 16:
            struct.pack_into('<QQ', data, offset, next_fp, next_lr)

    return base, bytes(data)


def write_corefile(
    registers: dict[str, int],
    crash_pc: int | None,
    stack_base: int,
    stack_mem: bytes,
    elf_path: Path,
    out_path: Path,
    image_base: int = 0,
    frames: list[tuple[int, int]] | None = None,
) -> Path:
    """Write a minimal ELF core from crash registers + stack dump.

    frames: optional list of (frame_fp, return_addr_elf) for building
    synthetic FP chain entries beyond the stack dump.

    Includes ELF .text/.rodata/.data sections at runtime addresses so
    GDB can resolve symbols and read code/data.  Detects architecture
    from elf_path.  Returns path to the core file.
    """
    arch = _detect_arch(elf_path)
    ei_class = 2  # ELFCLASS64

    # Build the NOTE segment
    gregset = _pack_registers(registers, crash_pc, arch)
    note_data = _build_prstatus(gregset, arch)

    # Collect PT_LOAD segments: stack + synthetic frames + ELF sections
    load_segments: list[tuple[int, bytes, int]] = []
    if stack_mem:
        load_segments.append((stack_base, stack_mem, PF_R | PF_W))
    # Add synthetic FP chain for frames beyond the stack dump
    if frames:
        synth = _build_synthetic_stack(
            frames, stack_base, len(stack_mem), image_base)
        if synth:
            load_segments.append((synth[0], synth[1], PF_R | PF_W))
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
        # LLDB rejects cores with ELFOSABI_NONE; ELFOSABI_LINUX is accepted by both LLDB and GDB.
        3,                 # EI_OSABI = ELFOSABI_LINUX
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
