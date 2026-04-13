"""PE/COFF (.efi) binary backend for MSVC-built UEFI applications.

Provides the same disassembly + call-site verification surface as the
ELF/DWARF backend, but operates on a PE file via `pefile`. Symbol names
and source info come from an optional companion `.map` file loaded
elsewhere; this module only holds machine code and section data.
"""
from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pefile

from . import disasm
from .models import AddressInfo, VarInfo


class PELoadError(Exception):
    """Raised when a PE file cannot be loaded or has an unsupported arch."""


# IMAGE_FILE_MACHINE_* constants
_PE_MACHINE_AMD64 = 0x8664
_PE_MACHINE_ARM64 = 0xAA64


class PEBinary:
    """PE/COFF binary backend.

    Mirrors the public surface of DwarfInfo that the decoder and Flask
    layer rely on (disassembly, call-site verification, memory reads).
    DWARF-specific methods (variable inspection, type expansion, source
    lines) are stubbed out with empty/None return values so the existing
    code paths degrade gracefully when PE sessions reach them.
    """

    def __init__(
        self, pe_path: Path,
        log: Callable[[str], None] | None = None,
    ) -> None:
        if log is None:
            def log(msg: str) -> None:
                print(msg, file=sys.stderr)

        self.path = pe_path
        try:
            pe = pefile.PE(str(pe_path), fast_load=True)
        except pefile.PEFormatError as e:
            raise PELoadError(f"not a PE file: {pe_path} ({e})") from e

        machine = pe.FILE_HEADER.Machine
        if machine == _PE_MACHINE_AMD64:
            self.arch = 'x86_64'
        elif machine == _PE_MACHINE_ARM64:
            self.arch = 'aarch64'
        else:
            pe.close()
            raise PELoadError(
                f"unsupported PE machine type 0x{machine:X} in {pe_path}")

        self.image_base: int = pe.OPTIONAL_HEADER.ImageBase

        # Capture every loaded section so read_memory can satisfy reads
        # that hit .rdata/.data/etc., and pull out .text specifically for
        # disassembly.
        self._sections: list[tuple[int, bytes]] = []
        self._section_names: dict[int, str] = {}
        self._text_data: bytes = b''
        self._text_addr: int = 0
        for section in pe.sections:
            name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            sec_addr = self.image_base + section.VirtualAddress
            sec_data = section.get_data()
            if not sec_data:
                continue
            self._sections.append((sec_addr, sec_data))
            self._section_names[sec_addr] = name
            if name == '.text':
                self._text_data = sec_data
                self._text_addr = sec_addr

        pe.close()

        if not self._text_data:
            raise PELoadError(f".text section missing from {pe_path}")

        self._cs = disasm.make_capstone(self.arch)

        log(f"Loaded PE binary {pe_path.name} "
            f"({self.arch}, image_base=0x{self.image_base:X}, "
            f".text={len(self._text_data)} bytes) [PE]")

    # -----------------------------------------------------------------
    # Properties
    # -----------------------------------------------------------------

    @property
    def dwarf_prefix(self) -> str | None:
        return None

    # -----------------------------------------------------------------
    # Disassembly (shared with DwarfInfo via rsod_decode.disasm)
    # -----------------------------------------------------------------

    def disassemble_around(
        self, addr: int, context: int = 24,
    ) -> list[tuple[int, str, str]]:
        """Disassemble instructions around addr. Empty list if out of range."""
        return disasm.disassemble_around(
            self._cs, self._text_data, self._text_addr, addr, context)

    def is_call_before(self, addr: int) -> bool:
        """True if the instruction immediately before addr is a call/bl."""
        return disasm.is_call_before(
            self._cs, self._text_data, self._text_addr, addr)

    # -----------------------------------------------------------------
    # Memory reads (PE sections + external stack dump)
    # -----------------------------------------------------------------

    def read_memory(
        self, addr: int, size: int,
        stack_base: int = 0, stack_mem: bytes = b'',
        image_base: int = 0,
    ) -> bytes | None:
        """Read `size` bytes from `addr`. Tries the stack dump first, then
        static PE sections (with `image_base` subtracted from `addr` to
        translate runtime addresses into the file's image-base space).
        """
        if stack_mem:
            off = addr - stack_base
            if 0 <= off <= len(stack_mem) - size:
                return stack_mem[off:off + size]
        # Translate runtime addr into "as if loaded at preferred base"
        file_addr = addr - image_base
        for sec_addr, sec_data in self._sections:
            off = file_addr - sec_addr
            if 0 <= off <= len(sec_data) - size:
                return sec_data[off:off + size]
        return None

    def read_int(
        self, addr: int, size: int,
        stack_base: int = 0, stack_mem: bytes = b'',
        image_base: int = 0,
    ) -> int | None:
        data = self.read_memory(addr, size, stack_base, stack_mem, image_base)
        if data is None:
            return None
        return int.from_bytes(data, 'little')

    def read_string(
        self, addr: int,
        stack_base: int = 0, stack_mem: bytes = b'',
        image_base: int = 0,
        max_len: int = 256,
    ) -> str | None:
        data = self.read_memory(addr, max_len, stack_base, stack_mem, image_base)
        if data is None:
            for try_len in (64, 16, 1):
                data = self.read_memory(
                    addr, try_len, stack_base, stack_mem, image_base)
                if data is not None:
                    break
            if data is None:
                return None
        nul = data.find(b'\0')
        if nul >= 0:
            data = data[:nul]
        try:
            return data.decode('utf-8', errors='replace')
        except Exception:
            return None

    # -----------------------------------------------------------------
    # DWARF-only methods: stubbed out, return empty/None for PE sessions.
    # The frontend renders "No source available" / empty tables on these,
    # which is the honest answer when there's no DWARF/PDB.
    # -----------------------------------------------------------------

    def get_symbols(self) -> list[tuple[int, str, bool]]:
        """PE COFF symbol tables are stripped by GenFw; symbols come from
        the companion .map file, not from here."""
        return []

    def resolve_address(self, addr: int) -> AddressInfo | None:
        return None

    def resolve_addresses(
        self, addrs: list[int], crash_pc: int = 0,
    ) -> dict[int, AddressInfo]:
        return {}

    def source_lines_for_addrs(self, addrs: list[int]) -> dict[int, str]:
        return {}

    def get_params(self, addr: int) -> list[VarInfo]:
        return []

    def get_locals(self, addr: int) -> list[VarInfo]:
        return []

    def get_globals(self, addr: int) -> list[VarInfo]:
        return []

    def get_type_die(self, cu_offset: int, type_offset: int) -> Any | None:
        return None

    def expand_type(
        self, die: Any, base_addr: int, depth: int = 0,
    ) -> list[VarInfo]:
        return []

    def get_cfi_unwinder(self) -> Any | None:
        return None

    def close(self) -> None:
        """No-op; pefile doesn't keep file handles after parsing."""
        return None

    def __enter__(self) -> PEBinary:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
