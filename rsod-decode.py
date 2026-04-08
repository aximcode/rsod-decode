#!/usr/bin/env python3
"""
RSOD Decode Tool

Resolves raw addresses in UEFI RSOD (Red Screen of Death) stack dumps to
function names, source locations, and more using symbol files.

Supports x86-64 (MSVC .map) and ARM64 (GCC ELF via pyelftools/capstone).

Usage:
  rsod-decode.py <rsod-log> <symbol-file> [-o output] [-v] [--base HEX]
  rsod-decode.py rsod.txt psa.efi.map
  rsod-decode.py rsod.txt af4305.efi.so -v
  rsod-decode.py rsod.txt af4305.efi.so -s DxeCore.debug -s Shell.debug
"""
from __future__ import annotations

import argparse
import bisect
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import cxxfilt
from capstone import CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_ARM, CS_MODE_64, Cs
from elftools.elf.elffile import ELFFile
from elftools.dwarf.die import DIE
from elftools.dwarf.compileunit import CompileUnit
from elftools.dwarf.locationlists import LocationParser


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class MapSymbol:
    """One symbol from a map file or ELF."""
    address: int
    name: str
    object_file: str
    is_function: bool = True

@dataclass
class SymbolTable:
    """Sorted symbol list with binary-search lookup."""
    symbols: list[MapSymbol] = field(default_factory=list)
    addresses: list[int] = field(default_factory=list)
    preferred_base: int = 0
    image_end: int = 0

    def lookup(self, addr: int) -> tuple[MapSymbol, int] | None:
        """Find the symbol containing addr. Returns (symbol, offset) or None."""
        if addr < self.preferred_base or addr > self.image_end:
            return None
        idx = bisect.bisect_right(self.addresses, addr) - 1
        if idx < 0:
            return None
        sym = self.symbols[idx]
        offset = addr - sym.address
        return (sym, offset) if offset >= 0 else None

@dataclass
class SymbolSource:
    """Loaded symbols plus metadata."""
    table: SymbolTable
    elf_path: Path | None = None
    name: str = ''
    dwarf: DwarfInfo | None = None

    def has_debug_info(self) -> bool:
        return self.dwarf is not None

@dataclass
class FrameInfo:
    """One resolved stack frame."""
    index: int
    address: int
    module: str
    symbol: MapSymbol | None = None
    sym_offset: int = 0
    source_loc: str = ''
    inlines: list[tuple[str, str]] = field(default_factory=list)

@dataclass
class CrashInfo:
    """Crash metadata extracted from the RSOD."""
    fmt: str = ''
    exception_desc: str = ''
    crash_pc: int | None = None
    crash_symbol: str = ''
    image_name: str = ''
    image_base: int = 0
    registers: dict[str, int] = field(default_factory=dict)
    esr: int | None = None
    far: int | None = None
    sp: int | None = None


# =============================================================================
# DWARF data structures
# =============================================================================

@dataclass
class AddressInfo:
    """Resolved address: function, source location, and inlines."""
    function: str = ''
    source_loc: str = ''
    inlines: list[tuple[str, str]] = field(default_factory=list)

@dataclass
class VarInfo:
    """A function parameter or local variable."""
    name: str = ''
    type_name: str = ''
    location: str = ''
    reg_name: str | None = None


# =============================================================================
# DWARF register name tables
# =============================================================================

_ARM64_REGS: dict[int, str] = {i: f'X{i}' for i in range(31)}
_ARM64_REGS[29] = 'FP'
_ARM64_REGS[30] = 'LR'
_ARM64_REGS[31] = 'SP'

_X86_64_REGS: dict[int, str] = {
    0: 'RAX', 1: 'RDX', 2: 'RCX', 3: 'RBX', 4: 'RSI', 5: 'RDI',
    6: 'RBP', 7: 'RSP', 8: 'R8', 9: 'R9', 10: 'R10', 11: 'R11',
    12: 'R12', 13: 'R13', 14: 'R14', 15: 'R15',
}

RE_ARM_MAPPING = re.compile(r'^\$[xdt](\.\d+)?$')


# =============================================================================
# DWARF helpers
# =============================================================================

def _resolve_die(die: DIE) -> DIE:
    """Follow abstract_origin/specification chains to the canonical DIE."""
    seen: set[int] = set()
    while die.offset not in seen:
        seen.add(die.offset)
        if 'DW_AT_abstract_origin' in die.attributes:
            die = die.get_DIE_from_attribute('DW_AT_abstract_origin')
        elif 'DW_AT_specification' in die.attributes:
            die = die.get_DIE_from_attribute('DW_AT_specification')
        else:
            break
    return die


def _die_name(die: DIE) -> str:
    """Get the name of a DIE, following reference chains if needed."""
    resolved = _resolve_die(die)
    attr = resolved.attributes.get('DW_AT_name')
    return attr.value.decode() if attr else ''


def _die_contains_addr(die: DIE, addr: int) -> bool:
    """Check if a DIE's address range contains addr."""
    low_attr = die.attributes.get('DW_AT_low_pc')
    if not low_attr:
        return False
    low = low_attr.value
    high_attr = die.attributes.get('DW_AT_high_pc')
    if not high_attr:
        return False
    high = high_attr.value
    if high_attr.form.startswith('DW_FORM_data'):
        high = low + high
    return low <= addr < high


def _resolve_type(die: DIE | None, depth: int = 0) -> str:
    """Resolve a type DIE to a human-readable name."""
    if depth > 10 or die is None:
        return '?'
    tag = die.tag
    name = die.attributes.get('DW_AT_name')

    if tag in ('DW_TAG_base_type', 'DW_TAG_structure_type',
               'DW_TAG_class_type', 'DW_TAG_enumeration_type',
               'DW_TAG_union_type', 'DW_TAG_typedef'):
        return name.value.decode() if name else tag.split('_')[-1]

    if tag == 'DW_TAG_pointer_type':
        if 'DW_AT_type' in die.attributes:
            inner = _resolve_type(
                die.get_DIE_from_attribute('DW_AT_type'), depth + 1)
            return f'{inner}*'
        return 'void*'

    if tag == 'DW_TAG_const_type':
        if 'DW_AT_type' in die.attributes:
            inner = _resolve_type(
                die.get_DIE_from_attribute('DW_AT_type'), depth + 1)
            return f'const {inner}'
        return 'const void'

    if tag == 'DW_TAG_reference_type':
        if 'DW_AT_type' in die.attributes:
            inner = _resolve_type(
                die.get_DIE_from_attribute('DW_AT_type'), depth + 1)
            return f'{inner}&'
        return 'void&'

    if tag == 'DW_TAG_volatile_type':
        if 'DW_AT_type' in die.attributes:
            inner = _resolve_type(
                die.get_DIE_from_attribute('DW_AT_type'), depth + 1)
            return f'volatile {inner}'
        return 'volatile void'

    if tag == 'DW_TAG_array_type':
        if 'DW_AT_type' in die.attributes:
            inner = _resolve_type(
                die.get_DIE_from_attribute('DW_AT_type'), depth + 1)
            return f'{inner}[]'
        return '?[]'

    # Follow DW_AT_type for other tags (restrict, etc.)
    if 'DW_AT_type' in die.attributes:
        return _resolve_type(
            die.get_DIE_from_attribute('DW_AT_type'), depth + 1)
    return '?'


def _decode_sleb128(data: list[int] | bytes, start: int = 0) -> int:
    """Decode a SLEB128 value from bytes."""
    result = 0
    shift = 0
    for b in data[start:]:
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                result -= 1 << shift
            break
    return result


def _decode_location(loc_expr: list[int] | bytes, reg_table: dict[int, str],
                     ) -> tuple[str, str | None]:
    """Decode a DWARF location expression to (description, register_name)."""
    if not loc_expr:
        return 'optimized out', None
    op = loc_expr[0]

    # DW_OP_reg0..DW_OP_reg31 (0x50..0x6F)
    if 0x50 <= op <= 0x6F:
        regnum = op - 0x50
        regname = reg_table.get(regnum, f'r{regnum}')
        return regname, regname

    # DW_OP_breg0..DW_OP_breg31 (0x70..0x8F) -- register + offset
    if 0x70 <= op <= 0x8F:
        regnum = op - 0x70
        regname = reg_table.get(regnum, f'r{regnum}')
        offset = _decode_sleb128(loc_expr, 1)
        if offset:
            return f'[{regname}{offset:+d}]', None
        return f'[{regname}]', None

    # DW_OP_fbreg (0x91) -- frame base + offset
    if op == 0x91:
        offset = _decode_sleb128(loc_expr, 1)
        return f'[FP{offset:+d}]', None

    # DW_OP_addr (0x03) -- absolute address
    if op == 0x03 and len(loc_expr) >= 9:
        addr = int.from_bytes(bytes(loc_expr[1:9]), 'little')
        return f'0x{addr:X}', None

    return f'expr[{" ".join(f"{b:02X}" for b in loc_expr)}]', None


# =============================================================================
# DwarfInfo class
# =============================================================================

class DwarfInfo:
    """High-level DWARF interface for crash analysis."""

    def __init__(self, elf_path: Path) -> None:
        self._path = elf_path
        self._file = elf_path.open('rb')
        self._elf = ELFFile(self._file)
        self._dwarf = self._elf.get_dwarf_info() if self._elf.has_dwarf_info() else None
        self._aranges = self._dwarf.get_aranges() if self._dwarf else None
        self._loc_parser = (LocationParser(self._dwarf.location_lists())
                            if self._dwarf else None)

        # Detect architecture for register names and disassembly
        arch = self._elf.get_machine_arch()
        if arch == 'AArch64':
            self._reg_table = _ARM64_REGS
            self._cs_arch = CS_ARCH_ARM64
            self._cs_mode = CS_MODE_ARM
        elif arch in ('x64', 'x86'):
            self._reg_table = _X86_64_REGS
            self._cs_arch = CS_ARCH_X86
            self._cs_mode = CS_MODE_64
        else:
            self._reg_table = _ARM64_REGS
            self._cs_arch = CS_ARCH_ARM64
            self._cs_mode = CS_MODE_ARM

        # Cache: CU offset -> parsed CU
        self._cu_cache: dict[int, CompileUnit] = {}

        # Capstone disassembler (cached)
        self._cs = Cs(self._cs_arch, self._cs_mode)

        # Cache .text section for disassembly
        text_sec = self._elf.get_section_by_name('.text')
        if text_sec:
            self._text_data: bytes = text_sec.data()
            self._text_addr: int = text_sec['sh_addr']
        else:
            self._text_data = b''
            self._text_addr = 0

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> DwarfInfo:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # -----------------------------------------------------------------
    # Symbol table (replaces nm -nC)
    # -----------------------------------------------------------------

    def get_symbols(self) -> list[tuple[int, str, bool]]:
        """Read .symtab and return [(addr, demangled_name, is_function), ...].
        Sorted by address, ARM mapping symbols filtered out."""
        symtab = self._elf.get_section_by_name('.symtab')
        if not symtab:
            return []

        raw: list[tuple[int, str, bool]] = []
        mangled_names: list[str] = []
        for sym in symtab.iter_symbols():
            addr = sym.entry.st_value
            if addr == 0:
                continue
            name = sym.name
            if RE_ARM_MAPPING.match(name):
                continue
            is_func = sym.entry.st_info.type in ('STT_FUNC', 'STT_GNU_IFUNC')
            raw.append((addr, name, is_func))
            mangled_names.append(name)

        # Batch demangle via cxxfilt
        demangled = self._demangle_batch(mangled_names)

        result: list[tuple[int, str, bool]] = []
        for (addr, _name, is_func), dem_name in zip(raw, demangled):
            result.append((addr, dem_name, is_func))

        result.sort(key=lambda x: x[0])
        return result

    @staticmethod
    def _demangle_batch(names: list[str]) -> list[str]:
        """Demangle C++ names via cxxfilt."""
        if not names:
            return []
        return [cxxfilt.demangle(n) for n in names]

    # -----------------------------------------------------------------
    # Address resolution (replaces addr2line -a -f -C -i)
    # -----------------------------------------------------------------

    def resolve_address(self, addr: int) -> AddressInfo | None:
        """Resolve an address to function, file:line, and inlines."""
        cu = self._get_cu_for_addr(addr)
        if not cu:
            return None

        info = AddressInfo()

        # File:line from line program
        info.source_loc = self._addr_to_line(cu, addr)

        # Function name + inlines from DIE tree
        self._resolve_function(cu, addr, info)

        return info if info.function or info.source_loc else None

    def resolve_addresses(self, addrs: list[int],
                          ) -> dict[int, AddressInfo]:
        """Batch resolve multiple addresses."""
        result: dict[int, AddressInfo] = {}
        for addr in dict.fromkeys(addrs):  # dedup preserving order
            info = self.resolve_address(addr)
            if info:
                result[addr] = info
        return result

    # -----------------------------------------------------------------
    # Disassembly (replaces objdump)
    # -----------------------------------------------------------------

    def disassemble_around(self, addr: int, context: int = 24,
                           ) -> list[tuple[int, str, str]]:
        """Disassemble instructions around addr using capstone.
        Returns [(addr, mnemonic, op_str), ...]."""
        if not self._text_data:
            return []

        start = max(self._text_addr, addr - context)
        # Align to 4-byte boundary for ARM64
        if self._cs_arch == CS_ARCH_ARM64:
            start = start & ~3
        end = addr + context

        offset = start - self._text_addr
        end_offset = end - self._text_addr
        if offset < 0 or offset >= len(self._text_data):
            return []
        end_offset = min(end_offset, len(self._text_data))
        code = self._text_data[offset:end_offset]

        result: list[tuple[int, str, str]] = []
        for insn in self._cs.disasm(code, start):
            result.append((insn.address, insn.mnemonic, insn.op_str))
        return result

    def is_call_before(self, addr: int) -> bool:
        """Check if there's a call/bl/blr instruction in the 8 bytes
        immediately before addr."""
        check_start = addr - 8
        if check_start < self._text_addr:
            return False
        offset = check_start - self._text_addr
        end_offset = addr - self._text_addr
        if offset < 0 or end_offset > len(self._text_data):
            return False
        code = self._text_data[offset:end_offset]

        insns = list(self._cs.disasm(code, check_start))
        if not insns:
            return False
        last = insns[-1]
        return last.mnemonic in ('call', 'bl', 'blr', 'blx')

    def source_lines_for_addrs(self, addrs: list[int]) -> dict[int, str]:
        """Batch-resolve instruction addresses to cleaned source locations.
        Single pass through the line program for efficiency."""
        if not addrs:
            return {}
        # All addrs should be in the same CU (disassembly window)
        cu = self._get_cu_for_addr(addrs[0])
        if not cu:
            return {}
        lp = self._dwarf.line_program_for_CU(cu)
        if not lp:
            return {}

        addr_set = set(addrs)
        result: dict[int, str] = {}
        prev = None
        for entry in lp.get_entries():
            state = entry.state
            if state is None:
                continue
            if state.end_sequence:
                prev = None
                continue
            if prev:
                # Check which query addresses fall in [prev.address, state.address)
                for a in list(addr_set):
                    if prev.address <= a < state.address:
                        raw = self._format_file_line(lp, prev.file, prev.line)
                        if raw:
                            result[a] = _clean_path(raw)
                        addr_set.discard(a)
                if not addr_set:
                    break
            prev = state
        return result

    def _format_file_line(self, lp: object, file_idx: int, line: int) -> str:
        """Format a file:line string from line program data."""
        file_entry = lp['file_entry'][file_idx - 1]
        fname = (file_entry.name.decode()
                 if isinstance(file_entry.name, bytes) else file_entry.name)
        dir_idx = file_entry.dir_index
        dirs = lp['include_directory']
        if dir_idx > 0 and dir_idx <= len(dirs):
            d = dirs[dir_idx - 1]
            d = d.decode() if isinstance(d, bytes) else d
            fname = f'{d}/{fname}'
        return f'{fname}:{line}'

    # -----------------------------------------------------------------
    # Parameter and local variable extraction
    # -----------------------------------------------------------------

    def get_params(self, addr: int) -> list[VarInfo]:
        """Get function parameters at the given address."""
        func_die = self._find_function_die(addr)
        if not func_die:
            return []
        return self._extract_vars(func_die, 'DW_TAG_formal_parameter', addr)

    def get_locals(self, addr: int) -> list[VarInfo]:
        """Get local variables at the given address."""
        func_die = self._find_function_die(addr)
        if not func_die:
            return []
        return self._extract_vars(func_die, 'DW_TAG_variable', addr)

    # -----------------------------------------------------------------
    # Internal: CU lookup (cached)
    # -----------------------------------------------------------------

    def _get_cu_for_addr(self, addr: int) -> CompileUnit | None:
        """Find the CU containing addr via .debug_aranges."""
        if not self._aranges:
            return None
        cu_offset = self._aranges.cu_offset_at_addr(addr)
        if cu_offset is None:
            return None
        if cu_offset not in self._cu_cache:
            self._cu_cache[cu_offset] = self._dwarf._parse_CU_at_offset(cu_offset)
        return self._cu_cache[cu_offset]

    # -----------------------------------------------------------------
    # Internal: line program resolution
    # -----------------------------------------------------------------

    def _addr_to_line(self, cu: CompileUnit, addr: int) -> str:
        """Resolve addr to "dir/file:line" using the CU's line program."""
        lp = self._dwarf.line_program_for_CU(cu)
        if not lp:
            return ''

        prev = None
        for entry in lp.get_entries():
            state = entry.state
            if state is None:
                continue
            if state.end_sequence:
                prev = None
                continue
            if prev and prev.address <= addr < state.address:
                return self._format_file_line(lp, prev.file, prev.line)
            prev = state
        return ''

    # -----------------------------------------------------------------
    # Internal: function + inline resolution
    # -----------------------------------------------------------------

    def _resolve_function(self, cu: CompileUnit, addr: int,
                          info: AddressInfo) -> None:
        """Find function name and inlined call chain for addr."""
        for die in cu.iter_DIEs():
            if die.tag == 'DW_TAG_subprogram' and _die_contains_addr(die, addr):
                info.function = _die_name(die)
                # Look for inlined subroutines within this function
                self._find_inlines(die, addr, info)
                return

    def _find_inlines(self, parent: DIE, addr: int,
                      info: AddressInfo) -> None:
        """Find DW_TAG_inlined_subroutine DIEs containing addr."""
        for child in parent.iter_children():
            if child.tag == 'DW_TAG_inlined_subroutine':
                if _die_contains_addr(child, addr):
                    name = _die_name(child)
                    # Get call site location
                    call_file = child.attributes.get('DW_AT_call_file')
                    call_line = child.attributes.get('DW_AT_call_line')
                    loc = ''
                    if call_file and call_line:
                        cu = child.cu
                        lp = self._dwarf.line_program_for_CU(cu)
                        if lp:
                            fe = lp['file_entry'][call_file.value - 1]
                            fname = (fe.name.decode()
                                     if isinstance(fe.name, bytes) else fe.name)
                            loc = f'{fname}:{call_line.value}'
                    info.inlines.append((name, loc))
                    # Recurse for nested inlines
                    self._find_inlines(child, addr, info)

    # -----------------------------------------------------------------
    # Internal: function DIE lookup
    # -----------------------------------------------------------------

    def _find_function_die(self, addr: int) -> DIE | None:
        """Find the DW_TAG_subprogram DIE containing addr."""
        cu = self._get_cu_for_addr(addr)
        if not cu:
            return None
        for die in cu.iter_DIEs():
            if die.tag == 'DW_TAG_subprogram' and _die_contains_addr(die, addr):
                return die
        return None

    # -----------------------------------------------------------------
    # Internal: variable extraction (shared by params + locals)
    # -----------------------------------------------------------------

    def _extract_vars(self, func_die: DIE, tag: str,
                      crash_pc: int) -> list[VarInfo]:
        """Extract variables (params or locals) from a function DIE."""
        cu = func_die.cu
        results: list[VarInfo] = []

        for child in func_die.iter_children():
            if child.tag != tag:
                continue

            resolved = _resolve_die(child)
            name = resolved.attributes.get('DW_AT_name')
            var = VarInfo(name=name.value.decode() if name else '???')

            # Type
            if 'DW_AT_type' in resolved.attributes:
                type_die = resolved.get_DIE_from_attribute('DW_AT_type')
                var.type_name = _resolve_type(type_die)
            else:
                var.type_name = '?'

            # Location
            loc_attr = child.attributes.get('DW_AT_location')
            if loc_attr and self._loc_parser:
                try:
                    loc_data = self._loc_parser.parse_from_attribute(
                        loc_attr, cu['version'], func_die)
                    if isinstance(loc_data, list):
                        # Location list -- find entry valid at crash_pc
                        best = self._pick_location(loc_data, crash_pc, func_die)
                        if best:
                            var.location, var.reg_name = _decode_location(
                                best, self._reg_table)
                        else:
                            var.location = 'optimized out'
                    else:
                        var.location, var.reg_name = _decode_location(
                            loc_data.loc_expr, self._reg_table)
                except Exception as e:
                    var.location = f'error: {e}'
            else:
                var.location = 'optimized out'

            results.append(var)

        return results

    @staticmethod
    def _pick_location(loc_list: list[object], crash_pc: int,
                       func_die: DIE) -> list[int] | None:
        """Pick the location list entry valid at crash_pc."""
        base = 0
        low_pc = func_die.attributes.get('DW_AT_low_pc')
        if low_pc:
            base = low_pc.value
        pc_offset = crash_pc - base

        for entry in loc_list:
            if not hasattr(entry, 'loc_expr'):
                continue
            begin = getattr(entry, 'begin_offset',
                            getattr(entry, 'entry_offset', 0))
            end = getattr(entry, 'end_offset',
                          getattr(entry, 'entry_end', 0))
            if begin <= pc_offset < end:
                return entry.loc_expr

        # Fallback: return the first entry with a location
        for entry in loc_list:
            if hasattr(entry, 'loc_expr') and entry.loc_expr:
                return entry.loc_expr
        return None


# =============================================================================
# MSVC map file parser
# =============================================================================

RE_PREFERRED_BASE = re.compile(
    r'Preferred load address is\s+([0-9A-Fa-f]+)', re.IGNORECASE)

RE_SYMBOL_ENTRY = re.compile(
    r'^\s+([0-9A-Fa-f]+):[0-9A-Fa-f]+\s+'
    r'(\S+)\s+([0-9A-Fa-f]+)\s+(?:([fi])\s+)?(\S+)\s*$')


def parse_map_file(path: Path) -> SymbolTable:
    """Parse an MSVC linker map file."""
    all_lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    table = SymbolTable()

    for line in all_lines:
        m = RE_PREFERRED_BASE.search(line)
        if m:
            table.preferred_base = int(m.group(1), 16)
            break

    raw: list[MapSymbol] = []
    for line in all_lines:
        m = RE_SYMBOL_ENTRY.match(line)
        if not m:
            continue
        seg, name, addr_hex, flag, obj = m.groups()
        addr = int(addr_hex, 16)
        if addr == 0:
            continue
        is_func = flag in ('f', 'i') or seg in ('0001', '0002')
        raw.append(MapSymbol(addr, name, obj.strip(), is_func))

    return _build_table(table, raw)


# =============================================================================
# ELF / symbol table helpers
# =============================================================================

def _build_table(table: SymbolTable, raw: list[MapSymbol]) -> SymbolTable:
    """Sort, deduplicate, and finalize a SymbolTable."""
    raw.sort(key=lambda s: s.address)
    seen: set[int] = set()
    for sym in raw:
        if sym.address not in seen:
            seen.add(sym.address)
            table.symbols.append(sym)
            table.addresses.append(sym.address)
    if table.symbols:
        table.image_end = table.symbols[-1].address + 0x10000
    return table


def is_elf(path: Path) -> bool:
    try:
        with path.open('rb') as f:
            return f.read(4) == b'\x7fELF'
    except OSError:
        return False


def load_symbols(path: Path) -> SymbolSource:
    """Auto-detect symbol file format and load."""
    elf_path: Path | None = None
    dwarf_info: DwarfInfo | None = None

    if is_elf(path):
        elf_path = path
        try:
            dwarf_info = DwarfInfo(path)
            raw = dwarf_info.get_symbols()
        except Exception as e:
            sys.exit(f"Error: failed to read ELF {path}: {e}")
        table = SymbolTable()
        _build_table(table, [MapSymbol(a, n, '', f) for a, n, f in raw])
        src = 'ELF+DWARF'
    else:
        table = parse_map_file(path)
        src = 'MAP'

    func_count = sum(1 for s in table.symbols if s.is_function)
    data_count = len(table.symbols) - func_count
    _log(f"Loaded {len(table.symbols)} symbols ({func_count} code, "
         f"{data_count} data) from {path.name} [{src}]")
    if table.preferred_base:
        _log(f"Preferred base: 0x{table.preferred_base:X}")
    if table.symbols:
        _log(f"Symbol range: 0x{table.addresses[0]:X} - "
             f"0x{table.addresses[-1]:X}")
    if dwarf_info:
        _log("DWARF debug info via pyelftools (native)")

    return SymbolSource(table=table, elf_path=elf_path,
                        name=path.stem, dwarf=dwarf_info)


# =============================================================================
# Path cleanup
# =============================================================================

RE_SRC_PATH = re.compile(r'.*[/\\]source[/\\]src[/\\](.*)')


def _clean_path(raw: str) -> str:
    """Clean cross-compile DWARF paths to readable relative form."""
    raw = re.sub(r'\s*\(discriminator \d+\)', '', raw)
    m = RE_SRC_PATH.search(raw)
    if m:
        return m.group(1).replace('\\', '/')
    return re.sub(r'^.*build/Bin/[A-Z]:[/\\]', '', raw).replace('\\', '/')


# =============================================================================
# ESR decode (ARM64)
# =============================================================================

EC_TABLE: dict[int, str] = {
    0x00: "Unknown", 0x01: "WFI/WFE trap", 0x07: "SVE/SIMD/FP trap",
    0x0E: "Illegal Execution State", 0x15: "SVC (AArch64)",
    0x18: "MSR/MRS trap", 0x20: "Instruction Abort (lower EL)",
    0x21: "Instruction Abort (same EL)", 0x22: "PC Alignment Fault",
    0x24: "Data Abort (lower EL)", 0x25: "Data Abort (same EL)",
    0x26: "SP Alignment Fault", 0x2C: "FP exception",
    0x30: "SError", 0x32: "Breakpoint (lower EL)",
    0x33: "Breakpoint (same EL)", 0x34: "Software Step (lower EL)",
    0x35: "Software Step (same EL)", 0x3C: "BRK (AArch64)",
}
DFSC_TABLE: dict[int, str] = {
    0x00: "Address size fault L0", 0x01: "Address size fault L1",
    0x02: "Address size fault L2", 0x03: "Address size fault L3",
    0x04: "Translation fault L0", 0x05: "Translation fault L1",
    0x06: "Translation fault L2", 0x07: "Translation fault L3",
    0x09: "Access flag fault L1", 0x0A: "Access flag fault L2",
    0x0B: "Access flag fault L3", 0x0D: "Permission fault L1",
    0x0E: "Permission fault L2", 0x0F: "Permission fault L3",
    0x10: "Synchronous external abort", 0x21: "Alignment fault",
}


def format_esr(esr: int, far: int | None) -> list[str]:
    """Decode ARM64 ESR register to human-readable lines."""
    ec = (esr >> 26) & 0x3F
    il = (esr >> 25) & 1
    iss = esr & 0x1FFFFFF
    ec_name = EC_TABLE.get(ec, f"Unknown EC 0x{ec:02X}")
    lines = [f"ESR:       0x{esr:08X} -- EC=0x{ec:02X} {ec_name}, "
             f"IL={il}, ISS=0x{iss:07X}"]
    if ec in (0x20, 0x21, 0x24, 0x25):
        dfsc = iss & 0x3F
        dfsc_name = DFSC_TABLE.get(dfsc, f"DFSC 0x{dfsc:02X}")
        lines.append(f"           {dfsc_name}")
    if far is not None:
        desc = "NULL pointer dereference" if far < 0x100 else ""
        far_line = f"FAR:       0x{far:016X}"
        if desc:
            far_line += f" -- {desc}"
        lines.append(far_line)
    return lines


# =============================================================================
# Crash summary extraction
# =============================================================================

RE_DELL_X86_TYPE = re.compile(r'^Type:\s*(.+?)\s*Source:', re.IGNORECASE)
RE_DELL_ARM64_TYPE = re.compile(r'^Type:\s*(.+)', re.IGNORECASE)
RE_EDK2_TYPE = re.compile(
    r'X64 Exception Type\s*-\s*([0-9a-fA-F]+)\(([^)]+)\)', re.IGNORECASE)


def extract_crash_info(
    lines: list[str], fmt: str, table: SymbolTable, base_delta: int,
) -> CrashInfo:
    """Extract crash metadata from RSOD lines."""
    info = CrashInfo(fmt=fmt, image_base=table.preferred_base)
    regs: dict[str, int] = {}

    # Choose patterns based on format
    if fmt == 'dell_arm64':
        type_pats = [RE_DELL_ARM64_TYPE]
        pc_pats = [RE_PC_LINE]
        reg_pats = [RE_ARM64_REG]
    elif fmt == 'edk2_x64':
        type_pats = [RE_EDK2_TYPE]
        pc_pats = [RE_EDK2_RIP]
        reg_pats = [RE_EDK2_REG]
    else:
        type_pats = [RE_DELL_X86_TYPE]
        pc_pats = [RE_RIP_LINE]
        reg_pats = [RE_DELL_X86_REG]

    for line in lines:
        # Exception description
        if not info.exception_desc:
            for pat in type_pats:
                m = pat.search(line)
                if m:
                    if pat == RE_EDK2_TYPE:
                        info.exception_desc = f"{m.group(2)} (0x{m.group(1)})"
                    else:
                        info.exception_desc = m.group(1).strip()
                    break

        # Crash PC
        for pat in pc_pats:
            m = pat.match(line)
            if m:
                group_idx = 2 if pat == RE_EDK2_RIP else 1
                info.crash_pc = int(m.group(group_idx), 16)

        # Registers
        for pat in reg_pats:
            for reg, val in pat.findall(line):
                regs[reg] = int(val, 16)

    info.registers = regs
    info.sp = regs.get('SP', regs.get('RSP'))
    info.esr = regs.get('ESR')
    info.far = regs.get('FAR')

    # Resolve crash PC
    if info.crash_pc is not None:
        result = table.lookup(info.crash_pc - base_delta)
        if result:
            info.crash_symbol = result[0].name
        else:
            info.crash_symbol = "not in image"

    return info


def format_crash_summary(
    info: CrashInfo, git_ref: GitRef | None = None,
) -> list[str]:
    """Format the --- Crash Summary --- block."""
    lines = ['--- Crash Summary ---']
    if info.exception_desc:
        lines.append(f"Exception: {info.exception_desc}")
    if info.crash_pc is not None:
        sym = f" [{info.crash_symbol}]" if info.crash_symbol else ''
        lines.append(f"Crash PC:  0x{info.crash_pc:X}{sym}")
    if info.image_name:
        base = f" (base 0x{info.image_base:X})" if info.image_base else ''
        lines.append(f"Image:     {info.image_name}{base}")
    if git_ref:
        lines.append(f"Source:    {git_ref.label()}")
    if info.esr is not None:
        lines.extend(format_esr(info.esr, info.far))
    return lines


# =============================================================================
# Backtrace formatter
# =============================================================================

def format_backtrace(
    frames: list[FrameInfo],
    call_verified: dict[int, bool] | None = None,
) -> list[str]:
    """Format a clean gdb-style backtrace."""
    if not frames:
        return []
    verified = call_verified or {}
    lines = ['--- Backtrace ---']
    for f in frames:
        name = f.symbol.name if f.symbol else '???'
        loc = f" at {f.source_loc}" if f.source_loc else ''
        mod = f" [{f.module}]" if f.module else ''
        tag = ''
        if f.address in verified:
            tag = ' [verified]' if verified[f.address] else ' [stale?]'
        lines.append(f"#{f.index:<3d} 0x{f.address:X} in {name}{loc}{mod}{tag}")
        for func, sloc in f.inlines:
            lines.append(f"      (inlined) {func} at {sloc}")
    return lines


# =============================================================================
# Parameter extraction (verbose, frame #0)
# =============================================================================

def _format_vars(
    vars_: list[VarInfo], registers: dict[str, int],
    frame: FrameInfo, label: str,
) -> list[str]:
    """Format a list of VarInfo (params or locals) with register values."""
    if not vars_:
        return []
    func_name = frame.symbol.name.split('(')[0].rsplit('::', 1)[-1] if frame.symbol else '???'
    lines = [f'--- {label} (frame #{frame.index}: {func_name}) ---']
    for v in vars_:
        val_str = ''
        if v.reg_name and v.reg_name in registers:
            val = registers[v.reg_name]
            dec = f"  ({val})" if val < 0x10000 else ''
            val_str = f' = 0x{val:016X}{dec}'
        lines.append(f"  {v.name:<15s} ({v.type_name:<20s}) {v.location}{val_str}")
    return lines


def format_params(
    dwarf_info: DwarfInfo, crash_pc: int, registers: dict[str, int],
    frame: FrameInfo,
) -> list[str]:
    """Format parameters using real DWARF names and PC-accurate locations."""
    return _format_vars(
        dwarf_info.get_params(crash_pc), registers, frame, 'Parameters')


def format_locals(
    dwarf_info: DwarfInfo, crash_pc: int, registers: dict[str, int],
    frame: FrameInfo,
) -> list[str]:
    """Format local variables using DWARF info."""
    return _format_vars(
        dwarf_info.get_locals(crash_pc), registers, frame, 'Locals')


# =============================================================================
# Disassembly context (verbose)
# =============================================================================

def format_disassembly(
    dwarf: DwarfInfo, address: int, context: int = 24,
) -> list[str]:
    """Disassemble around an address using DwarfInfo, marking the target with >."""
    insns = dwarf.disassemble_around(address, context)
    if not insns:
        return []

    # Batch-resolve source lines for all instruction addresses
    src_map = dwarf.source_lines_for_addrs([a for a, _, _ in insns])

    lines = [f'--- Disassembly (0x{address:X}) ---']
    prev_src: str = ''
    for iaddr, mnemonic, op_str in insns:
        src = src_map.get(iaddr, '')
        if src and src != prev_src:
            lines.append(f'  {src}')
            prev_src = src

        marker = '>' if iaddr == address else ' '
        asm_text = f"{mnemonic}  {op_str}".rstrip()
        lines.append(f"  {marker} {iaddr:x}: {asm_text}")

    return lines if len(lines) > 1 else []


# =============================================================================
# Source context (verbose)
# =============================================================================

def format_source_context(
    source_loc: str, source_root: Path, context: int = 3,
    git_ref: GitRef | None = None, repo_root: Path | None = None,
) -> list[str]:
    """Show source lines around the target, marking it with >.
    If git_ref is provided, reads source at that commit via git show."""
    if ':' not in source_loc:
        return []
    file_part, line_part = source_loc.rsplit(':', 1)
    try:
        target_line = int(line_part)
    except ValueError:
        return []

    src_lines: list[str] | None = None
    display_path = file_part

    if git_ref and repo_root:
        # Read from git at the specified commit
        src_lines = _read_source_from_git(git_ref, file_part, repo_root)
        if not src_lines:
            # Try filename-only search via git ls-tree
            filename = Path(file_part).name
            src_lines = _read_source_from_git(git_ref, filename, repo_root)
        if src_lines:
            display_path = f"{file_part} @ {git_ref.short}"
    else:
        # Read from working tree
        src_path = source_root / file_part
        if not src_path.exists():
            filename = Path(file_part).name
            for subtree in ('EPSA', 'ADDF'):
                candidate_dir = source_root / subtree
                if candidate_dir.is_dir():
                    matches = list(candidate_dir.rglob(filename))
                    if len(matches) == 1:
                        src_path = matches[0]
                        display_path = str(src_path.relative_to(source_root))
                        break
            if not src_path.exists():
                return []
        try:
            src_lines = src_path.read_text(
                encoding='utf-8', errors='replace').splitlines()
        except OSError:
            return []

    if not src_lines:
        return []

    start = max(0, target_line - context - 1)
    end = min(len(src_lines), target_line + context)

    out = [f'--- Source ({display_path}) ---']
    for i in range(start, end):
        lineno = i + 1
        marker = '>' if lineno == target_line else ' '
        out.append(f"  {marker} {lineno:4d}: {src_lines[i]}")

    return out if len(out) > 1 else []


# =============================================================================
# Call-site verification
# =============================================================================

def verify_call_sites(
    dwarf: DwarfInfo, addresses: list[int],
) -> dict[int, bool]:
    """Check if return addresses have a preceding call instruction."""
    verified: dict[int, bool] = {}
    for addr in addresses:
        verified[addr] = dwarf.is_call_before(addr)
    return verified


# =============================================================================
# Annotation formatting (inline annotated RSOD lines)
# =============================================================================

def format_annotation(
    sym: MapSymbol, offset: int, source_loc: str = '',
) -> str:
    """Format a symbol lookup result for inline annotation."""
    obj = f"({sym.object_file})" if sym.object_file else ''
    loc = f"  [{source_loc}]" if source_loc else ''
    if sym.is_function:
        return f"<- {sym.name}{obj} + 0x{offset:03X}{loc}"
    return f"--data-- <- {sym.name}{obj}"


def _source_loc(
    line_info: dict[int, list[tuple[str, str]]], addr: int,
) -> str:
    """Get the primary source location for an address from resolved data."""
    entries = line_info.get(addr, [])
    return entries[0][1] if entries else ''


def _lookup_and_annotate(
    addr: int, table: SymbolTable, line_info: dict[int, list[tuple[str, str]]],
) -> str | None:
    """Look up addr, return annotation string or None."""
    result = table.lookup(addr)
    if not result:
        return None
    sym, offset = result
    return format_annotation(sym, offset, _source_loc(line_info, addr))


# =============================================================================
# RSOD line patterns
# =============================================================================

RE_STACK_LINE = re.compile(
    r'^(\s+[0-9A-Fa-f]+\s+)([0-9A-Fa-f]{16})(\s+.*)$')
RE_RIP_LINE = re.compile(r'^-->\s*RIP\s+([0-9A-Fa-f]+)(.*)', re.IGNORECASE)
RE_DELL_X86_REG = re.compile(r'([A-Z0-9]{2})=([0-9A-Fa-f]{16})')
RE_EDK2_RIP = re.compile(r'^(RIP\s+-\s+)([0-9A-Fa-f]+)(.*)')
RE_EDK2_REG = re.compile(r'([A-Z0-9]+)\s+-\s+([0-9A-Fa-f]{16})')
RE_EDK2_IMAGEBASE = re.compile(r'ImageBase=([0-9A-Fa-f]+)', re.IGNORECASE)
RE_ARM64_REG = re.compile(
    r'(X\d+|FP|LR|SP|ELR|SPSR|FPSR|FAR|PC|ESR)=([0-9A-Fa-f]+)')
RE_PC_LINE = re.compile(r'^-->\s*PC\s+([0-9A-Fa-f]+)(.*)', re.IGNORECASE)
RE_ARM64_FRAME = re.compile(
    r'^(s\d+)\s+([0-9A-Fa-f]+)\s+(\S+\.efi)\s+\+([0-9A-Fa-f]+)')


# =============================================================================
# RSOD format detection
# =============================================================================

def detect_format(lines: list[str]) -> str:
    for line in lines:
        if RE_PC_LINE.match(line) or RE_ARM64_FRAME.match(line):
            return 'dell_arm64'
        if line.startswith('--> PC') or line.startswith('-->PC'):
            return 'dell_arm64'
        if RE_ARM64_REG.search(line) and 'X0=' in line:
            return 'dell_arm64'
        if '!!!! X64 Exception' in line or RE_EDK2_RIP.match(line):
            return 'edk2_x64'
        if RE_RIP_LINE.match(line):
            return 'dell_x86'
    return 'dell_x86'


# =============================================================================
# Decode: shared register annotation helper
# =============================================================================

def _annotate_regs(
    line: str, patterns: list[re.Pattern[str]],
    table: SymbolTable, base_delta: int,
) -> str:
    """Annotate register values that resolve to symbols."""
    matches: list[tuple[str, str]] = []
    for pat in patterns:
        matches = pat.findall(line)
        if matches:
            break
    if not matches:
        return line
    anns: list[str] = []
    for reg, val_hex in matches:
        result = table.lookup(int(val_hex, 16) - base_delta)
        if result:
            anns.append(f"{reg}={format_annotation(*result)}")
    return f"{line}  [{', '.join(anns)}]" if anns else line


# =============================================================================
# Decode: shared frame builder (DRY -- used by both x86 and ARM64)
# =============================================================================

def _make_frame(
    index: int, address: int, module: str,
    sym: MapSymbol, offset: int,
    line_info: dict[int, list[tuple[str, str]]],
    info_key: int,
) -> FrameInfo:
    """Build a FrameInfo from a resolved symbol + resolved data."""
    entries = line_info.get(info_key, [])
    loc = entries[0][1] if entries else ''
    inlines = entries[1:] if len(entries) > 1 else []
    return FrameInfo(
        index=index, address=address, module=module,
        symbol=sym, sym_offset=offset, source_loc=loc, inlines=inlines)


def _extract_addr_from_line(
    line: str, patterns: list[tuple[re.Pattern[str], int]],
) -> int | None:
    """Try each (pattern, group_index) pair; return first matched address."""
    for pat, group in patterns:
        m = pat.match(line)
        if m:
            return int(m.group(group), 16)
    return None


# =============================================================================
# Decode: Dell x86 + EDK2 x64
# =============================================================================

# (pattern, capture group for the address)
_RIP_PATTERNS: list[tuple[re.Pattern[str], int]] = [
    (RE_RIP_LINE, 1),
    (RE_EDK2_RIP, 2),
]


def decode_x86(
    lines: list[str], table: SymbolTable, base_delta: int,
    line_info: dict[int, list[tuple[str, str]]],
) -> tuple[list[str], int, list[FrameInfo]]:
    """Decode x86 RSOD. Returns (annotated_lines, resolved_count, frames)."""
    in_registers = False
    in_stack = False
    resolved = 0
    out: list[str] = []
    frames: list[FrameInfo] = []
    frame_idx = 0

    for line in lines:
        has_regs = (RE_DELL_X86_REG.search(line) is not None
                    or RE_EDK2_REG.search(line) is not None)
        if has_regs and not in_stack:
            in_registers = True

        if line.strip().startswith('Stack Dump'):
            in_stack = True
            in_registers = False
            out.append(line)
            continue

        if in_registers and RE_STACK_LINE.match(line):
            in_stack = True
            in_registers = False

        if in_registers and not in_stack:
            out.append(_annotate_regs(
                line, [RE_DELL_X86_REG, RE_EDK2_REG], table, base_delta))
            continue

        # -->RIP or EDK2 RIP
        rip_addr = _extract_addr_from_line(line, _RIP_PATTERNS)
        if rip_addr is not None:
            ann = _lookup_and_annotate(rip_addr - base_delta, table, line_info)
            if ann:
                out.append(f"{line} {ann}")
                resolved += 1
            else:
                out.append(line)
            continue

        # Stack dump lines
        sm = RE_STACK_LINE.match(line) if in_stack else None
        if sm:
            value = int(sm.group(2), 16)
            adjusted = value - base_delta
            result = table.lookup(adjusted)
            if result:
                sym, offset = result
                out.append(f"{line} {format_annotation(
                    sym, offset, _source_loc(line_info, adjusted))}")
                resolved += 1
                frames.append(_make_frame(
                    frame_idx, value, '', sym, offset, line_info, adjusted))
                frame_idx += 1
            else:
                out.append(line)
            continue

        out.append(line)

    return out, resolved, frames


# =============================================================================
# Decode: Dell ARM64
# =============================================================================

def decode_arm64(
    lines: list[str], table: SymbolTable, base_delta: int,
    line_info_by_module: dict[str, dict[int, list[tuple[str, str]]]],
    extra_sources: dict[str, SymbolSource] | None = None,
    default_module_key: str = '',
) -> tuple[list[str], int, list[FrameInfo]]:
    """Decode ARM64 RSOD. Returns (annotated_lines, resolved_count, frames).

    line_info_by_module maps module key -> {addr: [(func, loc), ...]}.
    The default_module_key is for the primary symbol file.
    """
    resolved = 0
    out: list[str] = []
    frames: list[FrameInfo] = []
    frame_idx = 0

    # Flat line_info for -->PC (not module-scoped)
    default_info = line_info_by_module.get(default_module_key, {})

    for line in lines:
        # --> PC line
        pc_match = RE_PC_LINE.match(line)
        if pc_match:
            addr = int(pc_match.group(1), 16)
            ann = _lookup_and_annotate(addr - base_delta, table, default_info)
            if ann:
                out.append(f"{line} {ann}")
                resolved += 1
            else:
                out.append(line)
            continue

        # sNN frame lines
        fm = RE_ARM64_FRAME.match(line)
        if fm:
            module = fm.group(3)
            offset_in_module = int(fm.group(4), 16)

            # Multi-module: pick the right symbol source and line info
            mod_key = module.replace('.efi', '').lower()
            src = (extra_sources or {}).get(mod_key)
            use_table = src.table if src else table
            # Try module-specific line info, fall back to primary
            use_info = line_info_by_module.get(
                mod_key, line_info_by_module.get(default_module_key, {}))

            if use_table.preferred_base == 0:
                lookup_addr = offset_in_module
            else:
                lookup_addr = use_table.preferred_base + offset_in_module

            result = use_table.lookup(lookup_addr)
            if result:
                sym, off = result
                loc = _source_loc(use_info, offset_in_module)
                out.append(f"{line}  {format_annotation(sym, off, loc)}")
                resolved += 1
                frames.append(_make_frame(
                    frame_idx, offset_in_module, module,
                    sym, off, use_info, offset_in_module))
                frame_idx += 1
            else:
                out.append(line)
                frames.append(FrameInfo(
                    index=frame_idx, address=offset_in_module, module=module))
                frame_idx += 1
            continue

        # Register lines
        if RE_ARM64_REG.search(line):
            out.append(_annotate_regs(
                line, [RE_ARM64_REG], table, base_delta))
            continue

        out.append(line)

    return out, resolved, frames


# =============================================================================
# Utility
# =============================================================================

def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


# =============================================================================
# Git source resolution
# =============================================================================

import subprocess as _subprocess


@dataclass
class GitRef:
    """Resolved git reference for source context."""
    commit: str        # full commit hash
    short: str         # short hash
    summary: str       # commit subject line
    ref_name: str      # original --tag or --commit value

    def label(self) -> str:
        return f"{self.short} ({self.summary})"


def _resolve_git_ref(ref: str, repo_root: Path) -> GitRef | None:
    """Validate a git tag or commit hash and return its info."""
    try:
        r = _subprocess.run(
            ['git', '-C', str(repo_root), 'log', '--format=%H%n%h%n%s',
             '-1', ref],
            capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return None
        lines = r.stdout.strip().splitlines()
        if len(lines) < 3:
            return None
        return GitRef(
            commit=lines[0], short=lines[1],
            summary=lines[2], ref_name=ref)
    except (FileNotFoundError, _subprocess.TimeoutExpired):
        return None


def _read_source_from_git(
    git_ref: GitRef, file_path: str, repo_root: Path,
) -> list[str] | None:
    """Read source file at a specific git commit."""
    # Try the path directly with common prefixes
    for prefix in ('source/src/', ''):
        git_path = f"{prefix}{file_path}"
        lines = _git_show(git_ref.commit, git_path, repo_root)
        if lines is not None:
            return lines

    # Fallback: search by filename in EPSA/ and ADDF/ subtrees
    filename = Path(file_path).name
    for subtree in ('source/src/EPSA', 'source/src/ADDF'):
        found = _git_find_file(git_ref.commit, filename, subtree, repo_root)
        if found:
            return _git_show(git_ref.commit, found, repo_root)

    return None


def _git_show(
    commit: str, path: str, repo_root: Path,
) -> list[str] | None:
    """Run git show commit:path, return lines or None."""
    try:
        r = _subprocess.run(
            ['git', '-C', str(repo_root), 'show', f'{commit}:{path}'],
            capture_output=True, text=True, timeout=10)
        return r.stdout.splitlines() if r.returncode == 0 else None
    except (FileNotFoundError, _subprocess.TimeoutExpired):
        return None


def _git_find_file(
    commit: str, filename: str, subtree: str, repo_root: Path,
) -> str | None:
    """Find a file by name in a subtree at a specific commit."""
    try:
        r = _subprocess.run(
            ['git', '-C', str(repo_root), 'ls-tree', '-r', '--name-only',
             commit, subtree],
            capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return None
        matches = [p for p in r.stdout.splitlines() if p.endswith(f'/{filename}')]
        return matches[0] if len(matches) == 1 else None
    except (FileNotFoundError, _subprocess.TimeoutExpired):
        return None


# =============================================================================
# Main decode orchestrator
# =============================================================================

def _resolve_addresses_dwarf(
    dwarf_info: DwarfInfo, addresses: list[int],
) -> dict[int, list[tuple[str, str]]]:
    """Resolve addresses via DwarfInfo.
    Returns {addr: [(func, file:line), ...]} for compatibility with
    the line_info dict format used by the decoders."""
    resolved_raw = dwarf_info.resolve_addresses(addresses)
    result: dict[int, list[tuple[str, str]]] = {}
    for addr, info in resolved_raw.items():
        pairs: list[tuple[str, str]] = []
        if info.function and info.source_loc:
            pairs.append((info.function, _clean_path(info.source_loc)))
        for func, loc in info.inlines:
            pairs.append((func, _clean_path(loc)))
        if pairs:
            result[addr] = pairs
    return result


def decode_rsod(
    log_path: Path, sym_path: Path, out_path: Path,
    base_override: int | None, verbose: bool,
    extra_sym_paths: list[Path], source_root: Path | None,
    git_ref: GitRef | None = None, repo_root: Path | None = None,
) -> None:
    """Read RSOD log + symbol file, write annotated + enhanced output."""
    source = load_symbols(sym_path)
    table = source.table

    # Load extra symbol files for multi-module
    extra_sources: dict[str, SymbolSource] = {}
    for p in extra_sym_paths:
        s = load_symbols(p)
        extra_sources[p.stem.lower()] = s

    lines = log_path.read_text(encoding='utf-8', errors='replace').splitlines()
    fmt = detect_format(lines)
    _log(f"RSOD format: {fmt}")

    # Base delta
    base_delta = 0
    if base_override is not None:
        base_delta = base_override - table.preferred_base
        _log(f"Base override: 0x{base_override:X} (delta: {base_delta:+X})")
    elif fmt == 'edk2_x64':
        for line in lines:
            m = RE_EDK2_IMAGEBASE.search(line)
            if m:
                detected = int(m.group(1), 16)
                if detected != table.preferred_base:
                    base_delta = detected - table.preferred_base
                    _log(f"Auto-detected ImageBase: 0x{detected:X}")
                break

    # Collect addresses and resolve -- per-module for ARM64
    default_key = source.name.lower()
    line_info_by_module: dict[str, dict[int, list[tuple[str, str]]]] = {}

    if fmt == 'dell_arm64':
        # Group addresses by module
        module_addrs: dict[str, list[int]] = {}
        for line in lines:
            fm = RE_ARM64_FRAME.match(line)
            if fm:
                mod_key = fm.group(3).replace('.efi', '').lower()
                module_addrs.setdefault(mod_key, []).append(
                    int(fm.group(4), 16))
            pc = RE_PC_LINE.match(line)
            if pc:
                module_addrs.setdefault(default_key, []).append(
                    int(pc.group(1), 16))

        # Resolve each module against its own ELF
        dedicated: dict[str, SymbolSource] = {
            k: v for k, v in extra_sources.items() if v.has_debug_info()}
        for mod_key, addrs in module_addrs.items():
            mod_src = dedicated.get(mod_key, source)
            if mod_src.has_debug_info() and mod_src.dwarf:
                src_key = mod_key if mod_key in dedicated else default_key
                info = _resolve_addresses_dwarf(mod_src.dwarf, addrs)
                if info:
                    line_info_by_module.setdefault(src_key, {}).update(info)
                    _log(f"resolve [{mod_key}]: "
                         f"{len(info)}/{len(addrs)} resolved")
    elif source.has_debug_info() and source.dwarf:
        addrs = _collect_x86_addrs(lines, table, base_delta)
        if addrs:
            info = _resolve_addresses_dwarf(source.dwarf, addrs)
            if info:
                line_info_by_module[default_key] = info
                _log(f"resolve: {len(info)}/{len(addrs)} addresses")

    # Extract crash info
    crash_info = extract_crash_info(lines, fmt, table, base_delta)
    crash_info.image_name = source.name

    # Decode (annotated lines + frames)
    if fmt == 'dell_arm64':
        annotated, resolved, frames = decode_arm64(
            lines, table, base_delta, line_info_by_module,
            extra_sources, default_key)
    else:
        # x86 uses a flat dict -- get the default module's info
        flat_info = line_info_by_module.get(default_key, {})
        annotated, resolved, frames = decode_x86(
            lines, table, base_delta, flat_info)

    # Call-site verification via capstone (ELF sources only)
    call_verified: dict[int, bool] = {}
    if source.dwarf and frames:
        call_verified = verify_call_sites(
            source.dwarf, [f.address for f in frames])

    # Assemble output
    result: list[str] = []
    result.extend(format_crash_summary(crash_info, git_ref))
    result.append('')
    result.extend(annotated)
    result.append('')
    result.extend(format_backtrace(frames, call_verified))

    # Verbose sections for frame #0
    if verbose and frames:
        f0 = frames[0]

        # Parameters -- DWARF real names
        if source.dwarf:
            params = format_params(
                source.dwarf, f0.address, crash_info.registers, f0)
            if params:
                result.append('')
                result.extend(params)

            # Local variables
            locals_ = format_locals(
                source.dwarf, f0.address, crash_info.registers, f0)
            if locals_:
                result.append('')
                result.extend(locals_)

            # Disassembly via capstone
            if f0.address:
                disasm = format_disassembly(source.dwarf, f0.address)
                if disasm:
                    result.append('')
                    result.extend(disasm)

        if (source_root or git_ref) and f0.source_loc:
            src = format_source_context(
                f0.source_loc, source_root or Path('.'),
                git_ref=git_ref, repo_root=repo_root)
            if src:
                result.append('')
                result.extend(src)

    out_path.write_text('\n'.join(result) + '\n', encoding='utf-8')
    _log(f"Resolved {resolved} addresses")
    _log(f"Output: {out_path}")


def _collect_x86_addrs(
    lines: list[str], table: SymbolTable, base_delta: int,
) -> list[int]:
    """Collect resolvable addresses from x86/EDK2 RSOD lines."""
    addrs: list[int] = []
    in_stack = False
    for line in lines:
        if line.strip().startswith('Stack Dump'):
            in_stack = True
            continue
        for pat in (RE_RIP_LINE, RE_EDK2_RIP):
            m = pat.match(line)
            if m:
                addr = int(m.group(1 if pat == RE_RIP_LINE else 2), 16)
                adj = addr - base_delta
                if table.lookup(adj):
                    addrs.append(adj)
        if in_stack:
            sm = RE_STACK_LINE.match(line)
            if sm:
                adj = int(sm.group(2), 16) - base_delta
                if table.lookup(adj):
                    addrs.append(adj)
    return addrs


# =============================================================================
# CLI
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Decode RSOD stack dumps using MSVC map files or ELF binaries.')
    parser.add_argument('rsod_log', type=Path,
                        help='RSOD serial console capture (putty log)')
    parser.add_argument('symbol_file', type=Path,
                        help='MSVC .map file or ELF binary (.efi/.so)')
    parser.add_argument('-o', '--output', type=Path, default=None,
                        help='Output file (default: <log>_decode.txt)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show disassembly, source context, parameters')
    parser.add_argument('-s', '--sym', action='append', type=Path, default=[],
                        help='Additional symbol files for multi-module traces')
    parser.add_argument('--base', type=str, default=None,
                        help='Override image base address (hex)')
    parser.add_argument('--source-root', type=Path, default=None,
                        help='Local source tree root for source context')
    parser.add_argument('--tag', type=str, default=None,
                        help='Git tag for source context (e.g. 4305.3)')
    parser.add_argument('--commit', type=str, default=None,
                        help='Git commit hash for source context')
    args = parser.parse_args()

    if not args.rsod_log.exists():
        sys.exit(f"Error: RSOD log not found: {args.rsod_log}")
    if not args.symbol_file.exists():
        sys.exit(f"Error: symbol file not found: {args.symbol_file}")
    for s in args.sym:
        if not s.exists():
            sys.exit(f"Error: extra symbol file not found: {s}")

    out_path = args.output or args.rsod_log.with_name(
        f"{args.rsod_log.stem}_decode{args.rsod_log.suffix}")

    base_override: int | None = None
    if args.base is not None:
        try:
            base_override = int(args.base, 16)
        except ValueError:
            sys.exit(f"Error: invalid base address: {args.base}")

    # Default source root: infer from script location
    # Script is at scripts/rsod-decode/rsod-decode.py, so parents[3] = source/src/
    source_root = args.source_root
    if source_root is None:
        candidate = Path(__file__).resolve().parents[3]
        if candidate.is_dir():
            source_root = candidate

    # Resolve git ref (tag or commit) for source context
    git_ref: GitRef | None = None
    repo_root: Path | None = None
    ref_str = args.tag or args.commit
    if ref_str:
        # Find the repo root (walk up from source_root or script location)
        for candidate_root in (source_root, Path(__file__).resolve().parents[4]):
            if candidate_root and (candidate_root / '.git').exists():
                repo_root = candidate_root
                break
            # Check parent — source/src/ → source/ → repo root
            for p in (candidate_root,) if candidate_root else ():
                for parent in p.parents:
                    if (parent / '.git').exists():
                        repo_root = parent
                        break
                if repo_root:
                    break
            if repo_root:
                break

        if repo_root:
            git_ref = _resolve_git_ref(ref_str, repo_root)
            if git_ref:
                _log(f"Source: {git_ref.label()}")
            else:
                _log(f"Warning: git ref '{ref_str}' not found in {repo_root}")
        else:
            _log("Warning: git repo not found, --tag/--commit ignored")

    decode_rsod(args.rsod_log, args.symbol_file, out_path,
                base_override, args.verbose, args.sym,
                source_root, git_ref, repo_root)


if __name__ == '__main__':
    main()
