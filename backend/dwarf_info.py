"""DWARF debug info interface for crash analysis.

Provides the DwarfInfo class for symbol resolution, disassembly,
source line mapping, and parameter/local variable extraction from
ELF binaries with DWARF debug info.
"""
from __future__ import annotations

import re
from pathlib import Path

import cxxfilt
from capstone import CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_ARM, CS_MODE_64, Cs
from elftools.elf.elffile import ELFFile
from elftools.dwarf.die import DIE
from elftools.dwarf.compileunit import CompileUnit
from elftools.dwarf.descriptions import (
    describe_form_class, describe_reg_name, set_global_machine_arch,
)
from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.dwarf.locationlists import LocationParser

from .models import AddressInfo, VarInfo, clean_path

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
    # DWARF v4+: high_pc can be an offset (constant) rather than an address
    if describe_form_class(high_attr.form) == 'constant':
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


def _resolve_byte_size(die: DIE | None, depth: int = 0) -> int:
    """Resolve the byte size of a type DIE, following qualifiers/typedefs.

    Pointers always return 8 (ARM64/x86-64). Qualifiers (const, volatile,
    etc.) are transparent and forward to the underlying type.
    """
    if depth > 10 or die is None:
        return 0
    tag = die.tag

    # Base types, structs, enums, unions have DW_AT_byte_size directly
    bs = die.attributes.get('DW_AT_byte_size')
    if bs is not None:
        return bs.value

    # Pointers/references are always pointer-sized
    if tag in ('DW_TAG_pointer_type', 'DW_TAG_reference_type'):
        return 8

    # Qualifiers and typedefs are transparent — follow DW_AT_type
    if 'DW_AT_type' in die.attributes:
        return _resolve_byte_size(
            die.get_DIE_from_attribute('DW_AT_type'), depth + 1)
    return 0


def _decode_location(loc_expr: list[int] | bytes,
                     expr_parser: DWARFExprParser,
                     structs: object | None = None,
                     ) -> tuple[str, str | None]:
    """Decode a DWARF location expression to (description, register_name).

    Uses pyelftools' DWARFExprParser for parsing and describe_reg_name
    for register names, instead of hand-coded opcode tables.
    """
    if not loc_expr:
        return 'optimized out', None

    try:
        parsed = expr_parser.parse_expr(bytes(loc_expr))
    except Exception:
        return f'expr[{" ".join(f"{b:02X}" for b in loc_expr)}]', None

    if not parsed:
        return 'optimized out', None

    op = parsed[0]

    # DW_OP_regN — variable lives in a register
    if op.op_name.startswith('DW_OP_reg') and not op.op_name.startswith('DW_OP_regx'):
        regnum = int(op.op_name[len('DW_OP_reg'):])
        regname = describe_reg_name(regnum).upper()
        return regname, regname

    # DW_OP_bregN — register + offset (indirect)
    if op.op_name.startswith('DW_OP_breg') and not op.op_name.startswith('DW_OP_bregx'):
        regnum = int(op.op_name[len('DW_OP_breg'):])
        regname = describe_reg_name(regnum).upper()
        offset = op.args[0] if op.args else 0
        if offset:
            return f'[{regname}{offset:+d}]', None
        return f'[{regname}]', None

    # DW_OP_fbreg — frame base + offset
    if op.op_name == 'DW_OP_fbreg':
        offset = op.args[0] if op.args else 0
        return f'[FP{offset:+d}]', None

    # DW_OP_addr — absolute address
    if op.op_name == 'DW_OP_addr':
        addr = op.args[0] if op.args else 0
        return f'0x{addr:X}', None

    # Fallback: use pyelftools' describe for complex expressions
    if structs is not None:
        from elftools.dwarf.descriptions import describe_DWARF_expr
        return describe_DWARF_expr(bytes(loc_expr), structs), None
    return f'expr[{" ".join(f"{b:02X}" for b in loc_expr)}]', None


# =============================================================================
# DwarfInfo class
# =============================================================================

class DwarfInfo:
    """High-level DWARF interface for crash analysis."""

    def __init__(self, elf_path: Path, dwarf_prefix: str | None = None,
                 repo_root: Path | None = None) -> None:
        self._path = elf_path
        self._file = elf_path.open('rb')
        try:
            self._elf = ELFFile(self._file)
        except Exception:
            self._file.close()
            raise
        self._dwarf = None
        if self._elf.has_dwarf_info():
            try:
                self._dwarf = self._elf.get_dwarf_info()
            except Exception:
                # Fallback: skip relocation processing (needed for EDK2 GCC
                # .debug/.dll files that contain R_AARCH64_NONE relocations)
                self._dwarf = self._elf.get_dwarf_info(
                    relocate_dwarf_sections=False)
        self._aranges = self._dwarf.get_aranges() if self._dwarf else None
        self._loc_parser = (LocationParser(self._dwarf.location_lists())
                            if self._dwarf else None)

        # DWARF path prefix — stripped from all resolved paths to produce
        # paths relative to the repo root. Auto-detected if not specified.
        if dwarf_prefix is not None:
            self._dwarf_prefix = dwarf_prefix.replace('\\', '/')
        else:
            self._dwarf_prefix = self._detect_dwarf_prefix(repo_root)

        # Detect architecture for register names and disassembly
        arch = self._elf.get_machine_arch()
        if arch == 'AArch64':
            self._cs_arch = CS_ARCH_ARM64
            self._cs_mode = CS_MODE_ARM
            set_global_machine_arch('AArch64')
        elif arch in ('x64', 'x86'):
            self._cs_arch = CS_ARCH_X86
            self._cs_mode = CS_MODE_64
            set_global_machine_arch('x64')
        else:
            self._cs_arch = CS_ARCH_ARM64
            self._cs_mode = CS_MODE_ARM
            set_global_machine_arch('AArch64')

        # DWARF expression parser (for location decoding)
        if self._dwarf:
            self._expr_parser = DWARFExprParser(self._dwarf.structs)
        else:
            self._expr_parser = None

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

    @property
    def dwarf_prefix(self) -> str:
        """The detected or configured DWARF path prefix."""
        return self._dwarf_prefix

    def _detect_dwarf_prefix(self, repo_root: Path | None) -> str:
        """Auto-detect the DWARF path prefix from CU names.

        Finds the common prefix across all DW_AT_name values, then validates
        against repo_root if provided (tries suffixes until a file matches).
        """
        if not self._dwarf:
            return ''

        # Collect CU name paths
        cu_names: list[str] = []
        for cu in self._dwarf.iter_CUs():
            die = cu.get_top_DIE()
            name_attr = die.attributes.get('DW_AT_name')
            if name_attr:
                cu_names.append(name_attr.value.decode().replace('\\', '/'))

        if not cu_names:
            return ''

        # Find common prefix (using / as separator)
        prefix = cu_names[0]
        for name in cu_names[1:]:
            while prefix and not name.startswith(prefix):
                slash = prefix.rfind('/')
                prefix = prefix[:slash] if slash >= 0 else ''
            if not prefix:
                break

        # Trim to last directory separator
        if prefix and not prefix.endswith('/'):
            slash = prefix.rfind('/')
            prefix = prefix[:slash + 1] if slash >= 0 else ''

        if not prefix:
            return ''

        # If repo_root provided, validate by checking suffixes exist on disk
        if repo_root:
            for name in cu_names[:20]:
                rel = name[len(prefix):]
                if (repo_root / rel).is_file():
                    return prefix

            # Common prefix didn't produce valid paths — try shorter prefixes
            # by removing trailing directory components
            parts = prefix.rstrip('/').split('/')
            for i in range(len(parts) - 1, 0, -1):
                candidate = '/'.join(parts[:i]) + '/'
                for name in cu_names[:5]:
                    rel = name[len(candidate):]
                    if (repo_root / rel).is_file():
                        return candidate

        return prefix

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

        # Demangle C++ names
        demangled = [cxxfilt.demangle(n) for n in mangled_names]

        result: list[tuple[int, str, bool]] = []
        for (addr, _name, is_func), dem_name in zip(raw, demangled):
            result.append((addr, dem_name, is_func))

        result.sort(key=lambda x: x[0])
        return result

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
        cu = self._get_cu_for_addr(addrs[0])
        if not cu:
            return {}
        lp = self._dwarf.line_program_for_CU(cu)
        if not lp:
            return {}

        addr_set = set(addrs)
        result: dict[int, str] = {}
        prevstate = None

        for entry in lp.get_entries():
            state = entry.state
            if state is None:
                continue
            if prevstate:
                for a in list(addr_set):
                    if prevstate.address <= a < state.address:
                        raw = self._format_file_line(
                            lp, prevstate.file, prevstate.line, cu)
                        if raw:
                            result[a] = clean_path(raw)
                        addr_set.discard(a)
                if not addr_set:
                    return result
            if state.end_sequence:
                prevstate = None
            else:
                prevstate = state

        return result

    def _format_file_line(self, lp: object, file_idx: int, line: int,
                          cu: CompileUnit | None = None) -> str:
        """Format a file:line string from line program data.

        Joins the include directory with the filename, then strips the
        DWARF prefix to produce a repo-relative path.

        When the file resolves against comp_dir (dir index 1, the build
        CWD) and matches the CU's main source file, uses DW_AT_name
        instead — comp_dir paths are often build-directory copies that
        don't exist in the source tree.
        """
        # DWARF5 uses 0-based file/dir indices; DWARF4 and earlier use 1-based
        v5 = cu is not None and cu['version'] >= 5
        file_table_idx = file_idx if v5 else file_idx - 1
        if file_table_idx < 0 or file_table_idx >= len(lp['file_entry']):
            return ''
        file_entry = lp['file_entry'][file_table_idx]
        fname = (file_entry.name.decode()
                 if isinstance(file_entry.name, bytes) else file_entry.name)
        dir_idx = file_entry.dir_index
        dirs = lp['include_directory']

        # Resolve directory: DWARF5 dirs[dir_idx], DWARF4 dirs[dir_idx - 1]
        dir_table_idx = dir_idx if v5 else dir_idx - 1
        if 0 <= dir_table_idx < len(dirs):
            d = dirs[dir_table_idx]
            d = d.decode() if isinstance(d, bytes) else d
            fname = f'{d}/{fname}'

        # Normalize separators and strip the DWARF prefix
        fname = fname.replace('\\', '/')
        if self._dwarf_prefix and fname.startswith(self._dwarf_prefix):
            fname = fname[len(self._dwarf_prefix):]

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
        return self._dwarf.get_CU_at(cu_offset)

    # -----------------------------------------------------------------
    # Internal: line program resolution
    # -----------------------------------------------------------------

    def _addr_to_line(self, cu: CompileUnit, addr: int) -> str:
        """Resolve addr to "dir/file:line" using the CU's line program.

        Follows the pyelftools dwarf_decode_address.py example pattern:
        walk state entries, track prevstate, match when addr falls in
        [prevstate.address, state.address).
        """
        lp = self._dwarf.line_program_for_CU(cu)
        if not lp:
            return ''

        prevstate = None
        for entry in lp.get_entries():
            state = entry.state
            if state is None:
                continue
            if prevstate and prevstate.address <= addr < state.address:
                return self._format_file_line(
                    lp, prevstate.file, prevstate.line, cu)
            if state.end_sequence:
                prevstate = None
            else:
                prevstate = state
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
                            loc = self._format_file_line(
                                lp, call_file.value, call_line.value, cu)
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

            # Type and byte size
            if 'DW_AT_type' in resolved.attributes:
                type_die = resolved.get_DIE_from_attribute('DW_AT_type')
                var.type_name = _resolve_type(type_die)
                var.byte_size = _resolve_byte_size(type_die)
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
                        if best and self._expr_parser:
                            var.location, var.reg_name = _decode_location(
                                best, self._expr_parser, self._dwarf.structs)
                        else:
                            var.location = 'optimized out'
                    elif self._expr_parser:
                        var.location, var.reg_name = _decode_location(
                            loc_data.loc_expr, self._expr_parser, self._dwarf.structs)
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
