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
from elftools.dwarf.callframe import FDE, RegisterRule
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


def _strip_qualifiers(die: DIE | None, depth: int = 0) -> DIE | None:
    """Follow const/volatile/typedef qualifiers to the underlying type."""
    if depth > 10 or die is None:
        return None
    if die.tag in ('DW_TAG_const_type', 'DW_TAG_volatile_type',
                    'DW_TAG_typedef', 'DW_TAG_restrict_type'):
        if 'DW_AT_type' in die.attributes:
            return _strip_qualifiers(
                die.get_DIE_from_attribute('DW_AT_type'), depth + 1)
        return None
    return die


def _member_offset(die: DIE) -> int:
    """Get the byte offset of a struct/class member or base class."""
    attr = die.attributes.get('DW_AT_data_member_location')
    if attr is None:
        return 0
    if isinstance(attr.value, int):
        return attr.value
    # DWARF expression — common case is DW_OP_plus_uconst
    if isinstance(attr.value, list) and len(attr.value) >= 2:
        if attr.value[0] == 0x23:  # DW_OP_plus_uconst
            return attr.value[1]
    return 0


_ACCESS_MAP = {1: 'public', 2: 'protected', 3: 'private'}


def _access_str(die: DIE) -> str:
    """Get accessibility string for a class member."""
    attr = die.attributes.get('DW_AT_accessibility')
    if attr:
        return _ACCESS_MAP.get(attr.value, '')
    return ''


def _is_string_type(type_name: str) -> bool:
    """Check if a type name represents a C string pointer."""
    normalized = type_name.replace('const ', '').replace('volatile ', '').strip()
    return normalized in ('char*', 'CHAR8*', 'unsigned char*', 'signed char*')


def _resolve_enum_name(die: DIE, value: int) -> str | None:
    """Resolve an enum value to its enumerator name."""
    for child in die.iter_children():
        if child.tag == 'DW_TAG_enumerator':
            val_attr = child.attributes.get('DW_AT_const_value')
            if val_attr and val_attr.value == value:
                name_attr = child.attributes.get('DW_AT_name')
                return name_attr.value.decode() if name_attr else None
    return None


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

    # DW_OP_fbreg — CFA (Canonical Frame Address) + offset
    if op.op_name == 'DW_OP_fbreg':
        offset = op.args[0] if op.args else 0
        return f'[CFA{offset:+d}]', None

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
# CFI-based register unwinding
# =============================================================================

# DWARF register numbers → register name convention, per architecture
_ARM64_REG_NAMES: dict[int, str] = {
    **{i: f'X{i}' for i in range(29)},
    29: 'FP', 30: 'LR', 31: 'SP',
}
_ARM64_CALLEE_SAVED = {
    'X19', 'X20', 'X21', 'X22', 'X23',
    'X24', 'X25', 'X26', 'X27', 'X28', 'FP',
}

_X86_64_REG_NAMES: dict[int, str] = {
    0: 'RAX', 1: 'RDX', 2: 'RCX', 3: 'RBX',
    4: 'RSI', 5: 'RDI', 6: 'RBP', 7: 'RSP',
    8: 'R8', 9: 'R9', 10: 'R10', 11: 'R11',
    12: 'R12', 13: 'R13', 14: 'R14', 15: 'R15',
    16: 'RIP',
}
_X86_64_CALLEE_SAVED = {'RBX', 'RBP', 'R12', 'R13', 'R14', 'R15'}


class CFIUnwinder:
    """Reconstruct per-frame register state using .eh_frame CFI rules.

    Given crash-time registers and stack memory, walks the call chain
    applying CFI rules at each frame to recover the caller's registers.
    """

    def __init__(
        self, fde_list: list[FDE],
        reg_names: dict[int, str],
        callee_saved: set[str],
    ) -> None:
        self._fdes = sorted(fde_list, key=lambda f: f['initial_location'])
        self._starts = [f['initial_location'] for f in self._fdes]
        self._reg_names = reg_names
        self._callee_saved = callee_saved

    def _find_fde(self, pc: int) -> FDE | None:
        """Find the FDE covering a given PC via binary search."""
        import bisect
        idx = bisect.bisect_right(self._starts, pc) - 1
        if idx < 0:
            return None
        fde = self._fdes[idx]
        if pc < fde['initial_location'] + fde['address_range']:
            return fde
        return None

    def compute_cfa(self, pc: int, registers: dict[str, int]) -> int:
        """Compute the CFA (Canonical Frame Address) for a given PC and registers."""
        fde = self._find_fde(pc)
        if fde is None:
            return 0
        decoded = fde.get_decoded()
        if not decoded.table:
            return 0
        best = decoded.table[0]
        for row in decoded.table:
            if row['pc'] <= pc:
                best = row
            else:
                break
        cfa_rule = best['cfa']
        if cfa_rule.expr is not None:
            return 0
        cfa_reg_name = self._reg_names.get(cfa_rule.reg, f'R{cfa_rule.reg}')
        cfa_base = registers.get(cfa_reg_name)
        if cfa_base is None:
            return 0
        return cfa_base + cfa_rule.offset

    def unwind_frame(
        self, pc: int, registers: dict[str, int],
        stack_base: int, stack_mem: bytes,
    ) -> dict[str, int] | None:
        """Unwind one frame: given register state at `pc`, return caller's registers.

        Returns None if CFI rules are unavailable for this PC.
        """
        fde = self._find_fde(pc)
        if fde is None:
            return None

        decoded = fde.get_decoded()
        if not decoded.table:
            return None

        # Find the last CFI row with row.pc <= pc
        best = decoded.table[0]
        for row in decoded.table:
            if row['pc'] <= pc:
                best = row
            else:
                break

        # Compute CFA (Canonical Frame Address)
        cfa_rule = best['cfa']
        if cfa_rule.expr is not None:
            return None  # CFA expressions not supported yet
        cfa_reg_name = self._reg_names.get(cfa_rule.reg, f'R{cfa_rule.reg}')
        cfa_base = registers.get(cfa_reg_name)
        if cfa_base is None:
            return None
        cfa = cfa_base + cfa_rule.offset

        def read_mem(addr: int, size: int = 8) -> int | None:
            off = addr - stack_base
            if off < 0 or off + size > len(stack_mem):
                return None
            return int.from_bytes(stack_mem[off:off + size], 'little')

        caller_regs: dict[str, int] = {}
        for key, rule in best.items():
            if key in ('pc', 'cfa'):
                continue
            if not hasattr(rule, 'type'):
                continue
            name = self._reg_names.get(key, f'R{key}') if isinstance(key, int) else str(key)
            if rule.type == RegisterRule.OFFSET:
                val = read_mem(cfa + rule.arg)
                if val is not None:
                    caller_regs[name] = val
            elif rule.type == RegisterRule.SAME_VALUE:
                if name in registers:
                    caller_regs[name] = registers[name]
            elif rule.type == RegisterRule.REGISTER:
                src = self._reg_names.get(rule.arg, f'R{rule.arg}')
                if src in registers:
                    caller_regs[name] = registers[src]

        # Stack pointer in the caller = CFA (by definition)
        # Use the CFA's base register name (SP on ARM64, RSP on x86-64)
        caller_regs[cfa_reg_name] = cfa

        # Callee-saved registers not mentioned in CFI are implicitly
        # SAME_VALUE (ABI guarantee). Carry them forward.
        for name in self._callee_saved:
            if name not in caller_regs and name in registers:
                caller_regs[name] = registers[name]

        return caller_regs


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

        # Cache ELF sections for memory reads
        self._sections: list[tuple[int, bytes]] = []  # (base_addr, data)
        for name in ('.text', '.rodata', '.data'):
            sec = self._elf.get_section_by_name(name)
            if sec and sec['sh_size'] > 0:
                self._sections.append((sec['sh_addr'], sec.data()))
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

    def get_cfi_unwinder(self) -> CFIUnwinder | None:
        """Create a CFI unwinder from .eh_frame data, or None if unavailable."""
        if not self._dwarf:
            return None
        try:
            fdes = [e for e in self._dwarf.EH_CFI_entries()
                    if isinstance(e, FDE)]
        except Exception:
            return None
        if not fdes:
            return None
        if self._cs_arch == CS_ARCH_ARM64:
            reg_names = _ARM64_REG_NAMES
            callee_saved = _ARM64_CALLEE_SAVED
        else:
            reg_names = _X86_64_REG_NAMES
            callee_saved = _X86_64_CALLEE_SAVED
        return CFIUnwinder(fdes, reg_names, callee_saved)

    # -----------------------------------------------------------------
    # Memory reading (ELF sections + external stack dump)
    # -----------------------------------------------------------------

    def read_memory(
        self, addr: int, size: int,
        stack_base: int = 0, stack_mem: bytes = b'',
        image_base: int = 0,
    ) -> bytes | None:
        """Read `size` bytes from `addr`, checking stack dump then ELF sections.

        For ELF section reads, `image_base` is subtracted from `addr` to
        translate runtime addresses back to ELF file offsets.
        """
        # Try stack dump first (runtime addresses)
        if stack_mem:
            off = addr - stack_base
            if 0 <= off <= len(stack_mem) - size:
                return stack_mem[off:off + size]
        # Try ELF sections — translate runtime addr to ELF addr
        elf_addr = addr - image_base
        for sec_addr, sec_data in self._sections:
            off = elf_addr - sec_addr
            if 0 <= off <= len(sec_data) - size:
                return sec_data[off:off + size]
        return None

    def read_int(
        self, addr: int, size: int,
        stack_base: int = 0, stack_mem: bytes = b'',
        image_base: int = 0,
    ) -> int | None:
        """Read an integer of `size` bytes from `addr`."""
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
        """Read a null-terminated C string from `addr`."""
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
    # Type expansion (structs, classes, pointers, enums, arrays)
    # -----------------------------------------------------------------

    def get_type_die(self, cu_offset: int, type_offset: int) -> DIE | None:
        """Look up a type DIE by CU offset and DIE offset."""
        if not self._dwarf:
            return None
        try:
            cu = self._dwarf.get_CU_at(cu_offset)
            return cu.get_DIE_from_refaddr(type_offset)
        except Exception:
            return None

    def expand_type(
        self, type_die: DIE, addr: int,
        stack_base: int = 0, stack_mem: bytes = b'',
        image_base: int = 0,
    ) -> list[dict]:
        """Expand a type at a given address into its child fields.

        Handles structs/classes (members + inheritance), pointers
        (dereference), arrays (elements), and enums (name lookup).
        Returns a list of field dicts suitable for the API response.
        """
        if type_die is None:
            return []

        # Store memory context for internal methods
        self._mem_ctx = (stack_base, stack_mem, image_base)

        real = _strip_qualifiers(type_die)
        if real is None:
            return []
        tag = real.tag

        if tag in ('DW_TAG_structure_type', 'DW_TAG_class_type',
                    'DW_TAG_union_type'):
            return self._expand_struct(real, addr)

        if tag == 'DW_TAG_pointer_type':
            return self._expand_pointer(real, addr)

        if tag == 'DW_TAG_array_type':
            return self._expand_array(real, addr)

        return []

    def _read(self, addr: int, size: int) -> bytes | None:
        """Read memory using the current expand context."""
        sb, sm, ib = self._mem_ctx
        return self.read_memory(addr, size, sb, sm, ib)

    def _read_i(self, addr: int, size: int) -> int | None:
        """Read integer using the current expand context."""
        sb, sm, ib = self._mem_ctx
        return self.read_int(addr, size, sb, sm, ib)

    def _read_s(self, addr: int, max_len: int = 256) -> str | None:
        """Read string using the current expand context."""
        sb, sm, ib = self._mem_ctx
        return self.read_string(addr, sb, sm, ib, max_len)

    def _expand_struct(self, die: DIE, base_addr: int) -> list[dict]:
        """Expand struct/class/union members."""
        fields: list[dict] = []

        for child in die.iter_children():
            if child.tag == 'DW_TAG_inheritance':
                if 'DW_AT_type' not in child.attributes:
                    continue
                base_die = child.get_DIE_from_attribute('DW_AT_type')
                base_name = _resolve_type(base_die)
                offset = _member_offset(child)
                base_size = _resolve_byte_size(base_die)
                fields.append(self._make_field(
                    f'[base: {base_name}]', base_name, base_addr + offset,
                    base_size, base_die, access=_access_str(child)))
                continue

            if child.tag != 'DW_TAG_member':
                continue

            name_attr = child.attributes.get('DW_AT_name')
            name = name_attr.value.decode() if name_attr else '???'

            if 'DW_AT_type' not in child.attributes:
                continue
            member_type = child.get_DIE_from_attribute('DW_AT_type')
            type_name = _resolve_type(member_type)
            byte_size = _resolve_byte_size(member_type)
            offset = _member_offset(child)
            access = _access_str(child)

            if name.startswith('_vptr'):
                val = self._read_i(base_addr + offset, 8)
                fields.append({
                    'name': 'vtable', 'type': type_name, 'value': val,
                    'byte_size': 8, 'is_expandable': False,
                    'string_preview': None, 'type_offset': 0,
                    'cu_offset': 0, 'access': access,
                })
                continue

            fields.append(self._make_field(
                name, type_name, base_addr + offset,
                byte_size, member_type, access=access))

        return fields

    def _expand_pointer(self, die: DIE, addr: int) -> list[dict]:
        """Dereference a pointer and expand the target."""
        ptr_val = self._read_i(addr, 8)
        if ptr_val is None or ptr_val == 0:
            return []

        if 'DW_AT_type' not in die.attributes:
            return []
        target_die = die.get_DIE_from_attribute('DW_AT_type')
        target = _strip_qualifiers(target_die)
        if target is None:
            return []

        if target.tag in ('DW_TAG_structure_type', 'DW_TAG_class_type',
                          'DW_TAG_union_type'):
            return self._expand_struct(target, ptr_val)

        type_name = _resolve_type(target_die)
        byte_size = _resolve_byte_size(target_die)
        return [self._make_field('*', type_name, ptr_val, byte_size, target_die)]

    def _expand_array(
        self, die: DIE, addr: int, max_elements: int = 32,
    ) -> list[dict]:
        """Expand array elements."""
        if 'DW_AT_type' not in die.attributes:
            return []
        elem_die = die.get_DIE_from_attribute('DW_AT_type')
        elem_size = _resolve_byte_size(elem_die)
        if elem_size == 0:
            return []
        elem_type = _resolve_type(elem_die)

        count = max_elements
        for child in die.iter_children():
            if child.tag == 'DW_TAG_subrange_type':
                ub = child.attributes.get('DW_AT_upper_bound')
                cnt = child.attributes.get('DW_AT_count')
                if cnt:
                    count = min(cnt.value, max_elements)
                elif ub:
                    count = min(ub.value + 1, max_elements)
                break

        fields: list[dict] = []
        for i in range(count):
            fields.append(self._make_field(
                f'[{i}]', elem_type, addr + i * elem_size,
                elem_size, elem_die))
        return fields

    def _make_field(
        self, name: str, type_name: str, addr: int,
        byte_size: int, type_die: DIE,
        access: str = '',
    ) -> dict:
        """Build a field dict for the API response."""
        real = _strip_qualifiers(type_die)
        is_pointer = real is not None and real.tag == 'DW_TAG_pointer_type'
        is_aggregate = real is not None and real.tag in (
            'DW_TAG_structure_type', 'DW_TAG_class_type',
            'DW_TAG_union_type', 'DW_TAG_array_type')

        # Read scalar value
        value = None
        if byte_size > 0 and byte_size <= 8:
            value = self._read_i(addr, byte_size)
        elif is_pointer:
            value = self._read_i(addr, 8)

        # String preview for char pointers
        string_preview = None
        if is_pointer and value and _is_string_type(type_name):
            string_preview = self._read_s(value, max_len=64)

        # Enum name resolution
        if real is not None and real.tag == 'DW_TAG_enumeration_type' and value is not None:
            enum_name = _resolve_enum_name(real, value)
            if enum_name:
                string_preview = enum_name

        # Expandable if struct, pointer-to-struct, or array
        is_expandable = is_aggregate
        # For pointer-to-struct, use the target struct type so the expand
        # endpoint expands the struct directly at the pointer value.
        expand_die = type_die
        if is_pointer and real is not None and 'DW_AT_type' in real.attributes:
            target = _strip_qualifiers(
                real.get_DIE_from_attribute('DW_AT_type'))
            if target and target.tag in (
                    'DW_TAG_structure_type', 'DW_TAG_class_type',
                    'DW_TAG_union_type'):
                is_expandable = True
                expand_die = target

        type_offset = expand_die.offset if expand_die else 0
        cu_offset = expand_die.cu.cu_offset if expand_die else 0

        # expand_addr: the address the frontend should pass to /api/expand.
        # For pointer-to-struct: the pointer value (target address).
        # For embedded structs/arrays: the field's memory address in the parent.
        expand_addr: int | None = None
        if is_expandable:
            if is_pointer and value is not None:
                expand_addr = value
            else:
                expand_addr = addr

        result: dict = {
            'name': name,
            'type': type_name,
            'value': value,
            'byte_size': byte_size,
            'is_expandable': is_expandable,
            'expand_addr': expand_addr,
            'string_preview': string_preview,
            'type_offset': type_offset,
            'cu_offset': cu_offset,
        }
        if access:
            result['access'] = access
        return result

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
                var.type_offset = type_die.offset
                var.cu_offset = type_die.cu.cu_offset
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
