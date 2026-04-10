"""GDB/MI-based DWARF backend using pygdbmi.

Alternative to the pyelftools-based DwarfInfo for resolving variables,
types, disassembly, and source lines.  Delegates all DWARF interpretation
to GDB, which handles complex location expressions, entry values, C++
templates, and every DWARF edge case.

Requires GDB and pygdbmi to be installed.
"""
from __future__ import annotations

import re
import tempfile
from pathlib import Path

from pygdbmi.gdbcontroller import GdbController

from .corefile import write_corefile
from .models import VarInfo


def _parse_int(s: str) -> int | None:
    """Parse a GDB value string to int, handling hex and decimal."""
    if not s or s in ('<optimized out>', '<error', '<unavailable>'):
        return None
    s = s.strip()
    # Handle address-like: "0x5c6882a8 \"crashtest-v3\""
    if ' ' in s:
        s = s.split()[0]
    try:
        if s.startswith('0x') or s.startswith('0X'):
            return int(s, 16)
        return int(s)
    except ValueError:
        return None


def _extract_string_preview(val: str) -> str | None:
    """Extract string preview from GDB value like '0x5c6882a8 "hello"'."""
    m = re.search(r'"((?:[^"\\]|\\.)*)"', val)
    return m.group(1) if m else None


def _is_expandable_type(type_name: str) -> bool:
    """Check if a GDB type is expandable (struct/pointer-to-struct/array)."""
    t = type_name.strip()
    if t.endswith(']'):
        return True  # array
    if t.endswith('*'):
        return True  # pointer (might be struct pointer)
    if t.startswith('struct ') or t.startswith('volatile '):
        return True
    return False


class GdbBackend:
    """DWARF backend using GDB/MI via pygdbmi.

    Launches GDB with an ELF binary + synthesized core file.
    All DWARF interpretation is delegated to GDB.
    """

    def __init__(
        self,
        elf_path: Path,
        registers: dict[str, int],
        crash_pc: int | None,
        stack_base: int,
        stack_mem: bytes,
        image_base: int,
    ) -> None:
        self._elf_path = elf_path
        self._image_base = image_base
        self._frame_map: dict[int, int] = {}  # our addr → GDB frame index
        self._var_objects: set[str] = set()  # track created var objects

        # Generate core file
        self._tmpdir = Path(tempfile.mkdtemp(prefix='rsod_gdb_'))
        core_path = self._tmpdir / 'crash.core'
        write_corefile(
            registers, crash_pc, stack_base, stack_mem,
            elf_path, core_path, image_base)

        # Launch GDB
        self._gdb = GdbController(
            command=['gdb', '--interpreter=mi3', '-q', '-nx', str(elf_path)])
        self._cmd('set confirm off')
        self._cmd(f'target core {core_path}')
        self._cmd(f'add-symbol-file {elf_path} -o 0x{image_base:X}')

        # Build frame map from GDB's backtrace
        self._build_frame_map()

    def _cmd(self, command: str, timeout: float = 5) -> list[dict]:
        """Send a command and return all responses."""
        return self._gdb.write(command, timeout_sec=timeout)

    def _result(self, command: str, timeout: float = 5) -> dict:
        """Send a command and return the result payload."""
        for r in self._cmd(command, timeout):
            if r['type'] == 'result' and r.get('payload'):
                return r['payload']
        return {}

    def _build_frame_map(self) -> None:
        """Map PC addresses to GDB frame indices."""
        payload = self._result('-stack-list-frames')
        for f in payload.get('stack', []):
            addr = _parse_int(f.get('addr', ''))
            if addr is not None:
                self._frame_map[addr] = int(f['level'])

    def _select_frame(self, addr: int) -> int | None:
        """Switch GDB to the frame at the given address.

        Tries the raw address, addr + image_base, and fuzzy match
        (within ±16 bytes) since app.py may pass call_addr-1.
        Returns the GDB frame index, or None if not found.
        """
        # Exact match
        for a in (addr, addr + self._image_base):
            if a in self._frame_map:
                idx = self._frame_map[a]
                self._cmd(f'-stack-select-frame {idx}')
                return idx
        # Fuzzy match (call_addr-1 adjustment)
        runtime = addr + self._image_base
        for map_addr, idx in self._frame_map.items():
            if abs(map_addr - runtime) <= 16 or abs(map_addr - addr) <= 16:
                self._cmd(f'-stack-select-frame {idx}')
                return idx
        return None

    # -----------------------------------------------------------------
    # Variable extraction
    # -----------------------------------------------------------------

    def get_params(self, addr: int) -> list[VarInfo]:
        idx = self._select_frame(addr)
        if idx is None:
            return []
        payload = self._result(f'-stack-list-arguments 2 {idx} {idx}')
        results: list[VarInfo] = []
        for frame_args in payload.get('stack-args', []):
            for a in frame_args.get('args', []):
                name = a.get('name', '?')
                # Skip GDB's @entry variants
                if '@entry' in name:
                    continue
                results.append(self._mi_var_to_varinfo(a, addr))
        return results

    def get_locals(self, addr: int) -> list[VarInfo]:
        if self._select_frame(addr) is None:
            return []
        payload = self._result('-stack-list-locals 2')
        return [self._mi_var_to_varinfo(v, addr) for v in payload.get('locals', [])]

    def get_globals(self, addr: int) -> list[VarInfo]:
        # Delegate to pyelftools backend — GDB's info variables is
        # unreliable for CU-scope filtering.  Globals come from ELF
        # sections anyway (not runtime memory), so pyelftools is the
        # right tool.
        return []

    def _mi_var_to_varinfo(self, mi_var: dict, addr: int) -> VarInfo:
        """Convert a GDB/MI variable dict to VarInfo."""
        name = mi_var.get('name', '?')
        type_name = mi_var.get('type', '?')
        val_str = mi_var.get('value', '')

        var = VarInfo(name=name, type_name=type_name)
        var.value = _parse_int(val_str)
        var.string_preview = _extract_string_preview(val_str)

        # Always try variable objects — GDB knows the real type
        if _is_expandable_type(type_name) or val_str.startswith('{') or val_str == '':
            var_key = f'v_{addr:x}_{name}'
            try:
                # Clean up old var object if exists
                if var_key in self._var_objects:
                    self._cmd(f'-var-delete {var_key}')
                    self._var_objects.discard(var_key)
                p = self._result(f'-var-create {var_key} * {name}')
                numchild = int(p.get('numchild', '0'))
                if numchild > 0 or p.get('value', '') == '{...}':
                    var.is_expandable = True
                    var.var_key = var_key
                    var.expand_addr = var.value
                    self._var_objects.add(var_key)
                else:
                    self._cmd(f'-var-delete {var_key}')
            except Exception:
                pass

        # For struct values shown as "{...}", use address as value
        if val_str.startswith('{') and var.value is None:
            addr_payload = self._result(
                f'-data-evaluate-expression &{name}')
            var.value = _parse_int(addr_payload.get('value', ''))
            var.expand_addr = var.value

        return var

    # -----------------------------------------------------------------
    # Type expansion (via GDB variable objects)
    # -----------------------------------------------------------------

    def expand_type(
        self, type_die, addr: int,
        stack_base: int = 0, stack_mem: bytes = b'',
        image_base: int = 0,
        offset: int = 0, count: int = 32,
    ) -> tuple[list[dict], int]:
        """Expand a variable using GDB variable objects.

        type_die is used as the var_key (string) when called from the
        GDB backend. Falls back to address-based lookup.
        """
        var_key = type_die if isinstance(type_die, str) else ''
        if not var_key:
            return [], 0

        payload = self._result(f'-var-list-children --all-values {var_key}')
        children = payload.get('children', [])
        total = int(payload.get('numchild', len(children)))

        # Apply pagination
        page = children[offset:offset + count]
        fields: list[dict] = []
        for c in page:
            ch = c.get('child', c)
            child_name = ch.get('exp', '?')
            child_type = ch.get('type', '?')
            child_val_str = ch.get('value', '')
            child_key = ch.get('name', '')  # GDB var object name
            numchild = int(ch.get('numchild', '0'))

            value = _parse_int(child_val_str)
            is_expandable = numchild > 0 or child_val_str == '{...}'
            string_preview = _extract_string_preview(child_val_str)

            # For expandable children, the var_key is the child's
            # GDB variable object name
            expand_addr = value if is_expandable else None
            if is_expandable:
                self._var_objects.add(child_key)

            # Enum resolution: GDB shows "CRASH_MODE_PF" directly
            if not string_preview and re.match(r'^[A-Z_]+$', child_val_str):
                string_preview = child_val_str

            fields.append({
                'name': child_name,
                'type': child_type,
                'value': value,
                'byte_size': 0,
                'is_expandable': is_expandable,
                'expand_addr': expand_addr,
                'string_preview': string_preview,
                'type_offset': 0,
                'cu_offset': 0,
                'var_key': child_key,
            })

        return fields, total

    # -----------------------------------------------------------------
    # Memory reading
    # -----------------------------------------------------------------

    def read_int(
        self, addr: int, size: int,
        stack_base: int = 0, stack_mem: bytes = b'',
        image_base: int = 0,
    ) -> int | None:
        payload = self._result(
            f'-data-read-memory 0x{addr:x} x {size} 1 1')
        mem = payload.get('memory', [])
        if mem and mem[0].get('data'):
            return _parse_int(mem[0]['data'][0])
        return None

    def read_string(
        self, addr: int,
        stack_base: int = 0, stack_mem: bytes = b'',
        image_base: int = 0, max_len: int = 256,
    ) -> str | None:
        payload = self._result(
            f'-data-evaluate-expression (char*)0x{addr:x}')
        return _extract_string_preview(payload.get('value', ''))

    def read_memory(
        self, addr: int, size: int,
        stack_base: int = 0, stack_mem: bytes = b'',
        image_base: int = 0,
    ) -> bytes | None:
        payload = self._result(
            f'-data-read-memory 0x{addr:x} x 1 1 {size}')
        mem = payload.get('memory', [])
        if not mem:
            return None
        data = mem[0].get('data', [])
        return bytes(int(x, 16) & 0xFF for x in data) if data else None

    # -----------------------------------------------------------------
    # Disassembly and source
    # -----------------------------------------------------------------

    def disassemble_around(
        self, addr: int, context: int = 24,
    ) -> list[tuple[int, str, str]]:
        start = addr - context * 4
        end = addr + context * 4
        payload = self._result(
            f'-data-disassemble -s 0x{start:x} -e 0x{end:x} -- 0')
        insns: list[tuple[int, str, str]] = []
        for i in payload.get('asm_insns', []):
            a = _parse_int(i.get('address', ''))
            inst = i.get('inst', '')
            # Split "mov x0, #0x0" into mnemonic + operands
            parts = inst.split(None, 1)
            mnemonic = parts[0] if parts else inst
            op_str = parts[1] if len(parts) > 1 else ''
            if a is not None:
                insns.append((a, mnemonic, op_str))
        return insns

    def source_lines_for_addrs(
        self, addrs: list[int],
    ) -> dict[int, str]:
        result: dict[int, str] = {}
        for addr in addrs:
            payload = self._result(f'-symbol-info-line *0x{addr:x}')
            # Parse from console output
            for r in self._cmd(f'info line *0x{addr:x}'):
                if r['type'] == 'console':
                    line = r.get('payload', '')
                    m = re.search(r'Line (\d+) of "(.+?)"', line)
                    if m:
                        result[addr] = f'{m.group(2)}:{m.group(1)}'
                        break
        return result

    def is_call_before(self, addr: int) -> bool:
        """Check if the instruction before addr is a call/branch."""
        start = addr - 4
        payload = self._result(
            f'-data-disassemble -s 0x{start:x} -e 0x{addr:x} -- 0')
        for i in payload.get('asm_insns', []):
            inst = i.get('inst', '').lower()
            if any(op in inst for op in ('bl\t', 'bl ', 'call', 'blr')):
                return True
        return False

    def resolve_address(self, addr: int):
        """Resolve an address to function + source location."""
        from .models import AddressInfo
        # Get function name
        func = None
        for r in self._cmd(f'info symbol 0x{addr:x}'):
            if r['type'] == 'console':
                line = r.get('payload', '').strip()
                m = re.match(r'(\w+)(?:\s*\+\s*\d+)?\s+in section', line)
                if m:
                    func = m.group(1)
                    break
        # Get source line
        source_loc = ''
        for r in self._cmd(f'info line *0x{addr:x}'):
            if r['type'] == 'console':
                m = re.search(r'Line (\d+) of "(.+?)"', r.get('payload', ''))
                if m:
                    source_loc = f'{m.group(2)}:{m.group(1)}'
                    break
        if not func:
            return None
        return AddressInfo(function=func, source_loc=source_loc, inlines=[])

    def get_cfi_unwinder(self):
        return None  # GDB handles unwinding internally

    def get_type_die(self, cu_offset: int, type_offset: int):
        """Not applicable for GDB backend — returns the var_key string."""
        return None

    def close(self) -> None:
        try:
            self._gdb.exit()
        except Exception:
            pass
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)
