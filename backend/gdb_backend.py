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
        frames: list[tuple[int, int]] | None = None,
    ) -> None:
        self._elf_path = elf_path
        self._image_base = image_base
        self._frame_map: dict[int, int] = {}  # our addr → GDB frame index
        self._var_objects: set[str] = set()  # track created var objects
        self._globals_cache: list[VarInfo] | None = None

        # Track known memory ranges so we can distinguish real zeroes
        # from unmapped core file regions (which GDB reads as 0)
        self._valid_ranges: list[tuple[int, int]] = []
        if stack_mem:
            self._valid_ranges.append(
                (stack_base, stack_base + len(stack_mem)))
        # ELF sections mapped at runtime
        from elftools.elf.elffile import ELFFile
        with open(str(elf_path), 'rb') as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                if sec['sh_size'] > 0 and sec['sh_addr'] > 0:
                    rt = sec['sh_addr'] + image_base
                    self._valid_ranges.append((rt, rt + sec['sh_size']))

        # Generate core file with synthetic FP chain for frames
        # beyond the stack dump
        self._tmpdir = Path(tempfile.mkdtemp(prefix='rsod_gdb_'))
        core_path = self._tmpdir / 'crash.core'
        write_corefile(
            registers, crash_pc, stack_base, stack_mem,
            elf_path, core_path, image_base, frames=frames)

        # Launch GDB (reduce additional-output wait from 200ms to 10ms)
        self._gdb = GdbController(
            command=['gdb', '--interpreter=mi3', '-q', '-nx', str(elf_path)],
            time_to_check_for_additional_output_sec=0.01)
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

    def _has_memory(self, addr: int, size: int = 1) -> bool:
        """Check if addr..addr+size falls within known memory."""
        end = addr + size
        for start, rend in self._valid_ranges:
            if addr >= start and end <= rend:
                return True
        return False

    def _resolve_frame_idx(self, addr: int) -> int | None:
        """Resolve an address to a GDB frame index (no GDB command sent).

        Tries raw address, addr + image_base, and fuzzy match (±16 bytes).
        """
        for a in (addr, addr + self._image_base):
            if a in self._frame_map:
                return self._frame_map[a]
        runtime = addr + self._image_base
        for map_addr, idx in self._frame_map.items():
            if abs(map_addr - runtime) <= 16 or abs(map_addr - addr) <= 16:
                return idx
        return None

    def _select_frame(self, addr: int) -> int | None:
        """Switch GDB to the frame at addr. Returns frame index."""
        idx = self._resolve_frame_idx(addr)
        if idx is not None:
            self._cmd(f'-stack-select-frame {idx}')
        return idx

    # -----------------------------------------------------------------
    # Expression evaluation
    # -----------------------------------------------------------------

    def evaluate_expression(self, addr: int, expr: str) -> dict:
        """Evaluate a C expression in the given frame context.

        Returns {'value': str, 'type': str} or {'error': str}.
        """
        if self._select_frame(addr) is None:
            return {'error': 'Frame not found'}

        # Get value
        responses = self._cmd(f'-data-evaluate-expression {expr}')
        value = None
        for r in responses:
            if r['type'] == 'result':
                if r.get('message') == 'error':
                    msg = r.get('payload', {}).get('msg', 'Unknown error')
                    return {'error': msg}
                if r.get('payload', {}).get('value'):
                    value = r['payload']['value']

        if value is None:
            return {'error': 'No result'}

        # Get type via "whatis" console command
        type_name = ''
        for r in self._cmd(f'whatis {expr}'):
            if r.get('type') == 'console':
                payload = r.get('payload', '')
                # GDB outputs "type = int\n"
                if 'type = ' in payload:
                    type_name = payload.split('type = ', 1)[1].strip()
                    break

        return {'value': value, 'type': type_name}

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
                if '@entry' in a.get('name', ''):
                    continue
                results.append(self._mi_var_to_varinfo(a, addr))
        return results

    def get_locals(self, addr: int) -> list[VarInfo]:
        if self._select_frame(addr) is None:
            return []
        payload = self._result('-stack-list-locals 2')
        return [self._mi_var_to_varinfo(v, addr)
                for v in payload.get('locals', [])]

    def get_globals(self, addr: int) -> list[VarInfo]:
        # GDB can't discover CU-scope globals via MI.  Returns empty;
        # app.py uses pyelftools for discovery and calls
        # evaluate_globals() to fill in GDB-resolved values.
        return []

    def evaluate_globals(self, names: list[VarInfo]) -> list[VarInfo]:
        """Evaluate global variables by name using GDB (cached).

        Takes VarInfo list from pyelftools (with names/types) and returns
        new VarInfo list with GDB-resolved values.
        """
        if self._globals_cache is not None:
            return self._globals_cache
        results: list[VarInfo] = []
        for v in names:
            p = self._result(f'-data-evaluate-expression {v.name}')
            val_str = p.get('value', '')
            var = VarInfo(name=v.name, type_name=v.type_name)
            var.value = _parse_int(val_str)
            var.string_preview = _extract_string_preview(val_str)
            # Enum resolution
            if var.value is None and val_str and re.match(r'^[A-Za-z_]\w*$', val_str):
                var.string_preview = val_str
                p2 = self._result(f'-data-evaluate-expression (int){v.name}')
                var.value = _parse_int(p2.get('value', ''))
            # Struct/array: try variable object
            if val_str.startswith('{') or val_str == '' or var.value is None:
                try:
                    vk = f'g_{v.name}'
                    if vk in self._var_objects:
                        self._cmd(f'-var-delete {vk}')
                    p3 = self._result(f'-var-create {vk} * {v.name}')
                    nc = int(p3.get('numchild', '0'))
                    if nc > 0 or p3.get('value', '') == '{...}':
                        var.is_expandable = True
                        var.var_key = vk
                        self._var_objects.add(vk)
                        # Get address for expand_addr and value
                        pa = self._result(f'-data-evaluate-expression &{v.name}')
                        addr = _parse_int(pa.get('value', ''))
                        var.expand_addr = addr
                        if var.value is None and addr is not None:
                            var.value = addr
                except Exception:
                    pass
            results.append(var)
        self._globals_cache = results
        return results

    def _mi_var_to_varinfo(self, mi_var: dict, addr: int) -> VarInfo:
        """Convert a GDB/MI variable dict to VarInfo."""
        name = mi_var.get('name', '?')
        type_name = mi_var.get('type', '?')
        val_str = mi_var.get('value', '')

        var = VarInfo(name=name, type_name=type_name)
        var.value = _parse_int(val_str)
        var.string_preview = _extract_string_preview(val_str)

        # Enum values: GDB returns name like "CRASH_MODE_PF" instead of int.
        # Use the name as string_preview; try to get numeric value via MI.
        if var.value is None and val_str and re.match(r'^[A-Za-z_]\w*$', val_str):
            var.string_preview = val_str
            # Get numeric value via expression evaluation
            p = self._result(f'-data-evaluate-expression (int){name}')
            var.value = _parse_int(p.get('value', ''))

        # Only create variable objects for likely-expandable types
        # (structs, arrays, pointers) — skip scalars to avoid MI round-trips
        needs_varobj = (
            _is_expandable_type(type_name)
            or val_str.startswith('{')
            or (val_str == '' and var.value is None)  # unknown value, might be struct
        )
        if needs_varobj:
            var_key = f'v_{addr:x}_{name}'
            try:
                if var_key in self._var_objects:
                    self._cmd(f'-var-delete {var_key}')
                    self._var_objects.discard(var_key)
                p = self._result(f'-var-create {var_key} * {name}')
                numchild = int(p.get('numchild', '0'))
                if numchild > 0 or p.get('value', '') == '{...}':
                    var.is_expandable = True
                    var.var_key = var_key
                    self._var_objects.add(var_key)
                    # expand_addr: for pointers, use the pointer value
                    # (where it points); for structs/arrays, use &name
                    if var.value is not None and '*' in type_name:
                        var.expand_addr = var.value
                    else:
                        addr_payload = self._result(
                            f'-data-evaluate-expression &{name}')
                        addr_val = _parse_int(
                            addr_payload.get('value', ''))
                        var.expand_addr = addr_val
                        if var.value is None:
                            var.value = addr_val
                else:
                    self._cmd(f'-var-delete {var_key}')
            except Exception:
                pass

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

        # Resolve actual address if the caller passed 0 (frontend
        # default when expand_addr was None)
        if addr == 0:
            path_payload = self._result(
                f'-var-info-path-expression {var_key}')
            path_expr = path_payload.get('path_expr', '')
            if path_expr:
                addr_payload = self._result(
                    f'-data-evaluate-expression &({path_expr})')
                resolved = _parse_int(addr_payload.get('value', ''))
                if resolved is not None:
                    addr = resolved

        # Check if the struct/array base address is in known memory.
        # The core file fills unmapped regions with zeroes, so GDB
        # would report 0 for fields that don't actually exist.
        addr_valid = addr == 0 or self._has_memory(addr)

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

            is_expandable = numchild > 0 or child_val_str == '{...}'

            if not addr_valid:
                # Parent struct is outside known memory — values are
                # zeroed core file padding, not real data
                value = None
                string_preview = None
                expand_addr = None
            else:
                value = _parse_int(child_val_str)
                string_preview = _extract_string_preview(child_val_str)

                # For expandable children with no parseable value (arrays,
                # embedded structs show "{...}"), resolve the address via GDB
                expand_addr = value if is_expandable else None
                if is_expandable and value is None and child_key:
                    path_payload = self._result(
                        f'-var-info-path-expression {child_key}')
                    path_expr = path_payload.get('path_expr', '')
                    if path_expr:
                        addr_payload = self._result(
                            f'-data-evaluate-expression &({path_expr})')
                        addr_val = _parse_int(
                            addr_payload.get('value', ''))
                        if addr_val is not None:
                            value = addr_val
                            expand_addr = addr_val

                # Enum resolution: GDB shows "CRASH_MODE_PF" directly
                if not string_preview and re.match(
                        r'^[A-Z_]+$', child_val_str):
                    string_preview = child_val_str

            if is_expandable:
                self._var_objects.add(child_key)

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
        if not self._has_memory(addr, size):
            return None
        payload = self._result(
            f'-data-read-memory 0x{addr:x} x 1 1 {size}')
        mem = payload.get('memory', [])
        if not mem:
            return None
        data = mem[0].get('data', [])
        if not data:
            return None
        try:
            return bytes(int(x, 16) & 0xFF for x in data)
        except ValueError:
            return None

    def read_memory_partial(
        self, addr: int, size: int,
        stack_base: int = 0, stack_mem: bytes = b'',
        image_base: int = 0,
    ) -> list[int | None]:
        """Read memory, returning None for unreadable bytes."""
        result: list[int | None] = [None] * size
        # Only read bytes within known memory ranges
        for i in range(size):
            if self._has_memory(addr + i):
                result[i] = -1  # placeholder: "should read"
        # Batch-read contiguous valid ranges via GDB
        i = 0
        while i < size:
            if result[i] != -1:
                i += 1
                continue
            # Find contiguous run of valid bytes
            j = i
            while j < size and result[j] == -1:
                j += 1
            chunk_size = j - i
            payload = self._result(
                f'-data-read-memory 0x{addr + i:x} x 1 1 {chunk_size}')
            mem = payload.get('memory', [])
            data = mem[0].get('data', []) if mem else []
            for k, x in enumerate(data):
                try:
                    result[i + k] = int(x, 16) & 0xFF
                except ValueError:
                    result[i + k] = None
            i = j
        return result

    # -----------------------------------------------------------------
    # Disassembly and source
    # -----------------------------------------------------------------

    def disassemble_around(
        self, addr: int, context: int = 24,
    ) -> list[tuple[int, str, str]]:
        # addr is an ELF offset; GDB needs runtime addresses
        rt = addr + self._image_base
        start = rt - context * 4
        end = rt + context * 4
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
                # Convert runtime addresses back to ELF offsets
                insns.append((a - self._image_base, mnemonic, op_str))
        return insns

    def source_lines_for_addrs(
        self, addrs: list[int],
    ) -> dict[int, str]:
        """Map ELF addresses to source lines via GDB."""
        result: dict[int, str] = {}
        for addr in addrs:
            rt = addr + self._image_base
            for r in self._cmd(f'info line *0x{rt:x}'):
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
