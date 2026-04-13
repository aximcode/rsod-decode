"""LLDB-based DWARF backend using LLDB's native Python API.

Alternative to the pyelftools DwarfInfo and to GdbBackend. Loads the
synthetic corefile written by write_corefile(), slides the target
module to image_base, and exposes the duck-typed surface the
serializers already use (frame-queries, memory reads, type expansion)
so callers can swap backends without knowing which one is active.

Phase 2 covers the ELF+DWARF path only; PE+PDB support lands in
Phase 3. Requires the system-installed lldb Python module, which is
imported via rsod_decode.lldb_loader.import_lldb().
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile

from .corefile import write_corefile
from .lldb_loader import import_lldb
from .models import AddressInfo, VarInfo


def lldb_available() -> bool:
    """True iff the system lldb Python module can be imported."""
    return import_lldb() is not None


def _is_expandable_type_name(type_name: str) -> bool:
    t = type_name.strip()
    if not t:
        return False
    if t.endswith(']') or t.endswith('*'):
        return True
    if t.startswith(('struct ', 'class ', 'union ')):
        return True
    return False


_CALL_MNEMONICS = ('bl', 'blr', 'blx', 'call', 'callq')


class LldbBackend:
    """DWARF backend using LLDB's in-process Python API.

    Public surface mirrors GdbBackend. The Session holds an instance as
    `lldb_dwarf`; serializers pick it up via `binary_for_session` when
    `session.backend == 'lldb'`.
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
        lldb = import_lldb()
        if lldb is None:
            raise RuntimeError('lldb Python module not available')
        self._lldb = lldb
        self._elf_path = elf_path
        self._image_base = image_base
        self._tmpdir = Path(tempfile.mkdtemp(prefix='rsod_lldb_'))
        self._var_objects: dict[str, Any] = {}
        self._globals_cache: list[VarInfo] | None = None

        core_path = self._tmpdir / 'crash.core'
        write_corefile(
            registers, crash_pc, stack_base, stack_mem,
            elf_path, core_path, image_base, frames=frames)

        self._debugger = lldb.SBDebugger.Create()
        self._debugger.SetAsync(False)
        self._target = self._debugger.CreateTarget(str(elf_path))
        if not self._target.IsValid():
            raise RuntimeError(
                f'LLDB failed to create target for {elf_path}')

        # Slide the module BEFORE LoadCore so LLDB's unwinder sees the
        # ELF's sections at their runtime addresses. The corefile itself
        # carries PT_LOADs at runtime addresses (image_base already baked
        # in by _load_elf_sections), so this keeps both views consistent.
        if image_base and self._target.GetNumModules() > 0:
            module = self._target.GetModuleAtIndex(0)
            slide_err = self._target.SetModuleLoadAddress(module, image_base)
            if not slide_err.Success():
                raise RuntimeError(
                    f'SetModuleLoadAddress failed: {slide_err.GetCString()}')

        err = lldb.SBError()
        self._process = self._target.LoadCore(str(core_path), err)
        if not err.Success():
            raise RuntimeError(f'LoadCore failed: {err.GetCString()}')
        if not self._process.IsValid() or self._process.GetNumThreads() < 1:
            raise RuntimeError('LoadCore returned an invalid process')

        self._thread = self._process.GetThreadAtIndex(0)

        self._frame_map: dict[int, int] = {}
        for i in range(self._thread.GetNumFrames()):
            frame = self._thread.GetFrameAtIndex(i)
            pc = frame.GetPC()
            if pc:
                self._frame_map[pc] = i

        # Valid-range tracking mirrors GdbBackend so we don't return
        # zeroed corefile padding as real memory.
        self._valid_ranges: list[tuple[int, int]] = []
        if stack_mem:
            self._valid_ranges.append(
                (stack_base, stack_base + len(stack_mem)))
        with open(str(elf_path), 'rb') as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                if sec['sh_size'] > 0 and sec['sh_addr'] > 0:
                    rt = sec['sh_addr'] + image_base
                    self._valid_ranges.append((rt, rt + sec['sh_size']))

    # -----------------------------------------------------------------
    # Frame mapping
    # -----------------------------------------------------------------

    def _resolve_frame_idx(self, addr: int) -> int | None:
        runtime = addr + self._image_base
        for a in (runtime, addr):
            if a in self._frame_map:
                return self._frame_map[a]
        for pc, idx in self._frame_map.items():
            if abs(pc - runtime) <= 16 or abs(pc - addr) <= 16:
                return idx
        return None

    def _frame_for(self, addr: int) -> Any | None:
        idx = self._resolve_frame_idx(addr)
        if idx is None:
            return None
        return self._thread.GetFrameAtIndex(idx)

    def _has_memory(self, addr: int, size: int = 1) -> bool:
        end = addr + size
        for start, rend in self._valid_ranges:
            if addr >= start and end <= rend:
                return True
        return False

    # -----------------------------------------------------------------
    # Variable extraction
    # -----------------------------------------------------------------

    def _sbvalue_to_varinfo(self, sv: Any, pc: int) -> VarInfo:
        name = sv.GetName() or '?'
        type_name = sv.GetTypeName() or '?'
        location = sv.GetLocation() or ''
        var = VarInfo(name=name, type_name=type_name, location=location)

        err = self._lldb.SBError()
        unsigned = sv.GetValueAsUnsigned(err, 0)
        is_pointer = type_name.rstrip().endswith('*')
        num_children = sv.GetNumChildren()

        # Scalars + pointers: trust GetValueAsUnsigned. For aggregates
        # we fill in a load address below instead.
        if num_children == 0 or is_pointer:
            if err.Success() and sv.GetValue() is not None:
                var.value = unsigned

        if _is_expandable_type_name(type_name) and num_children > 0:
            var.is_expandable = True
            load_addr = sv.GetLoadAddress()
            valid = load_addr != self._lldb.LLDB_INVALID_ADDRESS
            if is_pointer and var.value:
                var.expand_addr = var.value
            elif valid:
                var.expand_addr = load_addr
                if var.value is None:
                    var.value = load_addr
            var_key = f'v_{pc:x}_{name}'
            self._var_objects[var_key] = sv
            var.var_key = var_key

        preview = sv.GetSummary()
        if preview and preview.startswith('"') and preview.endswith('"'):
            var.string_preview = preview[1:-1]
        return var

    def get_params(self, addr: int) -> list[VarInfo]:
        frame = self._frame_for(addr)
        if frame is None:
            return []
        values = frame.GetVariables(True, False, False, True)
        return [self._sbvalue_to_varinfo(values.GetValueAtIndex(i), addr)
                for i in range(values.GetSize())]

    def get_locals(self, addr: int) -> list[VarInfo]:
        frame = self._frame_for(addr)
        if frame is None:
            return []
        values = frame.GetVariables(False, True, False, True)
        return [self._sbvalue_to_varinfo(values.GetValueAtIndex(i), addr)
                for i in range(values.GetSize())]

    def get_globals(self, addr: int) -> list[VarInfo]:
        # The pyelftools DwarfInfo is the authority on global discovery;
        # app.py calls evaluate_globals() on this backend afterwards to
        # fill in runtime-accurate values.
        return []

    def evaluate_globals(self, names: list[VarInfo]) -> list[VarInfo]:
        if self._globals_cache is not None:
            return self._globals_cache
        results: list[VarInfo] = []
        for v in names:
            out = VarInfo(
                name=v.name, type_name=v.type_name, location=v.location,
                type_offset=v.type_offset, cu_offset=v.cu_offset)
            sv = self._target.EvaluateExpression(v.name)
            if sv.GetError().Success():
                werr = self._lldb.SBError()
                unsigned = sv.GetValueAsUnsigned(werr, 0)
                if werr.Success() and sv.GetValue() is not None:
                    out.value = unsigned
                if _is_expandable_type_name(v.type_name) \
                        and sv.GetNumChildren() > 0:
                    out.is_expandable = True
                    load_addr = sv.GetLoadAddress()
                    if load_addr != self._lldb.LLDB_INVALID_ADDRESS:
                        out.expand_addr = load_addr
                        if out.value is None:
                            out.value = load_addr
                    var_key = f'g_{v.name}'
                    self._var_objects[var_key] = sv
                    out.var_key = var_key
                preview = sv.GetSummary()
                if preview and preview.startswith('"') and preview.endswith('"'):
                    out.string_preview = preview[1:-1]
            results.append(out)
        self._globals_cache = results
        return results

    def evaluate_expression(self, addr: int, expr: str) -> dict:
        frame = self._frame_for(addr)
        if frame is None:
            return {'error': 'Frame not found'}
        sv = frame.EvaluateExpression(expr)
        err = sv.GetError()
        if not err.Success():
            return {'error': err.GetCString() or 'Unknown error'}
        werr = self._lldb.SBError()
        unsigned = sv.GetValueAsUnsigned(werr, 0)
        value = sv.GetValue()
        if value is None and werr.Success():
            value = f'0x{unsigned:x}'
        return {'value': value or '', 'type': sv.GetTypeName() or ''}

    # -----------------------------------------------------------------
    # Type expansion (via cached SBValue handles, keyed by var_key)
    # -----------------------------------------------------------------

    def get_type_die(self, cu_offset: int, type_offset: int) -> None:
        """LLDB doesn't use DIE offsets — expansion goes through var_key."""
        return None

    def expand_type(
        self, type_die: Any, addr: int,
        stack_base: int = 0, stack_mem: bytes = b'',
        image_base: int = 0,
        offset: int = 0, count: int = 32,
    ) -> tuple[list[dict], int]:
        var_key = type_die if isinstance(type_die, str) else ''
        sv = self._var_objects.get(var_key)
        if sv is None:
            return [], 0

        sb_type = sv.GetType()
        if sb_type.IsPointerType():
            sv = sv.Dereference()

        total = sv.GetNumChildren()
        fields: list[dict] = []
        for i in range(offset, min(offset + count, total)):
            child = sv.GetChildAtIndex(i)
            fields.append(self._child_to_dict(child, var_key, i))
        return fields, total

    def _child_to_dict(self, child: Any, parent_key: str, idx: int) -> dict:
        name = child.GetName() or '?'
        type_name = child.GetTypeName() or '?'
        num_children = child.GetNumChildren()
        is_pointer = type_name.rstrip().endswith('*')
        is_expandable = (num_children > 0 and
                         _is_expandable_type_name(type_name))

        err = self._lldb.SBError()
        unsigned = child.GetValueAsUnsigned(err, 0)
        value: int | None = None
        if err.Success() and child.GetValue() is not None:
            value = unsigned
        elif is_pointer and err.Success():
            value = unsigned

        expand_addr: int | None = None
        var_key_out = ''
        if is_expandable:
            load_addr = child.GetLoadAddress()
            if is_pointer and value:
                expand_addr = value
            elif load_addr != self._lldb.LLDB_INVALID_ADDRESS:
                expand_addr = load_addr
            var_key_out = f'{parent_key}.{idx}.{name}'
            self._var_objects[var_key_out] = child

        string_preview: str | None = None
        preview = child.GetSummary()
        if preview and preview.startswith('"') and preview.endswith('"'):
            string_preview = preview[1:-1]

        return {
            'name': name,
            'type': type_name,
            'value': value,
            'byte_size': 0,
            'is_expandable': is_expandable,
            'expand_addr': expand_addr,
            'string_preview': string_preview,
            'type_offset': 0,
            'cu_offset': 0,
            'var_key': var_key_out,
        }

    # -----------------------------------------------------------------
    # Memory reading
    # -----------------------------------------------------------------

    def read_memory(
        self, addr: int, size: int,
        stack_base: int = 0, stack_mem: bytes = b'',
        image_base: int = 0,
    ) -> bytes | None:
        if not self._has_memory(addr, size):
            return None
        err = self._lldb.SBError()
        data = self._process.ReadMemory(addr, size, err)
        if not err.Success() or data is None:
            return None
        return bytes(data)

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
        image_base: int = 0, max_len: int = 256,
    ) -> str | None:
        for length in (max_len, 64, 16, 1):
            data = self.read_memory(
                addr, length, stack_base, stack_mem, image_base)
            if data is not None:
                nul = data.find(b'\x00')
                if nul >= 0:
                    data = data[:nul]
                return data.decode('utf-8', errors='replace')
        return None

    def read_memory_partial(
        self, addr: int, size: int,
        stack_base: int = 0, stack_mem: bytes = b'',
        image_base: int = 0,
    ) -> list[int | None]:
        result: list[int | None] = [None] * size
        i = 0
        while i < size:
            if not self._has_memory(addr + i):
                i += 1
                continue
            j = i
            while j < size and self._has_memory(addr + j):
                j += 1
            chunk = self.read_memory(
                addr + i, j - i, stack_base, stack_mem, image_base)
            if chunk:
                for k, b in enumerate(chunk):
                    result[i + k] = b
            i = j
        return result

    # -----------------------------------------------------------------
    # Disassembly and source
    # -----------------------------------------------------------------

    def disassemble_around(
        self, addr: int, context: int = 24,
    ) -> list[tuple[int, str, str]]:
        runtime = addr + self._image_base
        # Read a generous window of instructions centered on addr; the
        # exact byte size depends on the ISA so we read count*3 and
        # filter by the expected address range below.
        start = runtime - context * 4
        end = runtime + context * 4
        sb_addr = self._lldb.SBAddress(start, self._target)
        instructions = self._target.ReadInstructions(sb_addr, context * 3)
        insns: list[tuple[int, str, str]] = []
        for i in range(instructions.GetSize()):
            insn = instructions.GetInstructionAtIndex(i)
            load = insn.GetAddress().GetLoadAddress(self._target)
            if load == self._lldb.LLDB_INVALID_ADDRESS:
                continue
            if load < start or load >= end:
                continue
            mnemonic = insn.GetMnemonic(self._target) or ''
            operands = insn.GetOperands(self._target) or ''
            insns.append((load - self._image_base, mnemonic, operands))
        return insns

    def is_call_before(self, addr: int) -> bool:
        runtime = addr + self._image_base
        sb_addr = self._lldb.SBAddress(runtime - 8, self._target)
        instructions = self._target.ReadInstructions(sb_addr, 2)
        if instructions.GetSize() == 0:
            return False
        last = instructions.GetInstructionAtIndex(instructions.GetSize() - 1)
        mnemonic = (last.GetMnemonic(self._target) or '').lower()
        return mnemonic in _CALL_MNEMONICS

    def source_lines_for_addrs(
        self, addrs: list[int],
    ) -> dict[int, str]:
        result: dict[int, str] = {}
        for addr in addrs:
            runtime = addr + self._image_base
            sb_addr = self._target.ResolveLoadAddress(runtime)
            if not sb_addr.IsValid():
                continue
            line_entry = sb_addr.GetLineEntry()
            if not line_entry.IsValid():
                continue
            spec = line_entry.GetFileSpec()
            fname = spec.GetFilename() or ''
            directory = spec.GetDirectory() or ''
            if fname:
                path = f'{directory}/{fname}' if directory else fname
                result[addr] = f'{path}:{line_entry.GetLine()}'
        return result

    def resolve_address(self, addr: int) -> AddressInfo | None:
        runtime = addr + self._image_base
        sb_addr = self._target.ResolveLoadAddress(runtime)
        if not sb_addr.IsValid():
            return None
        symbol = sb_addr.GetSymbol()
        fn = symbol.GetName() if symbol.IsValid() else ''
        if not fn:
            return None
        line_entry = sb_addr.GetLineEntry()
        source_loc = ''
        if line_entry.IsValid():
            spec = line_entry.GetFileSpec()
            fname = spec.GetFilename() or ''
            directory = spec.GetDirectory() or ''
            if fname:
                path = f'{directory}/{fname}' if directory else fname
                source_loc = f'{path}:{line_entry.GetLine()}'
        return AddressInfo(function=fn, source_loc=source_loc, inlines=[])

    def resolve_addresses(
        self, addrs: list[int], crash_pc: int = 0,
    ) -> dict[int, AddressInfo]:
        out: dict[int, AddressInfo] = {}
        for a in addrs:
            info = self.resolve_address(a)
            if info is not None:
                out[a] = info
        return out

    def get_cfi_unwinder(self) -> None:
        """LLDB unwinds internally — pyelftools provides the decoder-time
        CFI unwinder, not this backend."""
        return None

    def close(self) -> None:
        try:
            self._lldb.SBDebugger.Destroy(self._debugger)
        except Exception:
            pass
        shutil.rmtree(self._tmpdir, ignore_errors=True)
