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
        self._mode: str = 'corefile'
        # PE+PDB mode stashes stack/registers for manual memory reads
        # since no SBProcess is available. Set in from_pe_pdb().
        self._crash_registers: dict[str, int] = registers
        self._stack_base: int = stack_base
        self._stack_mem: bytes = stack_mem

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
        if self._mode == 'pe_pdb':
            return None
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
        if self._mode == 'pe_pdb':
            # No SBProcess — can't evaluate runtime globals. Return the
            # pyelftools-discovered list untouched.
            return list(names)
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
        # PE+PDB mode: var_key encodes a type name, e.g. "pe_type:CrashContext".
        # Look the type up via SBModule.FindTypes, read the struct bytes at
        # the given address, and emit one field dict per member.
        if var_key.startswith('pe_type:'):
            type_name = var_key[len('pe_type:'):]
            return self._expand_pe_type(
                type_name, addr, offset, count)

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
        if self._mode == 'pe_pdb':
            return self._read_memory_static(addr, size)
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
        if self._mode == 'pe_pdb':
            result: list[int | None] = [None] * size
            for i in range(size):
                b = self._read_memory_static(addr + i, 1)
                if b is not None and len(b) == 1:
                    result[i] = b[0]
            return result
        result = [None] * size
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
        if self._mode == 'pe_pdb':
            return []
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
        if self._mode == 'pe_pdb':
            return False
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

    # =================================================================
    # PE+PDB mode — static type lookup + direct memory reads.
    # No SBProcess exists, so get_params/get_locals return [] and
    # variable values come from ground-truth addresses computed by the
    # caller (test or frontend) and passed to /api/expand.
    # =================================================================

    @classmethod
    def from_pe_pdb(
        cls,
        pe_path: Path,
        pdb_path: Path,
        registers: dict[str, int],
        crash_pc: int | None,
        stack_base: int,
        stack_mem: bytes,
        image_base: int,
        frames: list[tuple[int, int]] | None = None,
    ) -> LldbBackend:
        """Alternate constructor for a statically-loaded PE+PDB target.

        Builds an LldbBackend that holds a PE target with its PDB loaded
        as a symbol source, but no SBProcess. Variable values come from
        the RSOD registers + stack dump that get stashed on the instance,
        and struct expansion uses SBType layouts from the PDB.
        """
        lldb = import_lldb()
        if lldb is None:
            raise RuntimeError('lldb Python module not available')
        instance = cls.__new__(cls)
        instance._lldb = lldb
        instance._elf_path = pe_path
        instance._image_base = image_base
        instance._tmpdir = Path(tempfile.mkdtemp(prefix='rsod_lldb_pe_'))
        instance._var_objects = {}
        instance._globals_cache = None
        instance._mode = 'pe_pdb'
        instance._crash_registers = registers
        instance._stack_base = stack_base
        instance._stack_mem = stack_mem
        instance._valid_ranges = []

        instance._debugger = lldb.SBDebugger.Create()
        instance._debugger.SetAsync(False)
        ci = instance._debugger.GetCommandInterpreter()
        ro = lldb.SBCommandReturnObject()
        ci.HandleCommand(
            f'target create --arch x86_64 {pe_path}', ro)
        if not ro.Succeeded():
            lldb.SBDebugger.Destroy(instance._debugger)
            raise RuntimeError(
                f'target create failed: {ro.GetError().strip()}')
        ci.HandleCommand(f'target symbols add {pdb_path}', ro)
        if not ro.Succeeded():
            lldb.SBDebugger.Destroy(instance._debugger)
            raise RuntimeError(
                f'target symbols add failed: {ro.GetError().strip()}')

        instance._target = instance._debugger.GetSelectedTarget()
        if not instance._target.IsValid():
            lldb.SBDebugger.Destroy(instance._debugger)
            raise RuntimeError('PE+PDB target invalid after creation')

        # Cache module sections with their file addresses (no slide
        # — PE files link with ImageBase baked into section addresses).
        instance._pe_sections: list[tuple[int, int, Any]] = []
        if instance._target.GetNumModules() > 0:
            module = instance._target.GetModuleAtIndex(0)
            for i in range(module.GetNumSections()):
                sec = module.GetSectionAtIndex(i)
                file_addr = sec.GetFileAddress()
                size = sec.GetByteSize()
                if size > 0 and file_addr != \
                        lldb.LLDB_INVALID_ADDRESS:
                    instance._pe_sections.append((file_addr, size, sec))
        return instance

    def _read_memory_static(self, addr: int, size: int) -> bytes | None:
        """PE+PDB mode memory read: stack dump first, then PE sections."""
        if self._stack_mem:
            off = addr - self._stack_base
            if 0 <= off <= len(self._stack_mem) - size:
                return self._stack_mem[off:off + size]
        for file_addr, sec_size, sec in self._pe_sections:
            off = addr - file_addr
            if 0 <= off <= sec_size - size:
                err = self._lldb.SBError()
                data = sec.GetSectionData().ReadRawData(err, off, size)
                if err.Success() and data is not None:
                    return bytes(data)
                return None
        return None

    def _read_cstring_static(
        self, addr: int, max_len: int = 256,
    ) -> str | None:
        """Read a NUL-terminated UTF-8 string from PE sections or stack."""
        for length in (max_len, 64, 16, 1):
            data = self._read_memory_static(addr, length)
            if data is not None:
                nul = data.find(b'\x00')
                if nul >= 0:
                    data = data[:nul]
                return data.decode('utf-8', errors='replace')
        return None

    def _find_pe_type(self, type_name: str) -> Any | None:
        """Look up a type by name via SBModule.FindTypes."""
        if self._target.GetNumModules() == 0:
            return None
        module = self._target.GetModuleAtIndex(0)
        matches = module.FindTypes(type_name)
        if matches.GetSize() == 0:
            # FindFirstType handles typedefs better than FindTypes in
            # some lldb builds; try it as a fallback.
            t = module.FindFirstType(type_name)
            return t if t and t.IsValid() else None
        return matches.GetTypeAtIndex(0)

    def _expand_pe_type(
        self, type_name: str, addr: int,
        offset: int, count: int,
    ) -> tuple[list[dict], int]:
        sb_type = self._find_pe_type(type_name)
        if sb_type is None:
            return [], 0
        total = sb_type.GetNumberOfFields()
        fields: list[dict] = []
        for i in range(offset, min(offset + count, total)):
            field = sb_type.GetFieldAtIndex(i)
            fields.append(self._pe_field_to_dict(field, addr))
        return fields, total

    def _pe_field_to_dict(self, field: Any, struct_addr: int) -> dict:
        """Turn one SBTypeMember into the /api/expand field dict format."""
        name = field.GetName() or '?'
        field_type = field.GetType()
        type_name = field_type.GetName() or '?'
        field_off = field.GetOffsetInBytes()
        field_addr = struct_addr + field_off
        field_size = field_type.GetByteSize()

        is_pointer = field_type.IsPointerType()
        is_array = field_type.IsArrayType()
        # Struct/class detection via type class
        type_class = field_type.GetTypeClass()
        is_struct = type_class in (
            self._lldb.eTypeClassStruct,
            self._lldb.eTypeClassClass,
            self._lldb.eTypeClassUnion,
        )
        is_expandable = is_pointer or is_array or is_struct

        value: int | None = None
        string_preview: str | None = None
        expand_addr: int | None = None
        var_key_out = ''

        if is_pointer:
            raw = self._read_memory_static(field_addr, 8)
            if raw is not None:
                value = int.from_bytes(raw, 'little')
            if value:
                pointee = field_type.GetPointeeType()
                pointee_name = pointee.GetName() or ''
                if 'char' in pointee_name:
                    string_preview = self._read_cstring_static(value, 256)
                # Pointer to struct → expand the pointee at the pointer value
                pointee_class = pointee.GetTypeClass()
                if pointee_class in (
                    self._lldb.eTypeClassStruct,
                    self._lldb.eTypeClassClass,
                    self._lldb.eTypeClassUnion,
                ):
                    expand_addr = value
                    pointee_base = pointee_name.split('::')[-1]
                    var_key_out = f'pe_type:{pointee_base}'
        elif is_array:
            # Array element expansion: child fields are synthesized per
            # element. We don't wire up indexed expansion here; just
            # report the array as expandable pointing at its own address.
            expand_addr = field_addr
            elem_type = field_type.GetArrayElementType()
            elem_name = elem_type.GetName() or ''
            var_key_out = f'pe_array:{elem_name}:{field_type.GetByteSize()}'
            # For small integer arrays, show a preview by reading each
            # element. Not expandable further in this minimal path.
            raw = self._read_memory_static(field_addr, field_size)
            if raw is not None and elem_type.IsValid() and \
                    elem_type.GetByteSize() in (1, 2, 4, 8):
                try:
                    n_elems = field_size // elem_type.GetByteSize()
                    elem_size = elem_type.GetByteSize()
                    parts = [
                        int.from_bytes(
                            raw[j * elem_size:(j + 1) * elem_size],
                            'little')
                        for j in range(n_elems)
                    ]
                    string_preview = '[' + ', '.join(str(p) for p in parts) + ']'
                except Exception:
                    pass
        elif is_struct:
            expand_addr = field_addr
            nested = type_name.split('::')[-1]
            var_key_out = f'pe_type:{nested}'
        else:
            # Scalar — read field_size bytes, interpret as little-endian.
            if field_size in (1, 2, 4, 8):
                raw = self._read_memory_static(field_addr, field_size)
                if raw is not None:
                    value = int.from_bytes(raw, 'little')

        return {
            'name': name,
            'type': type_name,
            'value': value,
            'byte_size': field_size,
            'is_expandable': is_expandable,
            'expand_addr': expand_addr,
            'string_preview': string_preview,
            'type_offset': 0,
            'cu_offset': 0,
            'var_key': var_key_out,
        }
