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

import re
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


# -----------------------------------------------------------------------
# `image lookup -va` output parsing for PE+PDB per-frame variables.
#
# LLDB emits per-variable entries with DWARF-style location expressions,
# e.g. "DW_OP_breg7 RSP+32" for stack locals and "DW_OP_reg2 RCX" for
# register-held params. Entries may be range-scoped, meaning the
# location only applies when the PC is inside [lo, hi). We dedupe by
# name and pick the scope that covers the target PC.
# -----------------------------------------------------------------------

_RE_LOOKUP_VARIABLE = re.compile(
    r'Variable: id = \{[^}]+\},\s*name = "([^"]*)",\s*type = "([^"]*)",'
    r'.*?location = (.+?),\s*decl\s*=',
    re.DOTALL,
)
_RE_LOOKUP_RANGED = re.compile(
    r'^\s*\[0x([0-9a-fA-F]+),\s*0x([0-9a-fA-F]+)\)\s*->\s*(.+?)\s*$')
_RE_DW_OP_REG = re.compile(r'^\s*DW_OP_reg\d+\s+(\w+)\s*$')
_RE_DW_OP_BREG = re.compile(r'^\s*DW_OP_breg\d+\s+(\w+)([+-])(\d+)\s*$')
_RE_LOOKUP_FUNCTYPE = re.compile(r'compiler_type = "([^"]*)"')


def _count_func_params(sig: str) -> int:
    """Count parameters in a C function type signature.

    Uses the outermost parenthesized parameter list. Handles void and
    empty lists; does not try to be clever about function-pointer
    parameters, which could produce a low count in pathological cases.
    """
    depth = 0
    start = -1
    for i, ch in enumerate(sig):
        if ch == '(':
            if depth == 0:
                start = i
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0 and start >= 0:
                inner = sig[start + 1:i].strip()
                if not inner or inner == 'void':
                    return 0
                # Count top-level commas only
                d = 0
                count = 1
                for c in inner:
                    if c == '(':
                        d += 1
                    elif c == ')':
                        d -= 1
                    elif c == ',' and d == 0:
                        count += 1
                return count
    return 0


def _parse_lookup_vars(
    output: str, pc: int,
) -> list[dict[str, Any]]:
    """Parse Variable lines from `image lookup -va <pc>` text output.

    Returns entries in first-seen order, one per (name, location-scope)
    pair. Each entry: {name, type_name, kind, info, applies}, where
    kind is 'reg' (info=reg_name) or 'stack' (info=(reg, offset)).
    `applies` is True when the location covers `pc`.
    """
    entries: list[dict[str, Any]] = []
    for m in _RE_LOOKUP_VARIABLE.finditer(output):
        name = m.group(1)
        type_name = m.group(2).strip()
        raw_loc = m.group(3).strip()

        ranged = _RE_LOOKUP_RANGED.match(raw_loc)
        if ranged:
            lo = int(ranged.group(1), 16)
            hi = int(ranged.group(2), 16)
            expr = ranged.group(3).strip()
            applies = lo <= pc < hi
            has_range = True
        else:
            expr = raw_loc
            applies = True
            has_range = False

        reg_m = _RE_DW_OP_REG.match(expr)
        breg_m = _RE_DW_OP_BREG.match(expr)
        if reg_m:
            kind = 'reg'
            info: Any = reg_m.group(1).upper()
        elif breg_m:
            reg = breg_m.group(1).upper()
            off = int(breg_m.group(3))
            if breg_m.group(2) == '-':
                off = -off
            kind = 'stack'
            info = (reg, off)
        else:
            continue

        entries.append({
            'name': name,
            'type_name': type_name,
            'kind': kind,
            'info': info,
            'applies': applies,
            'ranged': has_range,
        })
    return entries


def _dedupe_lookup_vars(
    entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Pick one entry per name, preferring applicable scopes.

    When both an applicable ranged location and an applicable block-
    wide location exist for the same variable, the ranged entry wins
    (tighter scope). Unapplicable entries are only kept as fallbacks.
    """
    by_name: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for e in entries:
        name = e['name']
        cur = by_name.get(name)
        if cur is None:
            by_name[name] = e
            order.append(name)
            continue
        # Prefer applies=True, then prefer ranged (tighter scope).
        if e['applies'] and not cur['applies']:
            by_name[name] = e
        elif e['applies'] and cur['applies'] and \
                e['ranged'] and not cur['ranged']:
            by_name[name] = e
    return [by_name[n] for n in order]


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

    def _addr_mappable(self, addr: int, size: int = 1) -> bool:
        """True if `addr..addr+size` lives in any known memory region.

        Used as a pointer-validity gate before advertising a variable
        as expandable. A pointer whose target isn't mappable (e.g.
        MSVC reuses a home-space spill slot after the initial arg
        read, leaving stale garbage in the DWARF-advertised location)
        should NOT get the ▶ expansion affordance in the UI — or the
        user clicks in and sees a struct full of dashes.
        """
        if self._mode == 'pe_pdb':
            if self._stack_mem:
                off = addr - self._stack_base
                if 0 <= off and off + size <= len(self._stack_mem):
                    return True
            for file_addr, sec_size, _ in self._pe_sections:
                off = addr - file_addr
                if 0 <= off and off + size <= sec_size:
                    return True
            return False
        return self._has_memory(addr, size)

    # -----------------------------------------------------------------
    # Variable extraction
    # -----------------------------------------------------------------

    def _sbvalue_to_varinfo(self, sv: Any, pc: int) -> VarInfo:
        name = sv.GetName() or '?'
        type_name = sv.GetTypeName() or '?'
        location = sv.GetLocation() or ''
        var = VarInfo(name=name, type_name=type_name, location=location)

        # Resolve typedefs (e.g. `typedef struct { ... } CrashContext`)
        # — LLDB reports the declared type's GetTypeClass() as
        # eTypeClassTypedef until we call GetCanonicalType().
        sb_type = sv.GetType().GetCanonicalType()
        is_pointer = sb_type.IsPointerType()
        type_class = sb_type.GetTypeClass()
        is_aggregate = type_class in (
            self._lldb.eTypeClassStruct,
            self._lldb.eTypeClassClass,
            self._lldb.eTypeClassUnion,
            self._lldb.eTypeClassArray,
        )

        err = self._lldb.SBError()
        unsigned = sv.GetValueAsUnsigned(err, 0)
        num_children = sv.GetNumChildren()

        # Scalars + pointers: trust GetValueAsUnsigned. For aggregates
        # we fill in a load address below instead.
        if num_children == 0 or is_pointer:
            if err.Success() and sv.GetValue() is not None:
                var.value = unsigned

        if (is_aggregate or is_pointer) and num_children > 0:
            load_addr = sv.GetLoadAddress()
            valid = load_addr != self._lldb.LLDB_INVALID_ADDRESS
            if is_pointer and var.value:
                # Stale pointer gate: drop expandability when the
                # pointer target isn't in any known memory region so
                # the frontend doesn't invite a click-through into
                # garbage. Matches the PE-mode gate in
                # _pe_var_to_varinfo.
                if self._addr_mappable(var.value, 1):
                    var.is_expandable = True
                    var.expand_addr = var.value
                else:
                    var.is_expandable = False
            elif valid:
                var.is_expandable = True
                var.expand_addr = load_addr
                if var.value is None:
                    var.value = load_addr
            else:
                var.is_expandable = False
            if var.is_expandable:
                var_key = f'v_{pc:x}_{name}'
                self._var_objects[var_key] = sv
                var.var_key = var_key

        preview = sv.GetSummary()
        if preview and preview.startswith('"') and preview.endswith('"'):
            var.string_preview = preview[1:-1]
        return var

    def get_params(self, addr: int) -> list[VarInfo]:
        if self._mode == 'pe_pdb':
            return self._pe_get_variables(addr, args=True)
        frame = self._frame_for(addr)
        if frame is None:
            return []
        values = frame.GetVariables(True, False, False, True)
        return [self._sbvalue_to_varinfo(values.GetValueAtIndex(i), addr)
                for i in range(values.GetSize())]

    def get_locals(self, addr: int) -> list[VarInfo]:
        if self._mode == 'pe_pdb':
            return self._pe_get_variables(addr, args=False)
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
                sb_type = sv.GetType().GetCanonicalType()
                tc = sb_type.GetTypeClass()
                is_aggregate = tc in (
                    self._lldb.eTypeClassStruct,
                    self._lldb.eTypeClassClass,
                    self._lldb.eTypeClassUnion,
                    self._lldb.eTypeClassArray,
                )
                if (is_aggregate or sb_type.IsPointerType()) \
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
        sb_type = child.GetType().GetCanonicalType()
        num_children = child.GetNumChildren()
        is_pointer = sb_type.IsPointerType()
        type_class = sb_type.GetTypeClass()
        is_aggregate = type_class in (
            self._lldb.eTypeClassStruct,
            self._lldb.eTypeClassClass,
            self._lldb.eTypeClassUnion,
            self._lldb.eTypeClassArray,
        )
        is_expandable = num_children > 0 and (is_aggregate or is_pointer)

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
                if self._addr_mappable(value, 1):
                    expand_addr = value
                else:
                    # Stale child pointer — drop expandability.
                    is_expandable = False
            elif load_addr != self._lldb.LLDB_INVALID_ADDRESS:
                expand_addr = load_addr
            if is_expandable:
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
        """Disassemble a window centred on `addr`.

        Corefile mode: `addr` is an ELF offset; runtime = addr+slide and
        we report back in ELF-offset space so the serializer can compare
        against `frame.address`.

        PE+PDB mode: `addr` is already the absolute file address (PE
        links with ImageBase baked in, no slide), so we pass it
        through. SBAddress construction differs per mode — corefile
        targets have a valid load-address list, PE+PDB targets don't,
        so we go through `_resolve_sb_address` which knows the
        difference.

        Forward-decoding always starts at `addr`, guaranteeing the
        target shows up as an `insn.address == addr` entry. Backward
        decoding is anchored on the enclosing function's start address
        (from `SBFunction` / `SBSymbol`) whenever we can find one; the
        alignment would otherwise be lost on variable-length x86 and
        the caller's `is_target` highlight would never match.
        """
        file_mode = self._mode == 'pe_pdb'
        runtime = addr if file_mode else addr + self._image_base

        # Find the enclosing function's range. The backward window is
        # anchored on the function start when it's within reach, and
        # both halves are clamped to `[func_start, func_end)` so we
        # don't bleed into neighbouring functions' epilogues / int3
        # padding (which would get tagged with the wrong source
        # line by LLDB's line table).
        sb_addr = self._resolve_sb_address(addr)
        func_start_rt: int | None = None
        func_end_rt: int | None = None
        if sb_addr.IsValid():
            fn = sb_addr.GetFunction()
            if fn.IsValid():
                start_sb = fn.GetStartAddress()
                end_sb = fn.GetEndAddress()
            else:
                sym = sb_addr.GetSymbol()
                start_sb = sym.GetStartAddress()
                end_sb = sym.GetEndAddress()
            if start_sb.IsValid() and end_sb.IsValid():
                fs = (
                    start_sb.GetFileAddress() if file_mode
                    else start_sb.GetLoadAddress(self._target))
                fe = (
                    end_sb.GetFileAddress() if file_mode
                    else end_sb.GetLoadAddress(self._target))
                if fs != self._lldb.LLDB_INVALID_ADDRESS and fs > 0:
                    func_start_rt = fs
                if fe != self._lldb.LLDB_INVALID_ADDRESS and fe > fs:
                    func_end_rt = fe

        # Backward: skip entirely when addr is at (or before) the
        # function entry. Otherwise anchor on func_start.
        if func_start_rt is not None and runtime <= func_start_rt:
            back_start = runtime
            back_count = 0
        elif (
            func_start_rt is not None
            and runtime - func_start_rt <= context * 6
        ):
            back_start = func_start_rt
            back_count = max(1, (runtime - back_start) // 2 + 8)
        else:
            back_start = runtime - context * 4
            back_count = context * 2

        def _read_from(start_rt: int, count: int) -> Any:
            if file_mode:
                sb = self._target.ResolveFileAddress(start_rt)
            else:
                sb = self._lldb.SBAddress(start_rt, self._target)
            if not sb.IsValid():
                return None
            return self._target.ReadInstructions(sb, count)

        window_lo = runtime - context
        window_hi = runtime + context
        if func_start_rt is not None:
            window_lo = max(window_lo, func_start_rt)
        if func_end_rt is not None:
            window_hi = min(window_hi, func_end_rt)
        insns: list[tuple[int, str, str]] = []
        seen: set[int] = set()

        def _consume(instructions: Any, lo: int, hi: int) -> None:
            if instructions is None:
                return
            for i in range(instructions.GetSize()):
                insn = instructions.GetInstructionAtIndex(i)
                lldb_addr = insn.GetAddress()
                use = (
                    lldb_addr.GetFileAddress() if file_mode
                    else lldb_addr.GetLoadAddress(self._target))
                if use == self._lldb.LLDB_INVALID_ADDRESS:
                    continue
                if use < lo or use >= hi or use in seen:
                    continue
                seen.add(use)
                mnemonic = insn.GetMnemonic(self._target) or ''
                operands = insn.GetOperands(self._target) or ''
                offset_addr = use if file_mode else use - self._image_base
                insns.append((offset_addr, mnemonic, operands))

        # Backward half: only keep instructions strictly below runtime.
        if back_count > 0:
            _consume(_read_from(back_start, back_count), window_lo, runtime)
        # Forward half: decode from runtime itself so `addr` lands
        # exactly on an instruction boundary.
        _consume(_read_from(runtime, context * 2), runtime, window_hi)

        insns.sort(key=lambda it: it[0])
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

    def _resolve_sb_address(self, addr: int) -> Any:
        """Resolve a frame address to an SBAddress in a mode-aware way.

        Corefile mode: `addr` is an ELF offset; add the module slide and
        use `ResolveLoadAddress` which walks the process-slid section
        list. PE+PDB mode: `addr` is already an absolute file address
        (PE links with ImageBase baked in and we never called
        SetModuleLoadAddress), so `ResolveFileAddress` is the right
        lookup — `ResolveLoadAddress` silently returns an SBAddress
        with a null symbol and invalid line entry for a process-less
        target.
        """
        if self._mode == 'pe_pdb':
            return self._target.ResolveFileAddress(addr)
        runtime = addr + self._image_base
        return self._target.ResolveLoadAddress(runtime)

    def source_lines_for_addrs(
        self, addrs: list[int],
    ) -> dict[int, str]:
        result: dict[int, str] = {}
        for addr in addrs:
            sb_addr = self._resolve_sb_address(addr)
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
        sb_addr = self._resolve_sb_address(addr)
        if not sb_addr.IsValid():
            return None
        # PE+PDB exposes function names via SBAddress.GetFunction()
        # only — SBSymbol is invalid for PDB-backed targets. Prefer
        # SBFunction when it's valid and fall back to SBSymbol for
        # corefile/DWARF paths where the function scope tables
        # carry the richer info on SBSymbol.
        fn_obj = sb_addr.GetFunction()
        if fn_obj.IsValid():
            fn = fn_obj.GetName() or ''
        else:
            symbol = sb_addr.GetSymbol()
            fn = symbol.GetName() if symbol.IsValid() else ''
        line_entry = sb_addr.GetLineEntry()
        source_loc = ''
        if line_entry.IsValid():
            spec = line_entry.GetFileSpec()
            fname = spec.GetFilename() or ''
            directory = spec.GetDirectory() or ''
            if fname:
                path = f'{directory}/{fname}' if directory else fname
                source_loc = f'{path}:{line_entry.GetLine()}'
        if not fn and not source_loc:
            return None
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

    # -----------------------------------------------------------------
    # Tail-call reconstruction
    # -----------------------------------------------------------------

    def _function_range(self, name: str) -> tuple[int, int] | None:
        """Look up a function by name and return its [start, end) file
        address range, or None if not found."""
        sctxs = self._target.FindFunctions(name)
        if not sctxs.GetSize():
            return None
        fn = sctxs.GetContextAtIndex(0).GetFunction()
        if not fn.IsValid():
            return None
        start = fn.GetStartAddress()
        end = fn.GetEndAddress()
        if not start.IsValid() or not end.IsValid():
            return None
        return (start.GetFileAddress(), end.GetFileAddress())

    _CALL_COMMENT_RE = re.compile(
        r'^(?P<sym>[^\s]+(?: [^\s]+)*?) at (?P<src>[^\s]+:\d+)$')

    def _parse_call_comment(
        self, comment: str,
    ) -> tuple[str, str] | None:
        """Extract `(symbol, source_loc)` from an LLDB insn comment.

        LLDB annotates call/jmp targets with strings like
        `run_crashtest at psaentry.c:296` — `symbol at file:line`.
        When the symbol is unresolved the comment is empty.
        """
        if not comment:
            return None
        m = self._CALL_COMMENT_RE.match(comment.strip())
        if not m:
            return None
        return m.group('sym'), m.group('src')

    def _iter_function_instructions(
        self, start: int, end: int,
    ) -> list[Any]:
        """Return every SBInstruction whose address falls in
        `[start, end)` in order.

        Address space is consistently the file-address space for
        both modes — for pe_pdb that's the absolute PE file address
        (what PDB records carry), for corefile that's the ELF
        offset (what `GetFileAddress` on an in-module SBAddress
        returns). The function handles the mode-specific SBAddress
        construction and instruction-addr extraction internally so
        callers can pass `GetFileAddress()`-derived bounds
        uniformly.
        """
        file_mode = self._mode == 'pe_pdb'
        if file_mode:
            sb = self._target.ResolveFileAddress(start)
        else:
            # Corefile: use load-address space for the SBAddress
            # constructor because that's what the process-less
            # ResolveLoadAddress expects, then translate back to
            # file-addr for comparisons. image_base is the runtime
            # slide the target was loaded at.
            sb = self._target.ResolveLoadAddress(start + self._image_base)
        if not sb.IsValid():
            return []
        byte_count = max(1, end - start)
        instrs = self._target.ReadInstructions(sb, byte_count)
        kept: list[Any] = []
        for i in range(instrs.GetSize()):
            insn = instrs.GetInstructionAtIndex(i)
            lldb_addr = insn.GetAddress()
            if file_mode:
                a = lldb_addr.GetFileAddress()
            else:
                load = lldb_addr.GetLoadAddress(self._target)
                if load == self._lldb.LLDB_INVALID_ADDRESS:
                    continue
                a = load - self._image_base
            if a < start:
                continue
            if a >= end:
                break
            kept.append(insn)
        return kept

    def _locate_call_at_return(
        self, ret_addr: int, function_name: str | None = None,
    ) -> tuple[Any, int] | None:
        """Walk the enclosing function looking for the call whose
        return address is `ret_addr`. Returns `(SBInstruction,
        file_addr)` on success, None otherwise. The walk is
        bounded by the function's [start, end) range so we don't
        stumble into neighbouring code. All addresses are in the
        file-address space (ELF offset for corefile, PE file
        address for pe_pdb) — the same space `ret_addr` is in.
        """
        range_: tuple[int, int] | None = None
        if function_name:
            range_ = self._function_range(function_name)
        if range_ is None:
            sb_addr = self._resolve_sb_address(ret_addr)
            if not sb_addr.IsValid():
                return None
            fn = sb_addr.GetFunction()
            if fn.IsValid():
                start_sb = fn.GetStartAddress()
                end_sb = fn.GetEndAddress()
            else:
                sym = sb_addr.GetSymbol()
                if not sym.IsValid():
                    return None
                start_sb = sym.GetStartAddress()
                end_sb = sym.GetEndAddress()
            if not start_sb.IsValid() or not end_sb.IsValid():
                return None
            start = start_sb.GetFileAddress()
            end = end_sb.GetFileAddress()
            if start == self._lldb.LLDB_INVALID_ADDRESS:
                return None
            range_ = (start, end)

        file_mode = self._mode == 'pe_pdb'
        for insn in self._iter_function_instructions(*range_):
            mn = (insn.GetMnemonic(self._target) or '').lower()
            if not mn.startswith(('call', 'bl', 'jmp')):
                continue
            insn_addr = insn.GetAddress()
            if file_mode:
                a = insn_addr.GetFileAddress()
            else:
                load = insn_addr.GetLoadAddress(self._target)
                if load == self._lldb.LLDB_INVALID_ADDRESS:
                    continue
                a = load - self._image_base
            if a + insn.GetByteSize() == ret_addr:
                return (insn, a)
        return None

    def find_callee_at_return_addr(
        self, ret_addr: int, function_name: str | None = None,
    ) -> tuple[str, str] | None:
        """Find the call that returns to `ret_addr` and parse its target.

        Returns `(callee_symbol, callee_source_loc)` from LLDB's
        annotation comment, or None if the call is indirect or
        unresolved. Corefile mode expects `ret_addr` as an ELF
        offset; pe_pdb mode expects an absolute file address.
        """
        located = self._locate_call_at_return(ret_addr, function_name)
        if located is None:
            return None
        insn, _ = located
        comment = insn.GetComment(self._target) or ''
        return self._parse_call_comment(comment)

    def call_site_addr_for_return(
        self, ret_addr: int,
    ) -> int | None:
        """Return the file address of the call instruction whose
        return address is `ret_addr`, or None if not found.

        This is what the UI's disassembly tab should center on for a
        non-crash frame: the actual CALL / BL instruction, not the
        address past it. Corefile mode returns an ELF offset,
        pe_pdb mode returns an absolute file address — matching the
        address space of `frame.address` in each mode.
        """
        located = self._locate_call_at_return(ret_addr)
        if located is None:
            return None
        _, insn_addr = located
        return insn_addr

    def tail_call_target(
        self, function_name: str,
    ) -> tuple[str, int, str] | None:
        """Locate `function_name`'s terminating tail-call jmp.

        If the function ends in an unconditional `jmp <known_sym>`
        (no instructions after), returns a tuple of
        `(target_symbol_name, jmp_file_addr, jmp_source_loc)` — the
        symbol the jmp lands on, the file address of the jmp
        instruction itself, and the `file:line` source location of
        the jmp from LLDB's line table. Returns None when the
        function has a proper `ret`, the tail target is indirect,
        or the target symbol is not resolvable.

        Callers use the jmp's own `(addr, source_loc)` as the
        "current location" of a synthetic tail-called frame —
        that's more meaningful than the function entry since it
        shows where control transferred to the next link in the
        chain.
        """
        range_ = self._function_range(function_name)
        if range_ is None:
            return None
        insns = self._iter_function_instructions(*range_)
        if not insns:
            return None
        last = insns[-1]
        mn = (last.GetMnemonic(self._target) or '').lower()
        if not mn.startswith('jmp') and mn not in ('b',):
            return None
        parsed = self._parse_call_comment(last.GetComment(self._target) or '')
        if parsed is None:
            return None
        target_symbol, _target_src = parsed
        lldb_addr = last.GetAddress()
        file_mode = self._mode == 'pe_pdb'
        if file_mode:
            jmp_addr = lldb_addr.GetFileAddress()
        else:
            load = lldb_addr.GetLoadAddress(self._target)
            if load == self._lldb.LLDB_INVALID_ADDRESS:
                return None
            jmp_addr = load - self._image_base
        if jmp_addr == self._lldb.LLDB_INVALID_ADDRESS:
            return None
        # Look up the source line for the jmp itself (caller's last
        # executed line, not the callee's entry).
        jmp_sb = self._resolve_sb_address(jmp_addr)
        jmp_src = ''
        if jmp_sb.IsValid():
            le = jmp_sb.GetLineEntry()
            if le.IsValid():
                spec = le.GetFileSpec()
                fname = spec.GetFilename() or ''
                directory = spec.GetDirectory() or ''
                if fname:
                    path = f'{directory}/{fname}' if directory else fname
                    jmp_src = f'{path}:{le.GetLine()}'
        return (target_symbol, jmp_addr, jmp_src)

    def function_entry_source_loc(
        self, function_name: str,
    ) -> tuple[int, str] | None:
        """Look up a function by name and return
        `(entry_file_addr, "file:line")` for its first line entry, or
        None if the function isn't found.
        """
        sctxs = self._target.FindFunctions(function_name)
        if not sctxs.GetSize():
            return None
        fn = sctxs.GetContextAtIndex(0).GetFunction()
        if not fn.IsValid():
            return None
        start = fn.GetStartAddress()
        if not start.IsValid():
            return None
        file_addr = start.GetFileAddress()
        le = start.GetLineEntry()
        source_loc = ''
        if le.IsValid():
            spec = le.GetFileSpec()
            fname = spec.GetFilename() or ''
            directory = spec.GetDirectory() or ''
            if fname:
                path = f'{directory}/{fname}' if directory else fname
                source_loc = f'{path}:{le.GetLine()}'
        return (file_addr, source_loc)

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

        # Per-frame post-prologue RSP map for DWARF [RSP+offset]
        # resolution. The crash frame's RSP is the raw register value;
        # each subsequent frame's RSP is derived from where its
        # predecessor's return-address slot sits on the stack.
        instance._pe_frame_rsps = instance._compute_pe_frame_rsps(
            frames, stack_base, stack_mem,
            registers.get('RSP', 0))
        return instance

    def _compute_pe_frame_rsps(
        self,
        frames: list[tuple[int, int]] | None,
        stack_base: int,
        stack_mem: bytes,
        crash_rsp: int,
    ) -> dict[int, int]:
        """Derive `{frame_return_addr: effective_rsp}` for PE mode.

        MSVC x64 has no CFI we can use without a process, so we walk
        the stack ourselves: each frame's return-address slot was
        pushed by the caller's `call` instruction, so `slot_addr + 8`
        is the caller's post-prologue RSP (MSVC doesn't mutate RSP
        mid-body absent alloca).
        """
        result: dict[int, int] = {}
        if not frames:
            return result
        # Frame 0 is the crash frame — its RSP is the registered value.
        result[frames[0][1]] = crash_rsp

        min_offset = 0
        for i in range(1, len(frames)):
            # Each frame's own return address was pushed by its caller's
            # `call` instruction, so searching for it locates the slot
            # at (frame_i_post_prologue_rsp - 8).
            target = frames[i][1]
            target_bytes = target.to_bytes(8, 'little', signed=False)
            slot_offset: int | None = None
            off = min_offset - (min_offset % 8)
            while off <= len(stack_mem) - 8:
                if stack_mem[off:off + 8] == target_bytes:
                    slot_offset = off
                    break
                off += 8
            if slot_offset is None:
                continue
            result[frames[i][1]] = stack_base + slot_offset + 8
            min_offset = slot_offset + 8
        return result

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

    def _resolve_pe_frame_rsp(self, lookup_pc: int) -> int | None:
        """Find the PE-mode RSP for a frame at or near `lookup_pc`.

        Serializer passes either `frame.address` (crash frame) or
        `frame.call_addr - 1` (non-crash) as `lookup_pc`, so we accept
        anything within ~16 bytes of a known frame return address.
        """
        if lookup_pc in self._pe_frame_rsps:
            return self._pe_frame_rsps[lookup_pc]
        for key, rsp in self._pe_frame_rsps.items():
            if abs(key - lookup_pc) <= 16:
                return rsp
        return None

    def _pe_get_variables(
        self, lookup_pc: int, args: bool,
    ) -> list[VarInfo]:
        """Pre-resolve params/locals for a PE+PDB frame at `lookup_pc`.

        Parses `image lookup -va <lookup_pc>` output into a list of
        variables with DWARF-style locations, deduplicates by name
        (picking the scope that covers `lookup_pc`), splits into
        args vs. locals using the function type signature, and
        resolves values using the frame's computed RSP.
        """
        rsp = self._resolve_pe_frame_rsp(lookup_pc)
        ci = self._debugger.GetCommandInterpreter()
        ro = self._lldb.SBCommandReturnObject()
        ci.HandleCommand(f'image lookup -va 0x{lookup_pc:x}', ro)
        if not ro.Succeeded():
            return []
        output = ro.GetOutput()

        parsed = _dedupe_lookup_vars(_parse_lookup_vars(output, lookup_pc))
        if not parsed:
            return []

        ft_m = _RE_LOOKUP_FUNCTYPE.search(output)
        param_count = _count_func_params(ft_m.group(1)) if ft_m else 0
        chosen = parsed[:param_count] if args else parsed[param_count:]
        return [self._pe_var_to_varinfo(v, lookup_pc, rsp) for v in chosen]

    def _pe_var_to_varinfo(
        self,
        entry: dict[str, Any],
        lookup_pc: int,
        frame_rsp: int | None,
    ) -> VarInfo:
        """Turn one parsed image-lookup entry into a pre-resolved VarInfo.

        Stack-based locations (`DW_OP_breg7 RSP+N`) are resolved via
        the frame's effective RSP + stack_mem; register locations are
        resolved from the crash registers only when the target frame
        is the crash frame itself (callee-saved values aren't preserved
        across non-tail calls and we have no CFI to unwind them).
        """
        name = entry['name']
        type_name = entry['type_name']
        kind = entry['kind']
        info = entry['info']

        var = VarInfo(name=name, type_name=type_name)
        # Crash frame is the first entry in the RSP map (PE mode stores
        # it keyed by `frames[0].address`, which equals the crash PC).
        crash_pc = next(iter(self._pe_frame_rsps), None)
        is_crash_frame = (crash_pc is not None
                          and abs(lookup_pc - crash_pc) <= 16)

        addr: int | None = None
        if kind == 'reg':
            reg_name = info
            var.location = reg_name
            if is_crash_frame and reg_name in self._crash_registers:
                var.reg_name = reg_name
                var.value = self._crash_registers[reg_name]
            else:
                # Non-crash frame: register values aren't preserved
                # across intervening calls and we have no CFI to
                # unwind them. Mark the var pre-resolved as None so
                # the serializer doesn't read a wrong crash-RSP reg.
                var.is_expandable = False
            return var
        # Stack-based location
        reg_name, offset = info
        if reg_name == 'RSP' and frame_rsp is not None:
            addr = frame_rsp + offset
        elif reg_name in self._crash_registers:
            addr = self._crash_registers[reg_name] + offset
        var.location = f'[{reg_name}{offset:+d}]'

        # Type classification via SBType when the PDB defines the type.
        sb_type = self._find_pe_type(self._canonical_type_name(type_name))
        is_pointer = type_name.rstrip().endswith('*')
        is_array = '[' in type_name and type_name.rstrip().endswith(']')
        is_struct = False
        byte_size = 0
        if sb_type is not None:
            byte_size = sb_type.GetByteSize() or 0
            tc = sb_type.GetTypeClass()
            is_struct = tc in (
                self._lldb.eTypeClassStruct,
                self._lldb.eTypeClassClass,
                self._lldb.eTypeClassUnion,
            )

        if addr is None:
            if var.value is not None:
                var.is_expandable = False
            return var

        if is_pointer:
            raw = self._read_memory_static(addr, 8)
            if raw is not None:
                var.value = int.from_bytes(raw, 'little')
            pointee_name = type_name.rstrip()[:-1].strip()
            pointee_base = self._canonical_type_name(pointee_name)
            pointee_type = self._find_pe_type(pointee_base)
            is_pointee_struct = False
            if pointee_type is not None:
                tc = pointee_type.GetTypeClass()
                is_pointee_struct = tc in (
                    self._lldb.eTypeClassStruct,
                    self._lldb.eTypeClassClass,
                    self._lldb.eTypeClassUnion,
                )
            # Only offer expansion if the pointer target is mappable.
            # Dangling/stale pointers (e.g. MSVC spill slot reuse —
            # initialize_test's `config` param at [RSP+96] reads
            # garbage after the first line of the body) get the
            # expandable flag dropped so the UI doesn't invite the
            # user to dive into a struct of dashes.
            if var.value and is_pointee_struct and \
                    self._addr_mappable(var.value, 1):
                var.is_expandable = True
                var.expand_addr = var.value
                var.var_key = f'pe_type:{pointee_base}'
            else:
                var.is_expandable = False
            # char* → try to read the pointed-to C string
            if var.value and 'char' in type_name:
                var.string_preview = self._read_cstring_static(var.value, 256)
            return var

        if is_struct:
            var.is_expandable = True
            var.expand_addr = addr
            var.value = addr
            var.var_key = f'pe_type:{self._canonical_type_name(type_name)}'
            return var

        if is_array:
            var.is_expandable = True
            var.expand_addr = addr
            # Match the existing expand_type array preview shape.
            if sb_type is not None and byte_size > 0:
                raw = self._read_memory_static(addr, byte_size)
                elem = sb_type.GetArrayElementType()
                esize = elem.GetByteSize() if elem.IsValid() else 0
                if raw is not None and esize in (1, 2, 4, 8):
                    n = byte_size // esize
                    parts = [
                        int.from_bytes(
                            raw[j * esize:(j + 1) * esize], 'little')
                        for j in range(n)
                    ]
                    var.string_preview = (
                        '[' + ', '.join(str(p) for p in parts) + ']')
            return var

        # Scalar: read the bytes and store as int.
        size = byte_size if byte_size in (1, 2, 4, 8) else 0
        if size == 0:
            size = self._scalar_size(type_name)
        if size in (1, 2, 4, 8):
            raw = self._read_memory_static(addr, size)
            if raw is not None:
                var.value = int.from_bytes(raw, 'little')
                var.is_expandable = False
        return var

    @staticmethod
    def _canonical_type_name(type_name: str) -> str:
        """Strip qualifiers/keywords to get a bare lookup name.

        Handles 'const', 'volatile', and 'struct '/'class '/'union '
        prefixes. Returns the innermost identifier for namespaced
        types (C++ ::-separated paths).
        """
        t = type_name.strip().rstrip('*').strip()
        for prefix in ('const ', 'volatile ', 'struct ', 'class ', 'union '):
            while t.startswith(prefix):
                t = t[len(prefix):].strip()
        return t.split('::')[-1]

    @staticmethod
    def _scalar_size(type_name: str) -> int:
        """Heuristic size for scalar type names when SBType isn't available."""
        t = type_name.strip().replace('const ', '').replace('volatile ', '')
        if t in ('char', 'signed char', 'unsigned char', 'int8_t', 'uint8_t', 'bool'):
            return 1
        if t in ('short', 'signed short', 'unsigned short', 'int16_t', 'uint16_t'):
            return 2
        if t in ('int', 'signed int', 'unsigned int', 'int32_t', 'uint32_t'):
            return 4
        if t in ('long long', 'signed long long', 'unsigned long long',
                 'int64_t', 'uint64_t'):
            return 8
        if t.startswith('long'):
            return 8  # MSVC long is 4, but long long is 8; be conservative.
        return 0

    def _pe_field_to_dict(self, field: Any, struct_addr: int) -> dict:
        """Turn one SBTypeMember into the /api/expand field dict format."""
        name = field.GetName() or '?'
        field_type = field.GetType()
        type_name = field_type.GetName() or '?'
        field_off = field.GetOffsetInBytes()
        field_addr = struct_addr + field_off
        field_size = field_type.GetByteSize()

        # Resolve typedefs before checking type class — LLDB reports
        # `typedef struct { ... } Foo` as eTypeClassTypedef.
        canonical_field_type = field_type.GetCanonicalType()
        is_pointer = canonical_field_type.IsPointerType()
        is_array = canonical_field_type.IsArrayType()
        type_class = canonical_field_type.GetTypeClass()
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
                pointee = canonical_field_type.GetPointeeType()
                pointee_name = pointee.GetName() or ''
                if 'char' in pointee_name:
                    string_preview = self._read_cstring_static(value, 256)
                # Pointer to struct → expand the pointee at the
                # pointer value, but only if the target is mappable.
                # Stale/dangling pointers stay non-expandable.
                pointee_class = pointee.GetTypeClass()
                if pointee_class in (
                    self._lldb.eTypeClassStruct,
                    self._lldb.eTypeClassClass,
                    self._lldb.eTypeClassUnion,
                ) and self._addr_mappable(value, 1):
                    expand_addr = value
                    pointee_base = pointee_name.split('::')[-1]
                    var_key_out = f'pe_type:{pointee_base}'
                else:
                    is_expandable = False
            else:
                is_expandable = False
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
            value = field_addr
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
