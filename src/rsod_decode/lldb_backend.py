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

from .corefile import write_corefile
from .lldb_loader import import_lldb
from .minidump import write_minidump
from .models import AddressInfo, VarInfo

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
        self._init_common(lldb, elf_path, image_base,
                          addr_slide=image_base,
                          registers_fully_populated=True)

        core_path = self._tmpdir / 'crash.core'
        write_corefile(
            registers, crash_pc, stack_base, stack_mem,
            elf_path, core_path, image_base, frames=frames)

        self._target = self._debugger.CreateTarget(str(elf_path))
        if not self._target.IsValid():
            raise RuntimeError(
                f'LLDB failed to create target for {elf_path}')

        # Slide the module BEFORE LoadCore so LLDB's unwinder sees the
        # ELF's sections at their runtime addresses. The corefile
        # itself carries PT_LOADs at runtime addresses (image_base
        # already baked in by _load_elf_sections), so this keeps both
        # views consistent.
        if image_base and self._target.GetNumModules() > 0:
            module = self._target.GetModuleAtIndex(0)
            slide_err = self._target.SetModuleLoadAddress(module, image_base)
            if not slide_err.Success():
                raise RuntimeError(
                    f'SetModuleLoadAddress failed: {slide_err.GetCString()}')

        self._load_core_and_index(core_path, stack_base, stack_mem)

    def _init_common(
        self,
        lldb: Any,
        binary_path: Path,
        image_base: int,
        addr_slide: int,
        registers_fully_populated: bool,
    ) -> None:
        """Populate the state common to both constructors.

        Decoder-facing addresses are ELF offsets for corefile mode
        (bare section offsets) and absolute file addresses for PE+PDB
        mode (ImageBase already baked in). ``addr_slide`` is the value
        to add on entry to reach the LLDB-side runtime address — set
        to ``image_base`` for ELF cores and ``0`` for PE minidumps.

        ``registers_fully_populated`` is True for ELF cores (the
        NT_PRSTATUS gregset covers every register LLDB can read) and
        False for PE minidumps (Dell RSODs carry GPRs only, no XMM
        state, so register-held scalars must be suppressed — see
        ``_sbvalue_to_varinfo``).
        """
        self._lldb = lldb
        self._elf_path = binary_path
        self._image_base = image_base
        self._addr_slide = addr_slide
        self._registers_fully_populated = registers_fully_populated
        self._tmpdir = Path(tempfile.mkdtemp(prefix='rsod_lldb_'))
        self._var_objects: dict[str, Any] = {}
        self._globals_cache: list[VarInfo] | None = None
        self._debugger = lldb.SBDebugger.Create()
        self._debugger.SetAsync(False)

    def _load_core_and_index(
        self, core_path: Path, stack_base: int, stack_mem: bytes,
    ) -> None:
        """LoadCore the synthetic crash dump and snapshot thread state.

        Shared by both constructors after the target + symbol
        provisioning is in place: feed ``core_path`` to
        ``SBTarget.LoadCore``, cache the first thread, build the
        ``pc → frame_index`` map used by ``_frame_for``, and seed
        ``_valid_ranges`` from the stack dump plus every module
        section LLDB exposes at runtime addresses.
        """
        lldb = self._lldb
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

        self._valid_ranges: list[tuple[int, int]] = []
        if stack_mem:
            self._valid_ranges.append(
                (stack_base, stack_base + len(stack_mem)))
        module = self._target.GetModuleAtIndex(0)
        for s_idx in range(module.GetNumSections()):
            sec = module.GetSectionAtIndex(s_idx)
            load = sec.GetLoadAddress(self._target)
            size = sec.GetByteSize()
            if size and load != lldb.LLDB_INVALID_ADDRESS:
                self._valid_ranges.append((load, load + size))

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
        """True if ``addr..addr+size`` lives in any known memory region.

        Also serves as the pointer-validity gate before advertising a
        variable as expandable. A pointer whose target isn't mappable
        (e.g. MSVC reuses a home-space spill slot after the initial
        arg read, leaving stale garbage in the DWARF-advertised
        location) should NOT get the ▶ expansion affordance in the
        UI — or the user clicks in and sees a struct full of dashes.
        """
        end = addr + size
        for start, rend in self._valid_ranges:
            if addr >= start and end <= rend:
                return True
        return False

    @staticmethod
    def _in_scope_variables(frame_values: Any) -> list[Any]:
        """Dedupe `SBFrame.GetVariables` output by name, preferring
        entries with a concrete location.

        LLDB's PE/PDB path leaks pre-prologue range-scoped S_LOCAL
        records through the `in_scope_only=True` flag: the same name
        appears twice — once without a location (``GetLoadAddress() ==
        0xFFFF_FFFF_FFFF_FFFF`` AND ``GetValue() is None``) and once
        with a real stack address. ELF+DWARF doesn't produce those
        duplicates, so each name appears exactly once and we keep it
        verbatim (even if it's optimized out — the frame-variable list
        still needs to report the name/type).

        Returns the SBValues in first-seen order with at most one
        entry per name. Whenever a duplicate exists, the entry with a
        concrete location (valid load address or non-None
        ``GetValue()``) wins.
        """
        def has_location(v: Any) -> bool:
            if v.GetLoadAddress() != 0xFFFFFFFFFFFFFFFF:
                return True
            return v.GetValue() is not None

        by_name: dict[str, Any] = {}
        order: list[str] = []
        for i in range(frame_values.GetSize()):
            v = frame_values.GetValueAtIndex(i)
            name = v.GetName() or '?'
            if name not in by_name:
                by_name[name] = v
                order.append(name)
                continue
            if has_location(v) and not has_location(by_name[name]):
                by_name[name] = v
        return [by_name[n] for n in order]

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
        load_addr = sv.GetLoadAddress()
        # Register-held scalars on a PE+PDB target are unreliable:
        # the Dell RSOD doesn't carry FP/vector state so LLDB falls
        # back to reading zeros for unmapped registers and reports
        # them as real "0" values. Detect register locations by the
        # string shape — addresses start with '0x', registers are
        # bare identifiers like 'eax' or 'xmm9'. Suppress the value
        # so the UI/tests skip cleanly, matching the old
        # `_pe_var_to_varinfo` behavior.
        raw_loc = (sv.GetLocation() or '').strip()
        is_register_held = bool(raw_loc) and not raw_loc.startswith('0x')
        register_unreliable = (
            is_register_held and not self._registers_fully_populated)

        # Scalars + pointers: trust GetValueAsUnsigned. For aggregates
        # we fill in a load address below instead.
        if (num_children == 0 or is_pointer) and not register_unreliable:
            if err.Success() and sv.GetValue() is not None:
                var.value = unsigned

        if (is_aggregate or is_pointer) and num_children > 0:
            valid = load_addr != self._lldb.LLDB_INVALID_ADDRESS
            if is_pointer and var.value:
                # Stale pointer gate: drop expandability when the
                # pointer target isn't in any known memory region so
                # the frontend doesn't invite a click-through into
                # garbage.
                if self._has_memory(var.value, 1):
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
        if (not var.string_preview) and is_pointer and var.value and (
                'char' in type_name):
            # LLDB's SBValue summary returns `""` for C-string pointers
            # targeting file-backed memory (e.g. PE .rdata) even though
            # `process.ReadMemory` can read the bytes — a known
            # ProcessMinidump quirk. Fall back to a manual NUL scan.
            fallback = self._read_cstring_via_process(var.value)
            if fallback:
                var.string_preview = fallback
        return var

    def _read_cstring_via_process(
        self, addr: int, max_len: int = 256,
    ) -> str | None:
        """Read a NUL-terminated UTF-8 string from live-target memory.

        `SBProcess.ReadMemory` returns ``None`` for file-backed PE
        sections under ProcessMinidump ("could not parse memory info"
        from the missing MemoryInfoListStream). `SBTarget.ReadMemory`
        takes the same buffer-filled-but-error-set shape but actually
        populates the data — trust the returned bytes when they're
        non-empty.
        """
        for length in (max_len, 64, 16, 1):
            if not self._has_memory(addr, length):
                continue
            err = self._lldb.SBError()
            sb = self._lldb.SBAddress(addr, self._target)
            data = self._target.ReadMemory(sb, length, err)
            if not data:
                continue
            raw = bytes(data)
            if not raw:
                continue
            nul = raw.find(b'\x00')
            if nul >= 0:
                raw = raw[:nul]
            return raw.decode('utf-8', errors='replace')
        return None

    def get_params(self, addr: int) -> list[VarInfo]:
        frame = self._frame_for(addr)
        if frame is None:
            return []
        raw = frame.GetVariables(True, False, False, True)
        return [self._sbvalue_to_varinfo(v, addr)
                for v in self._in_scope_variables(raw)]

    def get_locals(self, addr: int) -> list[VarInfo]:
        frame = self._frame_for(addr)
        if frame is None:
            return []
        raw = frame.GetVariables(False, True, False, True)
        return [self._sbvalue_to_varinfo(v, addr)
                for v in self._in_scope_variables(raw)]

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
                if self._has_memory(value, 1):
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
        if (not string_preview) and is_pointer and value and (
                'char' in type_name):
            # LLDB returns `""` for C-string pointers into file-backed
            # PE .rdata under ProcessMinidump (the summary is empty,
            # not missing). Fall back to a manual NUL scan.
            fallback = self._read_cstring_via_process(value)
            if fallback:
                string_preview = fallback

        # Array preview: render small integer arrays (attempts[4] style)
        # as `[v0, v1, v2, v3]` via SBValue's own child iteration. LLDB
        # doesn't supply a summary string for bare C arrays.
        if (not string_preview) and (
                type_class == self._lldb.eTypeClassArray):
            child_count = child.GetNumChildren()
            if 0 < child_count <= 16:
                parts: list[str] = []
                for i in range(child_count):
                    elem = child.GetChildAtIndex(i)
                    ev = elem.GetValue()
                    if ev is None:
                        parts.append('?')
                    else:
                        parts.append(str(elem.GetValueAsUnsigned()))
                string_preview = '[' + ', '.join(parts) + ']'

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
        # SBTarget.ReadMemory works across file-backed PE sections
        # under ProcessMinidump where SBProcess.ReadMemory returns
        # None — use it for both modes so the read path is uniform.
        sb = self._lldb.SBAddress(addr, self._target)
        data = self._target.ReadMemory(sb, size, err)
        if not data:
            return None
        raw = bytes(data)
        if not raw:
            return None
        return raw

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
        """Disassemble a window centred on `addr`.

        Decoder-facing addresses are ELF offsets for corefile mode and
        absolute file addresses for PE+PDB mode. `_addr_slide` reconciles
        the two: ``runtime = addr + _addr_slide`` is the live-target
        load address. The return list is back in the decoder's address
        space so the serializer can compare against `frame.address`.

        Forward-decoding always starts at `addr`, guaranteeing the
        target shows up as an `insn.address == addr` entry. Backward
        decoding is anchored on the enclosing function's start address
        (from `SBFunction` / `SBSymbol`) whenever we can find one; the
        alignment would otherwise be lost on variable-length x86 and
        the caller's `is_target` highlight would never match.
        """
        runtime = addr + self._addr_slide

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
                fs = start_sb.GetLoadAddress(self._target)
                fe = end_sb.GetLoadAddress(self._target)
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
                use = lldb_addr.GetLoadAddress(self._target)
                if use == self._lldb.LLDB_INVALID_ADDRESS:
                    continue
                if use < lo or use >= hi or use in seen:
                    continue
                seen.add(use)
                mnemonic = insn.GetMnemonic(self._target) or ''
                operands = insn.GetOperands(self._target) or ''
                insns.append((use - self._addr_slide, mnemonic, operands))

        # Backward half: only keep instructions strictly below runtime.
        if back_count > 0:
            _consume(_read_from(back_start, back_count), window_lo, runtime)
        # Forward half: decode from runtime itself so `addr` lands
        # exactly on an instruction boundary.
        _consume(_read_from(runtime, context * 2), runtime, window_hi)

        insns.sort(key=lambda it: it[0])
        return insns

    def is_call_before(self, addr: int) -> bool:
        runtime = addr + self._addr_slide
        sb_addr = self._lldb.SBAddress(runtime - 8, self._target)
        instructions = self._target.ReadInstructions(sb_addr, 2)
        if instructions.GetSize() == 0:
            return False
        last = instructions.GetInstructionAtIndex(instructions.GetSize() - 1)
        mnemonic = (last.GetMnemonic(self._target) or '').lower()
        return mnemonic in _CALL_MNEMONICS

    def _resolve_sb_address(self, addr: int) -> Any:
        """Resolve a decoder-facing address to an SBAddress.

        Decoder addresses are ELF offsets for corefile mode and
        absolute PE file addresses for PE+PDB mode. `_addr_slide` is
        the value needed to reach the runtime load address in each
        case (``image_base`` / ``0``). Both modes have a
        process-backed target after LoadCore, so `ResolveLoadAddress`
        works uniformly.
        """
        return self._target.ResolveLoadAddress(addr + self._addr_slide)

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
        """Return every SBInstruction in `[start, end)` in order.

        Bounds are in the decoder's address space (ELF offset for
        corefile mode, absolute PE file address for PE+PDB mode);
        `_addr_slide` reconciles them to the LLDB runtime load
        address space. Walks via `SBFunction.GetInstructions(target)`
        which returns the function's full instruction list without
        us having to guess a byte count — the `[start, end)`
        clamp is a belt-and-braces filter.
        """
        runtime_start = start + self._addr_slide
        sb = self._target.ResolveLoadAddress(runtime_start)
        if not sb.IsValid():
            return []
        fn = sb.GetFunction()
        instrs: Any
        if fn.IsValid():
            instrs = fn.GetInstructions(self._target)
        else:
            # Symbol-only (no debug info): fall back to a byte-bounded
            # read since there's no SBFunction to iterate.
            instrs = self._target.ReadInstructions(sb, max(1, end - start))
        kept: list[Any] = []
        for i in range(instrs.GetSize()):
            insn = instrs.GetInstructionAtIndex(i)
            load = insn.GetAddress().GetLoadAddress(self._target)
            if load == self._lldb.LLDB_INVALID_ADDRESS:
                continue
            a = load - self._addr_slide
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

        for insn in self._iter_function_instructions(*range_):
            mn = (insn.GetMnemonic(self._target) or '').lower()
            if not mn.startswith(('call', 'bl', 'jmp')):
                continue
            load = insn.GetAddress().GetLoadAddress(self._target)
            if load == self._lldb.LLDB_INVALID_ADDRESS:
                continue
            a = load - self._addr_slide
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
        load = last.GetAddress().GetLoadAddress(self._target)
        if load == self._lldb.LLDB_INVALID_ADDRESS:
            return None
        jmp_addr = load - self._addr_slide
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

    def make_struct_pointer_value(
        self, name: str, addr: int, type_name: str, frame_pc: int,
    ) -> str | None:
        """Create a synthetic SBValue at ``addr`` with the pointee type
        named ``type_name`` (the struct the pointer points at, not the
        pointer type itself), cache it on ``_var_objects``, and return
        a ``v_<pc>_<name>`` var_key the ``/api/expand`` path can use
        to walk the struct.

        Returns ``None`` if the type can't be resolved or the address
        isn't mappable — callers should leave the param non-expandable
        in that case. Used by the tail-call reconstructor to back-fill
        pointer-typed arguments that the standard frame-variable walk
        couldn't resolve (spill-slot reuse, register-held on entry,
        etc.) so the UI's expand affordance still works.
        """
        if not self._has_memory(addr, 1):
            return None
        pointee = self._target.FindFirstType(type_name)
        if not pointee.IsValid():
            return None
        pointee = pointee.GetCanonicalType()
        type_class = pointee.GetTypeClass()
        if type_class not in (
            self._lldb.eTypeClassStruct,
            self._lldb.eTypeClassClass,
            self._lldb.eTypeClassUnion,
        ):
            return None
        sb_addr = self._lldb.SBAddress(addr, self._target)
        sv = self._target.CreateValueFromAddress(name, sb_addr, pointee)
        if not sv.IsValid() or sv.GetNumChildren() == 0:
            return None
        var_key = f'v_{frame_pc:x}_{name}'
        self._var_objects[var_key] = sv
        return var_key

    def frame_body_rsp(self, addr: int) -> int | None:
        """Return the body-RSP (``SBFrame.GetSP()``) for the LLDB-unwound
        frame whose PC matches ``addr``, or None if no match.

        Used by the tail-call reconstructor to bootstrap the callsite
        argument resolver: we need the physical caller's post-prologue
        RSP to evaluate ``lea reg, [rsp+N]`` / ``[r11+N]`` operands.
        """
        frame = self._frame_for(addr)
        if frame is None or not frame.IsValid():
            return None
        return frame.GetSP()

    def get_function_parameters(
        self, function_name: str,
    ) -> list[tuple[str, str]]:
        """Return ``(name, type_name)`` for each declared parameter of
        ``function_name`` in ABI order, or an empty list if the function
        or its block variables can't be located.

        Uses ``SBFunction.GetBlock().GetVariables(target, args=True,
        locals=False, statics=False)`` which exposes the PDB's
        ``S_LOCAL`` parameter records — we need the names (not just
        the types from ``SBFunctionType``) so the reconstructor can
        map argument registers to the user-facing parameter name.
        """
        sctxs = self._target.FindFunctions(function_name)
        if not sctxs.GetSize():
            return []
        fn = sctxs.GetContextAtIndex(0).GetFunction()
        if not fn.IsValid():
            return []
        block = fn.GetBlock()
        if not block.IsValid():
            return []
        values = block.GetVariables(self._target, True, False, False)
        out: list[tuple[str, str]] = []
        for i in range(values.GetSize()):
            v = values.GetValueAtIndex(i)
            name = v.GetName() or ''
            type_name = v.GetTypeName() or ''
            if name:
                out.append((name, type_name))
        return out

    def resolve_callsite_args(
        self, call_addr: int, body_rsp: int | None = None,
        fp: int | None = None,
    ) -> dict[str, Any]:
        """Reconstruct MSVC x64 argument registers at a call/jmp site.

        Walks backward from the instruction at ``call_addr`` (in the
        decoder-facing address space) through the enclosing function's
        body, decoding writes to ``RCX`` / ``RDX`` / ``R8`` / ``R9``.
        ``body_rsp`` is the post-prologue RSP at the moment the call
        was about to execute — for a physical frame this is
        ``SBFrame.GetSP()``; for a tail-called wrapper the caller
        computes it from its chain context. ``fp`` is the frame pointer
        if distinct from the stack pointer.

        Returns the dict produced by
        :func:`callsite_args.resolve_callsite_args`. Registers the
        resolver couldn't decode are omitted.
        """
        from .callsite_args import (
            Instr, resolve_callsite_args as _resolve)

        sb = self._target.ResolveLoadAddress(call_addr + self._addr_slide)
        if not sb.IsValid():
            return {}
        fn = sb.GetFunction()
        if fn.IsValid():
            start_sb = fn.GetStartAddress()
            end_sb = fn.GetEndAddress()
        else:
            sym = sb.GetSymbol()
            if not sym.IsValid():
                return {}
            start_sb = sym.GetStartAddress()
            end_sb = sym.GetEndAddress()
        if not start_sb.IsValid() or not end_sb.IsValid():
            return {}
        start = start_sb.GetFileAddress()
        end = end_sb.GetFileAddress()
        if start == self._lldb.LLDB_INVALID_ADDRESS \
                or end == self._lldb.LLDB_INVALID_ADDRESS:
            return {}

        sb_insns = self._iter_function_instructions(start, end)
        instructions: list[Instr] = []
        call_index: int | None = None
        for insn in sb_insns:
            load = insn.GetAddress().GetLoadAddress(self._target)
            if load == self._lldb.LLDB_INVALID_ADDRESS:
                continue
            addr = load - self._addr_slide
            mn = insn.GetMnemonic(self._target) or ''
            ops = insn.GetOperands(self._target) or ''
            instructions.append((addr, mn, ops))
            if addr == call_addr:
                call_index = len(instructions) - 1
        if call_index is None or not instructions:
            return {}

        def reader(addr: int, size: int) -> bytes | None:
            return self.read_memory(addr, size)

        return _resolve(
            instructions, call_index=call_index,
            body_rsp=body_rsp, memory_reader=reader, fp=fp)

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
        as a symbol source and a synthetic Windows minidump mounted via
        `SBTarget.LoadCore`. The minidump carries the RSOD's register
        snapshot + stack dump; LLDB's ProcessMinidump plugin unwinds via
        the PE's `.pdata` records and auto-maps every PE section from
        the on-disk binary, so `SBProcess.ReadMemory`,
        `SBFrame.GetVariables`, and `SBValue.GetChildAtIndex` all work
        against a real (read-only) live-target surface.
        """
        lldb = import_lldb()
        if lldb is None:
            raise RuntimeError('lldb Python module not available')
        del frames  # LLDB's PDB .pdata unwinder drives the backtrace.
        instance = cls.__new__(cls)
        # PE files link with ImageBase baked into section addresses,
        # so decoder-facing addresses are already absolute — no slide.
        # Dell x86_64 RSODs carry GPRs only (no XMM/YMM), so the
        # CONTEXT blob's FP save area is zeroed and register-held
        # MSVC DWARF vars (`DW_OP_reg26 XMM9` style) must be
        # suppressed downstream — see `_sbvalue_to_varinfo`.
        instance._init_common(
            lldb, pe_path, image_base,
            addr_slide=0, registers_fully_populated=False)

        dump_path = instance._tmpdir / 'crash.dmp'
        write_minidump(
            registers, stack_base, stack_mem,
            pe_path, image_base, dump_path)

        ci = instance._debugger.GetCommandInterpreter()
        ro = lldb.SBCommandReturnObject()
        ci.HandleCommand(f'target create --arch x86_64 {pe_path}', ro)
        if not ro.Succeeded():
            lldb.SBDebugger.Destroy(instance._debugger)
            raise RuntimeError(
                f'target create failed: {ro.GetError().strip()}')
        ci.HandleCommand(f'target symbols add "{pdb_path}"', ro)
        if not ro.Succeeded():
            lldb.SBDebugger.Destroy(instance._debugger)
            raise RuntimeError(
                f'target symbols add failed: {ro.GetError().strip()}')

        instance._target = instance._debugger.GetSelectedTarget()
        if not instance._target.IsValid():
            lldb.SBDebugger.Destroy(instance._debugger)
            raise RuntimeError('PE+PDB target invalid after creation')

        instance._load_core_and_index(dump_path, stack_base, stack_mem)
        return instance
