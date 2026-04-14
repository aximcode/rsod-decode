"""Symbol table loading from MSVC map files and ELF binaries."""
from __future__ import annotations

import re
import sys
from collections.abc import Callable
from pathlib import Path

from .models import MapSymbol, SymbolTable, SymbolSource
from .dwarf_backend import DwarfInfo


class SymbolLoadError(Exception):
    """Raised when a symbol file cannot be loaded."""


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
    """Check if a file is an ELF binary."""
    try:
        with path.open('rb') as f:
            return f.read(4) == b'\x7fELF'
    except OSError:
        return False


def is_pe(path: Path) -> bool:
    """Check if a file is a PE/COFF binary (MZ header + PE signature)."""
    try:
        with path.open('rb') as f:
            if f.read(2) != b'MZ':
                return False
            f.seek(0x3c)
            pe_off = int.from_bytes(f.read(4), 'little')
            if pe_off <= 0 or pe_off > 0x10000:
                return False
            f.seek(pe_off)
            return f.read(4) == b'PE\x00\x00'
    except OSError:
        return False


def _load_pe_pdb_symbol_table(
    pe_path: Path, pdb_path: Path, log: Callable[[str], None],
) -> SymbolTable:
    """Build a SymbolTable for a PE+PDB pair by asking LLDB.

    LLDB's PDB symbol reader doesn't expose a flat enumerable symbol
    table the way the .map parser does — `SBModule.GetNumSymbols()`
    only returns PE exports (~75). Instead we walk every compile unit's
    line-entry table and collect the enclosing function at each line,
    which covers every function with source-line debug info (the only
    ones a backtrace will meaningfully resolve to anyway). PE exports
    are merged in as a fallback.

    Uses a short-lived SBDebugger; caller doesn't need LLDB otherwise.
    Returns an empty table on any failure so the caller can degrade.
    """
    from .lldb_loader import import_lldb
    lldb_mod = import_lldb()
    if lldb_mod is None:
        log(f"LLDB unavailable; cannot derive symbols from {pdb_path.name}")
        return SymbolTable()

    dbg = lldb_mod.SBDebugger.Create()
    try:
        dbg.SetAsync(False)
        ci = dbg.GetCommandInterpreter()
        ro = lldb_mod.SBCommandReturnObject()
        ci.HandleCommand(f'target create --arch x86_64 {pe_path}', ro)
        if not ro.Succeeded():
            log(f"LLDB target create failed: {ro.GetError().strip()}")
            return SymbolTable()
        ci.HandleCommand(f'target symbols add {pdb_path}', ro)
        if not ro.Succeeded():
            log(f"LLDB symbols add failed: {ro.GetError().strip()}")
            return SymbolTable()

        target = dbg.GetSelectedTarget()
        if not target.IsValid() or target.GetNumModules() == 0:
            log(f"PE+PDB target has no modules")
            return SymbolTable()
        module = target.GetModuleAtIndex(0)

        table = SymbolTable()
        if module.GetNumSections() > 0:
            first = module.GetSectionAtIndex(0)
            base = first.GetFileAddress()
            if base != lldb_mod.LLDB_INVALID_ADDRESS:
                table.preferred_base = base

        seen: dict[int, MapSymbol] = {}
        for i in range(module.GetNumCompileUnits()):
            cu = module.GetCompileUnitAtIndex(i)
            for j in range(cu.GetNumLineEntries()):
                le = cu.GetLineEntryAtIndex(j)
                if not le.IsValid():
                    continue
                fn = le.GetStartAddress().GetFunction()
                if not fn.IsValid():
                    continue
                start = fn.GetStartAddress().GetFileAddress()
                if start == lldb_mod.LLDB_INVALID_ADDRESS or start == 0:
                    continue
                if start in seen:
                    continue
                name = fn.GetName() or f'sub_{start:x}'
                seen[start] = MapSymbol(start, name, '', True)

        # Merge PE exports as a fallback for functions without debug info.
        for i in range(module.GetNumSymbols()):
            sym = module.GetSymbolAtIndex(i)
            if not sym.IsValid():
                continue
            sa = sym.GetStartAddress()
            if not sa.IsValid():
                continue
            addr = sa.GetFileAddress()
            if addr == lldb_mod.LLDB_INVALID_ADDRESS or addr == 0:
                continue
            if addr in seen:
                continue
            name = sym.GetName() or f'sym_{addr:x}'
            is_code = sym.GetType() == lldb_mod.eSymbolTypeCode
            seen[addr] = MapSymbol(addr, name, '', is_code)

        _build_table(table, list(seen.values()))
        return table
    finally:
        lldb_mod.SBDebugger.Destroy(dbg)


def load_symbols(path: Path, log: Callable[[str], None] | None = None,
                 dwarf_prefix: str | None = None,
                 repo_root: Path | None = None,
                 companion_path: Path | None = None,
                 pdb_path: Path | None = None) -> SymbolSource:
    """Auto-detect symbol file format and load.

    Args:
        path: Path to the primary symbol file: ELF (`.so`/`.debug`/`.elf`),
            MSVC `.map`, or PE (`.efi`).
        log: Optional callable(str) for status messages.
             Defaults to printing to stderr.
        dwarf_prefix: Optional prefix to strip from DWARF paths.
        repo_root: Optional repo root for auto-detecting dwarf_prefix.
        companion_path: Optional second file providing disassembly when
            the primary doesn't have it. Meaningful combinations:
              - primary=.map, companion=.efi (MSVC: .map has symbols,
                .efi has .text bytes)
              - primary=.efi, companion=.map (same pairing, reversed order)
            For ELF primary, companion_path is ignored.
        pdb_path: Optional MSVC `.pdb` companion. Only consulted when
            the primary is a `.efi` and no `.map` companion is present —
            lets `load_symbols` derive the symbol table from the PDB
            via a short-lived LLDB session when the user hasn't
            supplied a `.map` at all.
    """
    if log is None:
        def log(msg: str) -> None:
            print(msg, file=sys.stderr)

    elf_path: Path | None = None
    # Holds either DwarfInfo or PEBinary; models.BinaryBackend is a
    # TYPE_CHECKING-only alias so we can't annotate this at runtime.
    binary: object | None = None

    if is_elf(path):
        elf_path = path
        try:
            dwarf_info = DwarfInfo(path, dwarf_prefix=dwarf_prefix,
                                   repo_root=repo_root)
            raw = dwarf_info.get_symbols()
        except Exception as e:
            raise SymbolLoadError(f"failed to read ELF {path}: {e}") from e
        table = SymbolTable()
        _build_table(table, [MapSymbol(a, n, '', f) for a, n, f in raw])
        binary = dwarf_info
        src = 'ELF+DWARF'
    elif is_pe(path):
        # Primary is .efi: the PE provides .text bytes; companion (if any)
        # is a .map supplying symbols. When no .map is present but a
        # .pdb is, ask LLDB to enumerate functions from the PDB so the
        # backtrace still resolves.
        try:
            from .pe_backend import PEBinary, PELoadError
            binary = PEBinary(path, log=log)
        except Exception as e:
            raise SymbolLoadError(f"failed to read PE {path}: {e}") from e
        if companion_path is not None and not is_elf(companion_path) and not is_pe(companion_path):
            table = parse_map_file(companion_path)
            log(f"Paired with symbol map {companion_path.name}")
            src = 'PE+MAP'
        elif pdb_path is not None:
            table = _load_pe_pdb_symbol_table(path, pdb_path, log)
            src = 'PE+PDB'
        else:
            table = SymbolTable()
            src = 'PE'
    else:
        # Assume .map. Companion (if any) is a .efi for disassembly.
        table = parse_map_file(path)
        src = 'MAP'
        if companion_path is not None and is_pe(companion_path):
            try:
                from .pe_backend import PEBinary
                binary = PEBinary(companion_path, log=log)
            except Exception as e:
                raise SymbolLoadError(
                    f"failed to read PE companion {companion_path}: {e}"
                ) from e
            src = 'MAP+PE'

    func_count = sum(1 for s in table.symbols if s.is_function)
    data_count = len(table.symbols) - func_count
    log(f"Loaded {len(table.symbols)} symbols ({func_count} code, "
        f"{data_count} data) from {path.name} [{src}]")
    if table.preferred_base:
        log(f"Preferred base: 0x{table.preferred_base:X}")
    if table.symbols:
        log(f"Symbol range: 0x{table.addresses[0]:X} - "
            f"0x{table.addresses[-1]:X}")
    # Import DwarfInfo lazily for isinstance check (avoids top-level cycle)
    if binary is not None:
        if isinstance(binary, DwarfInfo):
            log("DWARF debug info via pyelftools (native)")
            if binary.dwarf_prefix:
                log(f"DWARF prefix: {binary.dwarf_prefix}")

    return SymbolSource(table=table, elf_path=elf_path,
                        name=path.stem, binary=binary)
