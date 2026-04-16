# RSOD Decode — UEFI RSOD Crash Dump Debugger

## Project Overview

UEFI RSOD (Red Screen of Death) crash dump analyzer. Ships as a
single `rsod` binary with `decode` (text report) and `serve` (web
UI) subcommands, plus a standalone `rsod.pyzw` zipapp.

- Three DWARF backends: pyelftools (standalone baseline, always
  available), LldbBackend (richer; ELF+DWARF via synthetic corefile,
  and PE+PDB via static `target create` + `target symbols add`),
  GdbBackend (ELF+DWARF cross-check via pygdbmi, used by the LLDB
  terminal tab and /api/eval as a fallback when system lldb is
  absent)
- Variable inspector with struct/pointer/array expansion, typedef-aware
- Memory hex dump viewer with region labels
- Expression evaluation (LLDB or GDB backend)
- In-browser LLDB and GDB terminal tabs sharing the session's debugger
  state
- Register change highlighting (CFI-unwound vs crash values)
- Multi-format support: EDK2 ARM64, Dell UEFI ARM64, Dell UEFI x86-64,
  MSVC EPSA x86-64 (with or without PDB)

## Architecture

```
pyproject.toml         — Packaging + deps + pytest config (console script: rsod)
src/rsod_decode/
  __main__.py          — `rsod decode|serve` subcommand dispatcher
  server.py            — Flask server launcher + browser open (`rsod serve`)
  cli.py               — Text-report CLI (`rsod decode`)
  app.py               — Flask API routes — thin JSON wrappers over ingest.py + service.py
  ingest.py            — Session lifecycle: stage→hash→dedup→promote→analyze→persist
                         (no Flask dep; all callers go through ingest_session())
  service.py           — Shared analysis pipeline: backend pick + source_loc
                         backfill + tail-call reconstruction + frame_details
  session.py           — Session dataclass + from/as_analysis_context adapters
  resource_paths.py    — frontend_dist() helper (pyzw-aware via $RSOD_FRONTEND_DIST)
  pdb_routing.py       — MSVC PE/.map/.pdb companion detection
  serializers.py       — Variable resolution + dict serializers
  decoder.py           — analyze_rsod pipeline + text formatters
  dwarf_backend.py     — pyelftools DWARF backend (~1300 lines)
  pe_backend.py        — PE/COFF binary backend (sections + capstone disasm)
  gdb_backend.py       — GDB/MI backend via pygdbmi (~600 lines)
  lldb_backend.py      — LLDB backend via system lldb Python API (~1250 lines)
                         - Corefile mode: synthetic ELF core via write_corefile +
                           SetModuleLoadAddress + LoadCore + SBFrame.GetVariables
                         - PE+PDB mode: static target via `target create --arch x86_64`
                           + `target symbols add`; per-frame RSP derived from stack_mem
                           scan; vars parsed from `image lookup -va` output
  lldb_bridge.py       — In-process SBCommandInterpreter wrapper for /ws/lldb
  lldb_loader.py       — sys.path shim to import system lldb from a venv
  corefile.py          — Synthetic ELF core generator (ELFOSABI_LINUX for LLDB)
  models.py            — Data structures (FrameInfo, VarInfo, CrashInfo, etc.)
  symbols.py           — Symbol loading (.map + ELF + PE+PDB via LLDB CU iteration)
  gdb_bridge.py        — PTY-based GDB terminal bridge
  esr.py               — ARM64 ESR decode tables
  decoders/
    base.py            — FormatDecoder ABC + shared Dell decode logic
    annotations.py     — Symbol annotation helpers
    unwinding.py       — FP/RBP chain walkers + stack dump parser
    edk2_arm64.py      — EDK2 ARM64 format (QEMU)
    edk2_x64.py        — EDK2 x86-64 format
    uefi_arm64.py      — Dell UEFI ARM64 format
    uefi_x86.py        — Dell UEFI x86-64 format

frontend/              — React 19 + TypeScript + Tailwind v4 + Vite
  src/components/
    detail/            — DetailPanel split into focused components
    CrashBanner.tsx    — Crash summary header + 3-way backend toggle (pyelf/gdb/lldb)
    BacktracePanel.tsx — Frame list
    RegisterPanel.tsx  — Register display with SIMD section
    MemoryView.tsx     — Hex dump with region map
    ExpressionEval.tsx — LLDB/GDB expression input
    HexAddress.tsx     — Clickable hex address component
    VarTooltip.tsx     — Hover-to-explore tooltip
    LldbConsole.tsx    — xterm.js LLDB console (in-process SBCommandInterpreter)
    GdbPanel.tsx       — xterm.js GDB terminal
    UploadForm.tsx     — File upload with drag-drop (.txt/.log/.map/.efi/.so/.debug/.pdb)
```

## Installing

```bash
pip install -e ".[gdb,dev]"
# Optional browser tests:
pip install -e ".[browser]" && python -m playwright install chromium
```

Exposes a single `rsod` console script with `decode` and `serve` subcommands.
The same code path ships as a standalone `rsod.pyzw` via `python build_pyz.py`
(requires `cd frontend && npm run build` first).

**LLDB backend**: requires the system lldb Python module (from LLVM,
typically `/usr/lib64/python3.*/site-packages/lldb` on Fedora/RHEL,
provided by the `lldb` package). `lldb_loader.py` finds it from a venv
without `--system-site-packages`. Falls back cleanly if not installed
— auto-detect drops to GDB then pyelftools.

## Running

```bash
# Web UI, opens a browser tab:
rsod serve /path/to/rsod.txt /path/to/CrashTest.so

# Symbol search path for auto-loading extra modules:
rsod serve rsod.txt CrashTest.so --symbol-path /path/to/symbols/

# Backend override (auto prefers lldb → gdb → pyelftools):
rsod serve rsod.txt symbols.so --backend auto|lldb|gdb|pyelftools

# MSVC PE + PDB session (any order of the extras):
rsod serve rsod.txt psa.map -s psa.efi -s psa.pdb

# MSVC PE + PDB session without the .map (symbols derived from PDB via LLDB):
rsod serve rsod.txt psa.efi -s psa.pdb

# Text report CLI (no web UI, no browser):
rsod decode rsod.txt symbols.so -v --backend lldb -o out.txt

# Standalone pyzw (same subcommands, same flags):
python rsod.pyzw decode rsod.txt symbols.so
python rsod.pyzw serve  rsod.txt symbols.so --port 9090
```

## Building Frontend

```bash
cd frontend && npm install && npm run build
```

## Test Data

- QEMU RSOD: `axl-sdk/scripts/run-qemu.sh --arch AARCH64 --serial-log /tmp/rsod.txt`
- CrashTest build: `uefi-devkit/build.sh --rebuild crashdriver --arch AARCH64 --no-image`
- CrashTest.so: `uefi-devkit/build/crashhandler/aa64/CrashTest.so`
- PSA x64 production fixture: `tests/fixtures/psa/` (real R470 `fGndBounce` crash)
- PSA x64 forcecrash fixture: `tests/fixtures/psa_x64_forcecrash/` — deterministic
  ground-truth fixture from Dell EPSA 4303.56 + `-forcecrash` hook (adapted from
  `uefi-devkit/crashtest/crashtest.c`, inlined into EPSA's `PsaEntry.c`). Captured on
  PowerEdge XE7745. Matched .efi/.pdb pair, known faulting function, known struct
  values — see that dir's `BUILD.md` and `.claude/memory/project_psa_forcecrash_fixture.md`

## Python Standards

- Use `from __future__ import annotations` for modern type syntax
- Annotate all function parameters and return types
- Use `pathlib.Path` over `os.path`
- Use f-strings, never `%` formatting
- Never use mutable default arguments
- Code must pass Pylance strict mode

## Key Patterns

- Frame addresses are ELF offsets; `image_base` maps to runtime addresses.
  PE fixtures (psa_x64*) are an exception: frame addresses are already
  runtime values because PE sections link with ImageBase baked in.
- pyelftools uses `type_offset`/`cu_offset` for expansion; GDB and LLDB
  use `var_key`. LLDB's var_key is either `v_{pc:x}_{name}` (ELF
  corefile mode, keyed to a cached SBValue) or `pe_type:<TypeName>`
  (PE+PDB mode, routed through `SBModule.FindTypes` + field-at-address
  reads). Both arrive at the same `/api/expand` endpoint.
- `canExpand = is_expandable && (expand_addr !== null || !!varKey)`
- LldbBackend drops `is_expandable` when a pointer target isn't in any
  known memory region (`_addr_mappable` check) — covers MSVC spill-slot
  reuse where the DWARF-advertised location holds stale scratch data.
- Typedef'd aggregates need `SBType.GetCanonicalType()` before calling
  `GetTypeClass()` — LLDB reports `typedef struct { ... } Foo` as
  `eTypeClassTypedef (32768)`, not `eTypeClassStruct (16384)`. All four
  call sites in lldb_backend.py resolve canonical types before class
  checks.
- Frame responses cached on `Session.frame_cache` (all backends)
- Dell RSOD `-->PC`/`-->RIP` line provides `image_base = abs_addr - offset`
- EDK2 `image_base` derived from `crash_pc - frames[0].address`
- GDB is ELF-only: `/api/session` auto-init skips GDB for PE sessions,
  `/api/backend` rejects gdb target when `session.pe_path is not None`,
  and GET `/api/session` reports `gdb_available = gdb_available() and
  session.pe_path is None` so the frontend grays out the button.
- LLDB corefile mode requires `SetModuleLoadAddress(module, image_base)`
  BEFORE `LoadCore` — reversed order loses symbol resolution.
- LLDB PE+PDB mode derives per-frame RSP by scanning `stack_mem` for
  each frame's own return-address slot (since MSVC has no CFI we can
  use without a live process); `frame_rsp = slot_addr + 8`.

## Known Limitations

- EDK2 stack dump: 512 bytes only. Dell: 4096 bytes.
- No .data/.bss runtime memory in RSOD — globals show ELF initial values (~approximate)
- GDB backend limited to frames with loaded symbols (can't unwind through Shell.efi etc.);
  LLDB has the same limitation but additionally handles PE+PDB which GDB doesn't.
- x86 SIMD registers (XMM/YMM) not in Dell RSOD format — e.g. MSVC x64
  often stores ints in XMM regs for trigger_gp_fault's `vector` param,
  so the name/type pin but the value reads as None.
- MSVC PDB spill-slot reuse: the compiler stores a pointer parameter
  in its home-space slot `[RSP+N]` at function entry, then reuses that
  slot later in the body. PDB location info can't express lifetime
  cutoffs, so `initialize_test`'s `config` param (at `[RSP+96]`) reads
  stale garbage at crash time. The `_addr_mappable` gate removes the
  expand arrow; the real `config` lives as a local in the caller's
  frame (fForceCrashIfRequested on the `psa_x64_forcecrash` fixture).
- MSVC tail-call optimization is common: `__declspec(noinline)` suppresses inlining
  but NOT tail calls. Middle wrappers that just forward to one other function get
  collapsed into `jmp`s, so the real stack depth is often shorter than the source
  call chain. The `psa_x64_forcecrash` fixture demonstrates this — source has 8
  frames, runtime stack shows ~5.
- PE+PDB per-frame variable discovery parses `image lookup -va <pc>` text;
  variables held in MSVC-specific DWARF regs (e.g. reg26 = XMM9) are
  named + typed but unresolvable without XMM in the crash register dump.
- PE+PDB array element expansion: `attempts[4]` renders as a preview
  string `[0, 1, 0, 0]` but individual elements aren't expandable
  (no per-index child synthesis in `_pe_field_to_dict`).
