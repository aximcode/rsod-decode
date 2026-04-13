# RSOD Decode — UEFI RSOD Crash Dump Debugger

## Project Overview

Web-based UEFI RSOD (Red Screen of Death) crash dump analyzer with:
- Dual DWARF backends: pyelftools (standalone) + GDB/MI (via pygdbmi)
- Variable inspector with struct/pointer/array expansion
- Memory hex dump viewer with region labels
- Expression evaluation (GDB backend)
- Register change highlighting (CFI-unwound vs crash values)
- Multi-format support: EDK2 ARM64, Dell UEFI ARM64, Dell UEFI x86-64

## Architecture

```
rsod-debug.py          — Entry point: Flask server + CLI pre-load
rsod-decode.py         — CLI-only tool (no web UI)

backend/
  app.py               — Flask API routes (~700 lines)
  session.py           — Session dataclass + store
  serializers.py       — Variable resolution + dict serializers
  decoder.py           — Analysis orchestrator: parsing, unwinding, CFI
  dwarf_backend.py     — pyelftools DWARF backend (1300 lines)
  gdb_backend.py       — GDB/MI backend via pygdbmi (~600 lines)
  corefile.py          — Synthetic ELF core file generator
  models.py            — Data structures (FrameInfo, VarInfo, CrashInfo, etc.)
  symbols.py           — Symbol loading (.map + ELF)
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
    CrashBanner.tsx    — Crash summary header
    BacktracePanel.tsx — Frame list
    RegisterPanel.tsx  — Register display with SIMD section
    MemoryView.tsx     — Hex dump with region map
    ExpressionEval.tsx — GDB expression input
    HexAddress.tsx     — Clickable hex address component
    VarTooltip.tsx     — Hover-to-explore tooltip
    GdbPanel.tsx       — xterm.js GDB terminal
    UploadForm.tsx     — File upload with drag-drop
```

## Running

```bash
# With pre-loaded RSOD + symbols:
python rsod-debug.py /path/to/rsod.txt /path/to/CrashTest.so

# With symbol search path for auto-loading:
python rsod-debug.py rsod.txt CrashTest.so --symbol-path /path/to/symbols/

# Backend selection:
python rsod-debug.py rsod.txt symbols.so --backend auto|gdb|pyelftools

# CLI only (no web UI):
python rsod-decode.py rsod.txt symbols.so
```

## Building Frontend

```bash
cd frontend && npm install && npm run build
```

## Test Data

- QEMU RSOD: `axl-sdk/scripts/run-qemu.sh --arch AARCH64 --serial-log /tmp/rsod.txt`
- CrashTest build: `uefi-devkit/build.sh --rebuild crashdriver --arch AARCH64 --no-image`
- CrashTest.so: `uefi-devkit/build/crashhandler/aa64/CrashTest.so`

## Python Standards

- Use `from __future__ import annotations` for modern type syntax
- Annotate all function parameters and return types
- Use `pathlib.Path` over `os.path`
- Use f-strings, never `%` formatting
- Never use mutable default arguments
- Code must pass Pylance strict mode

## Key Patterns

- Frame addresses are ELF offsets; `image_base` maps to runtime addresses
- GDB backend uses `var_key` for variable object expansion; pyelftools uses `type_offset`/`cu_offset`
- `canExpand = is_expandable && (expand_addr !== null || !!varKey)`
- Frame responses cached on `Session.frame_cache` (both backends)
- Dell RSOD `-->PC`/`-->RIP` line provides `image_base = abs_addr - offset`
- EDK2 `image_base` derived from `crash_pc - frames[0].address`

## Known Limitations

- EDK2 stack dump: 512 bytes only. Dell: 4096 bytes.
- No .data/.bss runtime memory in RSOD — globals show ELF initial values (~approximate)
- GDB backend limited to frames with loaded symbols (can't unwind through Shell.efi etc.)
- x86 SIMD registers (XMM/YMM) not in Dell RSOD format
- Expression eval requires GDB backend
