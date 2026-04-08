# rsod-decode.py — RSOD Stack Dump Decoder

Resolves raw addresses in UEFI RSOD (Red Screen of Death) stack dumps to
function names, source files, and line numbers.  Replaces the Windows-only
`epsaMap.bat` + `processRSOD.pl` workflow.

## Quick Start

```
python3 rsod-decode.py <rsod-log> <symbol-file> [-o output] [-v] [--base HEX]
```

**x86-64 example** (MSVC `.map` file):
```
python3 rsod-decode.py putty.txt pf4303.efi.map
```

**ARM64 example** (GCC `.so` file with debug symbols):
```
python3 rsod-decode.py rsod.txt af4305.efi.so
```

**ARM64 verbose** (adds disassembly, source context, parameters):
```
python3 rsod-decode.py rsod.txt af4305.efi.so -v
```

Output is written to `<log>_decode.txt` by default (override with `-o`).

## Getting Symbol Files

Symbol files are released to the NAS with every Jenkins build:

```
\\AUSPWDSAPP03.aus.amer.dell.com\CPGDiag$\Releases\EPSA\<VERSION>\TEST\map\
```

For example, release 4305A03:

```
\\AUSPWDSAPP03.aus.amer.dell.com\CPGDiag$\Releases\EPSA\4305A03\TEST\map\
```

### x86-64 builds (4303 branch)

Use the `.map` file.  The map file contains function names and object files
but no source line numbers.

| File | Description |
|------|-------------|
| `pf4303.efi.map` | DD_SERVER (PowerEdge server, full ESG) |
| `Nautilus4303.efi.map` | Nautilus factory |
| `psaDeft4303.efi.map` | DEFT (Dell EFI Functional Test) |
| `dbg_pf4303.efi.map` | Debug build |

### ARM64 builds (4305 branch)

Use the `.so` file.  The `.so` is the pre-stripped ELF shared object with
full DWARF debug symbols, enabling function names AND source file:line
resolution.

| File | Description |
|------|-------------|
| `af4305.efi.so` | ARM64 full ESG (PowerEdge ARM servers) |
| `pf4305.efi.so` | x86-64 build (also available as `.map`) |
| `pf4305.efi.map` | x86-64 MSVC linker map |

Note: The ARM64 `.efi` on the NAS is **stripped** (no symbols).  Always use
the `.so` for decoding.

## Capturing an RSOD

Connect to the server's iDRAC via SSH, then use the serial console:

```
racadm>> console com2
```

When the RSOD appears, copy the full text from PuTTY (or save the PuTTY
session log).  The capture should include the register dump and stack dump.

See `Document\developer.txt` section "Crash dumps for RSOD or YSOD" for
detailed instructions.

## Output Structure

The output has three sections: crash summary, annotated RSOD, and backtrace.
Verbose mode (`-v`) adds four more sections for frame #0: parameters,
locals, disassembly, and source context.

### Crash Summary (always shown)

```
--- Crash Summary ---
Exception: Synchronous exceptions, Syndrome:PC alignment fault
Crash PC:  0x1 [not in image]
Image:     af4305.efi (base 0x0)
ESR:       0x8A000000 -- EC=0x22 PC Alignment Fault, IL=1, ISS=0x0000000
FAR:       0x0000000000000001 -- NULL pointer dereference
```

For ARM64, the ESR register is decoded to show the exception class (Data
Abort, Instruction Abort, PC Alignment Fault, etc.) and for data aborts
the fault type (translation fault, permission fault, etc.).

### Annotated RSOD (always shown)

The original RSOD text with symbol annotations appended to each resolvable
address.  Same format as the v1 tool.

### Clean Backtrace (always shown)

A gdb-style numbered backtrace with function names, source locations, and
inline expansion (ARM64 with DWARF):

```
--- Backtrace ---
#0   0x1098 in cBeepCode::cBeepCode(unsigned short) at EPSA/UI/BeepCode.cpp:145 [psa.efi]
#1   0x321C in cDellTitleBar::Draw() at EPSA/Libs/PegLib/pthing.hpp:221 [psa.efi]
      (inlined) cDellTitleBar::Draw() at EPSA/UI/DellTitle.cpp:528
#4   0x62FC in cExec::fPromptTestError(...) at EPSA/UI/ePrompt.cpp:294 [psa.efi]
```

### Parameters — verbose only (`-v`)

Shows real parameter names and types from DWARF debug info, with
PC-accurate register/stack location tracking:

```
--- Parameters (frame #0: fPromptTestError) ---
  this            (const cExec*        ) X19 = 0x000000782D2538B0
  cc              (ADDF_EC             ) X22 = 0x0000000000000018  (24)
  pErrCodes       (char*               ) X2 = 0x000000787DFFE390
  pErrMsg         (char*               ) X20 = 0x000000787DFFE2CC
  type            (ADDF_PT             ) X4 = 0x0000000000000001  (1)
```

Note: locations are PC-accurate — parameters may have moved from their
entry-point registers (X0-X7) to callee-saved registers (X19-X28) or
stack slots by the time of the crash.

### Locals — verbose only (`-v`)

Shows local variables with register values when available:

```
--- Locals (frame #0: fPromptTestError) ---
  retState        (ADDF_EC             ) X22
  response        (int                 ) [FP-4]
```

### Disassembly — verbose only (`-v`)

Instructions around the crash address with source line annotations.
Disassembly via capstone (no external tools needed):

```
--- Disassembly (0x1098) ---
  EPSA/build/Bin/BeepCode.cpp:98
    1080: adrp  x2, #0x137000
    1084: ldr  w2, [x2, #0x30c]
    1088: cbz  w2, #0x114c
  EPSA/build/Bin/BeepCode.cpp:145
  > 1098: mov  w16, #3
    109c: mov  x13, #0x3540
```

### Source Context — verbose only (`-v`)

Source lines around the crash point (if source tree is accessible):

```
--- Source (EPSA/UI/ePrompt.cpp) ---
     292:     if (rc != ADDF_OK) {
     293:         fStatusMsg(PSA_CC_ERROR, "Test failed: %s", msg);
  >  294:         return fPromptUser(severity, msg, detail);
     295:     }
     296:     return rc;
```

Use `--source-root` to specify the local source tree.  Defaults to
auto-detection from the script's location in the repo.

## Options

| Option | Description |
|--------|-------------|
| `-o FILE` | Output file path (default: `<log>_decode.txt`) |
| `-v, --verbose` | Show disassembly, source context, and parameters |
| `-s FILE` | Additional symbol file for multi-module traces (repeatable) |
| `--base HEX` | Override image base address (hex, e.g. `5948A000`) |
| `--source-root PATH` | Local source tree root for source context |

### Multi-module traces (`-s`)

ARM64 RSODs trace through multiple modules (psa.efi, DxeCore.efi,
Shell.efi).  Provide additional symbol files to resolve frames from
other modules:

```
python3 rsod-decode.py rsod.txt af4305.efi.so -s DxeCore.debug -s Shell.debug
```

Module names are matched from the `sNN ADDR module.efi +OFFSET` lines.

### Non-default image base (MASER)

When EPSA is loaded by the MASER at a different address than the preferred
base (0x180000000 for x86), use `--base`:

```
python3 rsod-decode.py putty.txt pf4303.efi.map --base 5948A000
```

The tool automatically detects EDK2-format ImageBase lines when present.

### Call-site verification (ARM64 ELF only)

For ELF symbol files, the tool uses capstone to check if each return
address has a preceding `call`/`bl` instruction, marking frames as
`[verified]` or `[stale?]` in the backtrace.

## Supported RSOD Formats

The tool auto-detects the format:

| Format | Detected by | Architecture |
|--------|-------------|-------------|
| Dell BIOS x86 | `AX=`, `-->RIP` | x86-64 |
| Dell BIOS ARM64 | `X0=`, `-->PC`, `s00..sNN` | ARM64 |
| EDK2 x64 | `!!!! X64 Exception`, `RIP  -` | x86-64 |

## Requirements

- Python 3.10+
- Python packages (install via pip):

```
pip install -r requirements.txt
```

Required packages:

| Package | Purpose |
|---------|---------|
| `pyelftools` | ELF/DWARF parsing (symbols, source lines, inlines, params) |
| `capstone` | Disassembly (ARM64 and x86-64, verbose mode) |
| `cxxfilt` | C++ name demangling |

No external binutils tools (nm, addr2line, objdump) are needed.

## Symbol File Formats

| Source | Format | Functions | Source lines | Inlines | Parameters | Locals |
|--------|--------|-----------|-------------|---------|-----------|--------|
| MSVC `.map` | Text | Yes | No | No | No | No |
| GCC `.so`/`.efi` | ELF+DWARF | Yes (demangled) | Yes | Yes | Real names + types | Yes |

The tool auto-detects the format by checking for ELF magic bytes.
