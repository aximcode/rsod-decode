# rsod-decode — UEFI RSOD Stack Dump Decoder

Resolves raw addresses in UEFI RSOD (Red Screen of Death) stack dumps to
function names, source files, and line numbers.  Works with any UEFI
application crash on x86-64 or ARM64.

## Quick Start

```
rsod-decode <rsod-log> <symbol-file> [-o output] [-v] [--base HEX]
```

**x86-64 example** (MSVC `.map` file):
```
rsod-decode putty.txt app.efi.map
```

**ARM64 example** (GCC `.so` file with debug symbols):
```
rsod-decode rsod.txt app.efi.so
```

**ARM64 verbose** (adds disassembly, source context, parameters):
```
rsod-decode rsod.txt app.efi.so -v
```

**With git-pinned source** (reads source at a specific tag or commit):
```
rsod-decode rsod.txt app.efi.so -v --tag v1.0.3
rsod-decode rsod.txt app.efi.so -v --commit 6f3b70ec
```

Output is written to `<log>_decode.txt` by default (override with `-o`).

## Symbol Files

The tool accepts two types of symbol files:

### MSVC linker map files (x86-64)

Produced by the MSVC linker with `/MAP` flag.  Contains function names
and object files but no source line numbers.

### GCC ELF shared objects (ARM64)

The `.so` file produced before `objcopy` strips it to a `.efi`.  Contains
full DWARF debug symbols, enabling function names, source file:line
resolution, inline expansion, parameter names, and local variables.

Note: The `.efi` produced by `objcopy` is typically **stripped** — always
use the `.so` (or unstripped `.efi`) for decoding.

## Capturing an RSOD

Connect to the server's BMC/iDRAC via SSH, then use the serial console:

```
racadm>> console com2
```

When the RSOD appears, copy the full text from PuTTY (or save the PuTTY
session log).  The capture should include the register dump and stack dump.

## Output Structure

The output has three sections: crash summary, annotated RSOD, and backtrace.
Verbose mode (`-v`) adds four more sections for frame #0: parameters,
locals, disassembly, and source context.

### Crash Summary (always shown)

```
--- Crash Summary ---
Exception: Synchronous exceptions, Syndrome:Data abort
Crash PC:  0x78330E42B0 [not in image]
Image:     app (base 0x0)
Source:    6f3b70ecc (Release build v1.0.3)
ESR:       0x96000007 -- EC=0x25 Data Abort (same EL), IL=1, ISS=0x0000007
           Translation fault L3
FAR:       0x0000000000000000 -- NULL pointer dereference
```

For ARM64, the ESR register is decoded to show the exception class (Data
Abort, Instruction Abort, PC Alignment Fault, etc.) and for data aborts
the fault type (translation fault, permission fault, etc.).

### Annotated RSOD (always shown)

The original RSOD text with symbol annotations appended to each resolvable
address.

### Clean Backtrace (always shown)

A gdb-style numbered backtrace with function names, source locations, and
inline expansion (ARM64 with DWARF):

```
--- Backtrace ---
#0   0x1098 in MyClass::MyMethod(int) at src/module.cpp:145 [app.efi]
#1   0x321C in DrawFrame() at src/ui/draw.hpp:221 [app.efi]
      (inlined) DrawFrame() at src/ui/draw.cpp:528
#4   0x62FC in HandleError(ErrorCode, char*, char*) at src/error.cpp:294 [app.efi]
```

### Parameters — verbose only (`-v`)

Shows real parameter names and types from DWARF debug info, with
PC-accurate register/stack location tracking:

```
--- Parameters (frame #0: HandleError) ---
  this            (const MyClass*      ) X19 = 0x000000782D2538B0
  code            (ErrorCode           ) X22 = 0x0000000000000018  (24)
  msg             (char*               ) X2 = 0x000000787DFFE390
  detail          (char*               ) X20 = 0x000000787DFFE2CC
```

Note: locations are PC-accurate — parameters may have moved from their
entry-point registers (X0-X7) to callee-saved registers (X19-X28) or
stack slots by the time of the crash.

### Locals — verbose only (`-v`)

Shows local variables with register values when available:

```
--- Locals (frame #0: HandleError) ---
  retState        (int                 ) X22
  response        (int                 ) [FP-4]
```

### Disassembly — verbose only (`-v`)

Instructions around the crash address with source line annotations.
Disassembly via capstone (no external tools needed):

```
--- Disassembly (0x1098) ---
  src/module.cpp:98
    1080: adrp  x2, #0x137000
    1084: ldr  w2, [x2, #0x30c]
    1088: cbz  w2, #0x114c
  src/module.cpp:145
  > 1098: mov  w16, #3
    109c: mov  x13, #0x3540
```

### Source Context — verbose only (`-v`)

Source lines around the crash point (if source tree is accessible or
`--tag`/`--commit` is provided):

```
--- Source (src/error.cpp @ 6f3b70ecc) ---
     292:     if (rc != OK) {
     293:         LogError("Failed: %s", msg);
  >  294:         return PromptUser(severity, msg, detail);
     295:     }
     296:     return rc;
```

Use `--source-root` to specify the local source tree, or `--tag`/`--commit`
to read source from a specific git revision.

## Options

| Option | Description |
|--------|-------------|
| `-o FILE` | Output file path (default: `<log>_decode.txt`) |
| `-v, --verbose` | Show disassembly, source context, and parameters |
| `-s FILE` | Additional symbol file for multi-module traces (repeatable) |
| `--base HEX` | Override image base address (hex, e.g. `5948A000`) |
| `--source-root PATH` | Local source tree root for source context |
| `--tag TAG` | Git tag for source context (reads source at that revision) |
| `--commit HASH` | Git commit hash for source context |

### Multi-module traces (`-s`)

ARM64 RSODs trace through multiple modules (app.efi, DxeCore.efi,
Shell.efi).  Provide additional symbol files to resolve frames from
other modules:

```
rsod-decode rsod.txt app.efi.so -s DxeCore.debug -s Shell.debug
```

Module names are matched from the `sNN ADDR module.efi +OFFSET` lines.

### Non-default image base

When a UEFI application is loaded at a different address than the preferred
base (e.g., 0x180000000 for x86), use `--base`:

```
rsod-decode putty.txt app.efi.map --base 5948A000
```

The tool automatically detects EDK2-format ImageBase lines when present.

### Git-pinned source context (`--tag` / `--commit`)

By default, source context reads from the working tree.  Use `--tag` or
`--commit` to read source at a specific git revision — useful when the
working tree doesn't match the build that produced the crash:

```
rsod-decode rsod.txt app.efi.so -v --tag v1.0.3
rsod-decode rsod.txt app.efi.so -v --commit abc1234
```

The resolved commit is shown in the crash summary and source headers.

### Call-site verification (ARM64 ELF only)

For ELF symbol files, the tool uses capstone to check if each return
address has a preceding `call`/`bl` instruction, marking frames as
`[verified]` or `[stale?]` in the backtrace.

## Supported RSOD Formats

The tool auto-detects the format:

| Format | Detected by | Architecture |
|--------|-------------|-------------|
| UEFI BIOS x86 | `AX=`, `-->RIP` | x86-64 |
| UEFI BIOS ARM64 | `X0=`, `-->PC`, `s00..sNN` | ARM64 |
| EDK2 x64 | `!!!! X64 Exception`, `RIP  -` | x86-64 |

## Requirements

Python 3.10+ with pip packages listed in `requirements.txt`:

```
pip install -r requirements.txt
```

| Package | Version | Purpose |
|---------|---------|---------|
| `pyelftools` | >= 0.30 | ELF symbol tables and DWARF debug info |
| `capstone` | >= 5.0 | ARM64 and x86-64 disassembly |
| `cxxfilt` | >= 0.3 | C++ name demangling |

No external command-line tools (nm, addr2line, objdump) are needed.

Optional for `--tag`/`--commit`: `git` must be in PATH.

## Symbol File Formats

| Source | Format | Functions | Source lines | Inlines | Param names | Locals | Object files |
|--------|--------|-----------|-------------|---------|------------|--------|-------------|
| MSVC `.map` | Text | Yes | No | No | No | No | Yes |
| GCC `.so`/`.efi` | ELF+DWARF | Yes (demangled) | Yes | Yes | Real DWARF names | Yes | No |

The tool auto-detects the format by checking for ELF magic bytes.
