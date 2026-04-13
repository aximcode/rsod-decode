# PSA x86-64 forcecrash fixture (ground-truth)

Synthetic-but-real crash fixture built from the Dell EPSA `4303.56` release
tag, captured on a PowerEdge XE7745 running BIOS 1.3.3. Unlike the sibling
`psa/` fixture (real production R470 crash in `fGndBounce`), this one is
**deterministic** — the exact faulting function, register contents, stack
struct values, and call chain are known ahead of time and can be used as
assertion ground-truth for the decoder.

## Files

- `rsod_psa_x64.txt` — iDRAC `console com2` serial capture of the Dell BIOS
  exception dump. 49 KB. #GP at `trigger_gp_fault + 2`.
- `psa_x64.efi` — MSVC-linked PE32+ AMD64 UEFI application, 1,995,008 bytes.
  Contains the `-forcecrash` hook; everything else is stock `4303.56`.
- `psa_x64.map` — MSVC linker map file, 1.5 MB.
- `psa_x64.pdb` — MSVC CodeView debug database, 10.3 MB, **gitignored**
  (see root `.gitignore`). Matches `psa_x64.efi` by CodeView RSDS GUID
  `{9C1E90EB-5ECA-40CB-9B31-CFAFFB2960AA}` Age 3. Regenerate via the build
  procedure below if the file is missing.

## What the crash looks like

- **Exception**: General Protection Fault (#13)
- **RIP**: `0x18000618A` → `trigger_gp_fault + 2`
- **Image base**: `0x180000000` (matches the linker's `/BASE` default for
  X64 ROM=NO, so no relocation — runtime addresses == map RVAs)
- **LBR**: `0x180005AF5 → 0x180006188` (dispatch_crash → trigger_gp_fault)
- **Stack top**: RSP = `0x25FFF108`, first slot holds `0x180006144`
  (`initialize_test + 0x44`)

## Expected call chain and the tail-call caveat

Source-level chain is 8 frames deep:
```
fUEFIPSAEntry
  -> fForceCrashIfRequested
    -> run_crashtest
      -> initialize_test
        -> prepare_crash_context
          -> validate_environment
            -> dispatch_crash
              -> trigger_gp_fault       ← faulting RIP
```

MSVC tail-call-optimized `prepare_crash_context`, `validate_environment`, and
`dispatch_crash` (each just forwards to the next and returns), collapsing
them into `jmp` instructions. The decoder will therefore see **fewer real
stack frames than function calls**. Expected real frames:

1. `trigger_gp_fault` (no own frame — tiny leaf, 16 bytes)
2. `initialize_test` (owns `CrashContext ctx` local → can't tail-call)
3. `fForceCrashIfRequested`
4. `fUEFIPSAEntry`
5. Whatever launched `psa.efi` from the UEFI shell

`initialize_test` survives as a real frame specifically because it holds
`CrashContext ctx` on its stack and passes a pointer to `prepare_crash_context`
— the local must outlive the inner call, so MSVC refuses to tail-call.

## Ground-truth values on the stack

The `CrashContext` and `CrashTestConfig` structs are allocated on
`initialize_test`'s stack frame. The decoder should be able to read these
values by either:

1. Following the `CrashContext *` parameter pointer (held in a register or
   spilled slot at the crash site), or
2. Scanning the raw stack dump for the magic values.

| Offset (from RSP) | Value | Semantic |
|---|---|---|
| `+0x00` | `0x180006144` | return addr → `initialize_test + 0x44` |
| `+0x60` | `0x180005C59` | return addr → `fForceCrashIfRequested` |
| `+0xD0` | `0x18000602F` | return addr → `fForceCrashIfRequested` or `initialize_test` |
| `+0x90` | `0x0000123400000003` | `config.flags=0x1234`, `config.version=3` |
| `+0x98` | `0xDEAD0000CAFE0000` | `config.session_id` |
| `+0xA0` | `0x0000006400000001` | `config.origin.x=100 (0x64)`, `config.mode=1` (CRASH_MODE_GP) |
| `+0xA8` | `0x00000000000000C8` | `config.origin.y=200 (0xC8)` |
| `+0x38` | `0x0052BABE00000000` | partial `ctx.cookie = session_id ^ 0xDEFFBABECAFE0000` |

`ctx.tag` points to the string `"crashtest-v3"` in rdata.
`ctx.depth` is `1` and `ctx.attempts[1]` was set to `1` inside
`validate_environment` before the tail-called chain continued.

These values come directly from the source in
`delldiags/source/src/EPSA/Libs/PsaLib/EFI/PsaEntry.c`:
```c
ctx.config = config;
ctx.depth = 1;
ctx.cookie = config->session_id ^ 0xDEFFBABECAFE0000ULL;
ctx.tag = "crashtest-v3";
ctx.attempts[0] = 0;
// ...
config.session_id = 0xDEAD0000CAFE0000ULL;
config.origin.x = 100;
config.origin.y = 200;
config.mode = CRASH_MODE_GP; // 1
```

## Crash-hook source locations

Map-file RVAs for the hook functions (all in `PsaEntry.obj`):

| RVA | Function | Notes |
|---|---|---|
| `0x5a44` | `dispatch_crash` | Real frame; calls printf/Stall then switches to trigger |
| `0x5afc` | `fForceCrashIfRequested` | Real frame |
| `0x6100` | `initialize_test` | Real frame (owns `CrashContext ctx`) |
| `0x614c` | `prepare_crash_context` | Tail-called, 8 bytes |
| `0x6154` | `run_crashtest` | Tail-called, 28 bytes |
| `0x6170` | `trigger_divide_error` | `volatile int r = 1/0;` |
| `0x6188` | `trigger_gp_fault` | Store to non-canonical addr `0xDEAD0000DEAD0000` |
| `0x6198` | `trigger_invalid_opcode` | Call non-canonical fn pointer |
| `0x61a8` | `trigger_page_fault` | Store to NULL |
| `0x61b8` | `validate_environment` | Tail-called |

## How to regenerate

This fixture was built by:

1. Checking out `4303.56` tag on a laptop with MSVC + Dell build env
2. Applying three patches to the delldiags tree (keep files uncommitted):
   - `source/src/EPSA/MakeFile`: add `SYMBOLS = NO` default, `CMDSYMBOLS`
     macro, pass `$(CMDSYMBOLS)` to both `make_a_mod` and `link.mak` sub-nmakes.
   - `source/src/EPSA/Include.mak` (X64 section, after `CPPFLAGSONLY`):
     ```
     !if "$(SYMBOLS)" == "YES"
     CFLAGSONLY   = $(CFLAGSONLY) -Z7
     CPPFLAGSONLY = $(CPPFLAGSONLY) -Z7
     !endif
     ```
   - `source/src/EPSA/Bin/Link.mak` (after `!include` line): add `LDBG`
     macro `= /DEBUG /PDB:psa.pdb /OPT:REF /OPT:ICF`, append `$(LDBG)` to
     both X64 `@echo ... >response.lnk` lines.
3. Adding the `-forcecrash` hook (full code, not a stub) inline into
   `source/src/EPSA/Libs/PsaLib/EFI/PsaEntry.c`. The hook is adapted from
   `~/projects/aximcode/uefi-devkit/crashtest/crashtest.c` — see that file
   for the canonical version. Dropped directly into `PsaEntry.c` (not a
   separate .c) to avoid touching the PsaLib nmake rules.
4. Running, in a fresh cmd.exe:
   ```
   cd C:\tc3\delldiags\source\src\EPSA
   call ..\ADDF\vsToRun.bat
   make -a RELEASE=YES TXT_GUI=YES PEG_GUI=YES NUMA=NO ROM=NO PSA_FULL=YES PSA_ESG=YES X64=YES EFI=YES SYMBOLS=YES
   ```
   This matches the Jenkins `pf4303.efi` release command exactly, with
   `SYMBOLS=YES` added. `mk.bat` was **not** used — it mangles `=` in
   command-line args (cmd.exe batch arg tokenizer eats `=`) and also
   prompts interactively for a version string when it sees `-release`.
5. Output `bin\psa.efi` + `bin\psa.map` + `bin\psa.pdb` are the .efi/.map/.pdb
   in this directory (with names stripped of the `bin\` prefix and renamed
   to the `psa_x64.*` convention).
6. Capturing the RSOD: mount a FAT32 image containing `psa_x64.efi` via
   iDRAC virtual media on an XE7745, start `racadm console com2` in a
   separate shell piped through `tee rsod.txt`, then run
   `fs#:\x64\psa.efi -forcecrash gp` from the UEFI shell. The server
   faults, Dell BIOS dumps the exception state to COM2, and the pipe
   captures it.

## Why `/OPT:REF /OPT:ICF` matter in the link line

Adding `/DEBUG` to the MSVC linker line silently flips the `/OPT` defaults
from `REF/ICF` to `NOREF/NOICF` to preserve symbols for debugging. On this
codebase that bloats `.text` by 549 KB, `.rdata` by 182 KB, and `.data`
by 97 KB — the shipped `.efi` grows from ~2 MB to ~2.85 MB. Passing
`/OPT:REF /OPT:ICF` explicitly restores the dead-code elimination and
COMDAT folding, and the resulting `.efi` is actually 12 KB **smaller**
than the Jenkins `pf4303.efi` (because our link is a fresh build vs
Jenkins' older ICF decisions). The user's release size constraint is
satisfied.

## What the decoder should extract from this fixture

If the decoder is correct, loading `psa_x64.efi` + `psa_x64.map` (or
`psa_x64.pdb` when PDB support is added) with `rsod_psa_x64.txt` should
produce:

- `crash.rip` → resolves to `trigger_gp_fault + 2`
- `crash.exception` → "General Protection Fault"
- `crash.image_base` → `0x180000000`
- At least 3 walked frames with symbols:
  `trigger_gp_fault`, `initialize_test`, `fForceCrashIfRequested`
- LBR one-frame hint: `dispatch_crash` (from `0x180005AF5`)
- If variable inspection is enabled (PDB backend): `CrashContext.cookie`,
  `CrashTestConfig.session_id = 0xDEAD0000CAFE0000`, `origin.x = 100`,
  `origin.y = 200`, `mode = CRASH_MODE_GP`, `flags = 0x1234`

## Tag reference in delldiags

The source for this fixture lives at git tag `4303.56` in
`~/work/dell/delldiags`. The patches are not committed — they live only
on a detached-HEAD checkout on the build laptop. To rebuild from scratch
later, re-apply the patches and repeat the build procedure above.
