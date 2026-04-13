# PSA x86-64 regression fixture

Real Dell EPSA (PSA) crash captured from a PowerEdge R470 BIOS 1.1.3.

## Files

- `rsod_psa_x64.txt` — serial console capture containing the RSOD text
  (Invalid opcode crash at `0x1001696` inside `fGndBounce+0x96`).
- `psa_x64.map` — MSVC linker map file for `psa.efi`. Preferred base
  `0x180000000`, ~14929 symbols.
- `psa_x64.efi` — PE32+ AMD64 UEFI application built by MSVC. Source
  of `.text` bytes for capstone-driven disassembly and call-site
  verification in the `.map`-backed path (no DWARF, no source lines).

## How to refresh

1. Build EPSA x86-64 from `~/work/dell/delldiags/source/src/EPSA` and
   grab the resulting `psa.efi` and its map file.
2. Capture an RSOD through the serial console during a crash.
3. Replace these three files, keeping the same filenames. Adjust the
   pinned expected metrics in `tests/_datasets.py`'s `psa_x64` entry.

## Why they're committed as-is

The regression tests pin frame counts / call-site hit counts against a
specific build of `psa.efi`. Pointing tests at an out-of-tree build tree
would make every fresh clone skip these tests, hiding regressions. The
~3.7 MB cost to the repo buys deterministic CI coverage of the MSVC
workflow.
