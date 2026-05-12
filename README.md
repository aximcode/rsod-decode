# rsod-decode

Interactive UEFI **R**ed **S**creen **O**f **D**eath crash dump
debugger. Resolves raw addresses in serial-console crash captures
to function names, source files, parameters, and locals via DWARF
or PE+PDB. Ships as a single `rsod` binary with `decode` (text
report), `serve` (web UI), and `history` subcommands, plus a
self-contained `rsod.pyzw` zipapp.

Supports x86-64 and ARM64; auto-detects EDK2 ARM64, Dell UEFI
ARM64, Dell UEFI x86-64, and MSVC EPSA x86-64 (with or without
PDB) formats.

---

## At a glance

Drop an RSOD log + symbol files, get a clickable backtrace,
per-frame parameters/locals, full-file source view, disassembly
with inline source annotations, and an in-browser LLDB/GDB
terminal. Sessions persist across restarts, dedup by content
hash, and export as `.rsod.zip` bundles for cross-team sharing.

![Demo: upload screen → crash analysis → source tab → disassembly tab](docs/screenshots/demo.gif)

---

## Install

> **Most users:** grab the pre-built zipapp on Linux x86-64 (including
> WSL on Windows 11). It's the recommended path for everyone — full
> features, including LLDB integration. No pip, no venv, no Node, no
> build step.

### Recommended: pre-built `rsod.pyzw` (Linux x86-64 / WSL)

```bash
# 1. Install Python + LLDB (one-time, host system)
sudo apt install python3 python3-lldb lldb gdb            # Ubuntu / Debian / WSL
# sudo dnf install python3 python3-lldb lldb gdb          # Fedora / RHEL

# 2. Download the zipapp
#    The -o flag prevents wget/curl from auto-renaming to
#    rsod.pyzw.1 / .2 / etc. when an older copy is in cwd.
curl -L -o rsod.pyzw https://github.com/aximcode/rsod-decode/releases/latest/download/rsod.pyzw
chmod +x rsod.pyzw

# 3. Run it
./rsod.pyzw serve                       # web UI at localhost:5000
./rsod.pyzw decode rsod.txt symbols.so -v
./rsod.pyzw history
```

Requires Python 3.11+. The zipapp bundles Flask, capstone, the React
frontend, and every Python dependency — only the LLDB and GDB
binaries come from your system packages.

`python3-lldb` + `lldb` give you PE+PDB minidump analysis (the only
way to get full parameter/local visibility for MSVC EPSA crashes)
and callsite-arg reconstruction (recovers tail-call-elided frames).
`gdb` enables the GDB cross-check backend. Both are optional — the
tool degrades to the pyelftools backend if either is missing — but
strongly recommended for the full experience.

### Other platforms (macOS, Windows native, Linux ARM64)

The released `rsod.pyzw` is Linux x86-64 only because `libcapstone.so`
is baked into the bundle. To use rsod-decode on another platform, do
the source install below on the target host (works fine — capstone
has wheels for macOS, Windows, and Linux ARM64) and either run from
source or rebuild the zipapp via `python build_pyz.py`.

### Source install (developers + non-Linux-x86 hosts)

```bash
git clone https://github.com/aximcode/rsod-decode.git
cd rsod-decode
```

Prerequisites by platform:

| Platform | Run before `pip install` |
|----------|--------------------------|
| Ubuntu / Debian / WSL | `sudo apt install python3-pip python3-venv python3-lldb lldb gdb` |
| Fedora / RHEL | `sudo dnf install python3-pip python3-lldb lldb gdb` |
| macOS | `brew install python lldb gdb` |
| Windows | install Python from [python.org](https://python.org) + LLVM from [llvm.org](https://llvm.org/) |

A **venv is required** on modern Ubuntu / Debian (PEP 668 blocks
system-wide `pip install`). Strongly recommended elsewhere too.

```bash
python3 -m venv .venv
source .venv/bin/activate     # on Windows: .venv\Scripts\activate

pip install -e ".[gdb,dev]"
cd frontend && npm install && npm run build && cd ..

rsod --help
# Or rebuild the zipapp for distribution:
python build_pyz.py            # → rsod.pyzw
```

Optional extras: `[gdb]` adds `pygdbmi`, `[dev]` adds `pytest`,
`[browser]` adds `playwright` for the browser regression tests.

---

## Web UI (`rsod serve`)

Starts a local Flask server, opens your default browser, and lets
you drop any combination of RSOD log + symbol files in one action.

```bash
rsod serve                                 # upload form at localhost:5000
rsod serve rsod.txt app.efi.so             # pre-load a session on startup
rsod serve rsod.txt app.efi -s app.pdb     # MSVC PE+PDB crash
rsod serve --port 9090 --no-browser        # custom port, skip browser open
rsod serve --source-path ~/src/myproject   # extra source tree for source view
```

### Features

- **Clickable backtrace** with call-verification markers
  (`[verified]` / `[stale?]`) and inline expansion
- **Per-frame parameters and locals** with PC-accurate register/
  stack location tracking; struct/pointer fields are expandable
- **Memory hex-dump viewer** with region labels (stack, .text, etc.)
- **Disassembly** around the faulting PC with source-line headers
- **Full-file source view** that auto-scrolls to the crash line;
  scroll freely, use **"Go to line N"** to reset
- **Register panel** with symbol annotations and crash-vs-CFI-unwound
  highlighting
- **Three DWARF backends** — pyelftools (always), GDB/MI, system
  LLDB (richer; PE+PDB minidumps + callsite-arg reconstruction)
- **In-browser LLDB and GDB terminals** sharing the session's
  debugger state
- **Expression evaluation** via the LLDB/GDB backends
- **Persistent session history** (see below)

### Persistent session store

Uploaded sessions survive `rsod serve` restarts. Every upload writes
to a SQLite store at `~/.rsod-debug/sessions.db` plus a per-session
files directory under `~/.rsod-debug/files/<id>/`. The upload page
shows a "Recent sessions" list below the upload zone — click any row
to reopen the crash.

Session IDs are 16-char sha256 prefixes over the input bytes, so
re-uploading identical content deduplicates and Alice's id matches
Bob's id for the same crash. **Sessions are never auto-deleted**;
the only way to remove one is the explicit Delete button (in the
crash banner or per-row in history).

Override the data directory with `RSOD_DATA_DIR=...` for CI or
project-isolated history.

### Cross-machine sharing — export / import bundles

Click **Export** in the crash banner (or on a history row) to
download an `.rsod.zip` bundle:

```
crash-2026-04-15-ab12cd34.rsod.zip
```

The bundle contains the original RSOD text, the symbol files, and
a small `metadata.json` manifest. Send it to a teammate; they click
**Import bundle** on their upload page and drop straight into the
imported session — no out-of-band symbol file transfer needed.

Because session IDs are content hashes, the imported session lands
on the same `ab12cd34` id Alice's machine has. A
`#session/ab12cd34` permalink resolves to the same crash on any
install that has imported the bundle.

### Friendly session names

Click the session name above the crash banner (or the **Name**
button if unnamed) to set a friendly alias visible in history and
the banner. Useful for "R470 fGndBounce" vs `ae035623cff5c98a`.

---

## CLI (`rsod decode`)

Text report for a single crash. Default output is
`<log>_decode.txt` (override with `-o`); `--session` writes to
stdout.

```bash
# From files (also persists to history)
rsod decode rsod.txt app.efi.so
rsod decode rsod.txt app.efi.so -v                  # adds params/locals/disasm/source
rsod decode rsod.txt app.efi.so --tag v1.0.3        # source from a git ref
rsod decode rsod.txt app.efi.so --base 5948A000     # base address override
rsod decode rsod.txt app.efi.so --name "R470 crash" # friendly name in history

# From a previously persisted session
rsod decode --session ae035623                      # 8-char prefix is enough
rsod decode --session ae035623 -v                   # with params/disasm/source
```

### `rsod history`

Compact table of all persisted sessions, newest first:

```
ID          NAME                  IMAGE           EXCEPTION                 SYMBOL             FR   AGE
-------------------------------------------------------------------------------------------------------
ae035623    PSA forcecrash XE77…  psa_x64         General Protection Faul…  trigger_gp_fault    8    1m
b676f92c    PSA R470 fGndBounce   psa_x64         Invalid opcode (06)       not in image       14    1m
5d5e566f    Dell x64 CrashTest    CrashTest       General Protection Faul…  not in image        6    1m
```

`--json` for machine-readable output. `-n N` to limit row count.

### Options

| Option | Description |
|--------|-------------|
| `-o FILE` | Output file path (default: `<log>_decode.txt`, stdout for `--session`) |
| `-v, --verbose` | Show disassembly, source context, and parameters |
| `-s FILE` | Additional symbol file for multi-module traces (repeatable) |
| `--base HEX` | Override image base address (hex, e.g. `5948A000`) |
| `--source-path PATH` | Source tree to search (repeatable; auto-detected repo is fallback) |
| `--tag TAG` | Git tag for source context (reads source at that revision) |
| `--commit HASH` | Git commit hash for source context |
| `--session ID` | Replay a persisted session by id (full or 4+ char prefix) |
| `--name TEXT` | Friendly display name for the session (visible in history) |
| `--backend NAME` | Force a DWARF backend (`auto`, `lldb`, `gdb`, `pyelftools`) |

---

## Capturing an RSOD

Connect to the server's BMC/iDRAC via SSH, then use the serial
console:

```
racadm>> console com2
```

When the RSOD appears, copy the full text from PuTTY (or save the
PuTTY session log). The capture should include the register dump
and stack dump.

---

## Symbol files

| Source | Format | Functions | Source lines | Inlines | Param names | Locals |
|--------|--------|-----------|-------------|---------|------------|--------|
| MSVC `.map` | Text | yes | no | no | no | no |
| MSVC `.efi` + `.pdb` | PE + PDB (LLDB) | yes | yes | yes | yes | yes |
| GCC `.so` / unstripped `.efi` | ELF + DWARF | yes (demangled) | yes | yes | yes | yes |

The tool auto-detects format by magic bytes. The `.efi` produced by
`objcopy` is typically **stripped** — use the `.so` (or unstripped
`.efi`) for ELF builds.

For MSVC builds, drop the `.efi` + `.pdb` together for full
parameter/local visibility; the PDB drives an LLDB minidump session
behind the scenes.

---

## Supported RSOD formats

| Format | Detected by | Architecture |
|--------|-------------|--------------|
| UEFI BIOS x86 | `AX=`, `-->RIP` | x86-64 |
| UEFI BIOS ARM64 | `X0=`, `-->PC`, `s00..sNN` | ARM64 |
| EDK2 ARM64 | `Synchronous Exception`, `X0` | ARM64 |
| EDK2 x64 | `!!!! X64 Exception`, `RIP  -` | x86-64 |

---

## Dependencies

Python 3.11+. Pulled in automatically by `pip install -e .`:

| Package | Purpose | Pulled by |
|---------|---------|-----------|
| `pyelftools` | ELF + DWARF baseline | base |
| `capstone` | x86-64 / ARM64 disassembly | base |
| `cxxfilt` | C++ name demangling | base |
| `pefile` | PE binary parsing | base |
| `flask` + `flask-sock` + `simple-websocket` | web UI + WS terminals | base |
| `pygdbmi` | GDB/MI cross-check backend | `[gdb]` extra |
| `pytest` | test suite | `[dev]` extra |
| `playwright` | browser regression tests | `[browser]` extra |

External commands: `gdb` if you use `--backend gdb`; `git` if you use
`--tag`/`--commit` for source context; `node` + `npm` if you build the
React frontend yourself.

For the Playwright browser tests:

```bash
pip install -e ".[browser]"
python -m playwright install chromium
```

## Running the tests

```bash
pytest -q                # ~160 tests, ~30 seconds
pytest -m parser         # parser-only (fastest subset, no Flask)
pytest -m api            # Flask API
pytest -m lldb           # only the LLDB-gated tests (skipped if no LLDB)
```

---

## Architecture

See [DESIGN.md](DESIGN.md) for the full backend architecture
(SQLite session store, ingest pipeline, three DWARF backends,
schema migrations, frontend persistence contract, etc.).
