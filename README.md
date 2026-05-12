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

## Platform support

| Platform | Source install | `rsod.pyzw` zipapp |
|----------|---------------|---------------------|
| **Linux x86-64** (Fedora/RHEL/Ubuntu) | ✓ supported, primary dev target | ✓ `libcapstone.so` is bundled for Linux x86-64 |
| **Linux ARM64** | ✓ should work | ✗ rebuild `rsod.pyzw` on an ARM64 host |
| **macOS** (Intel + Apple Silicon) | ✓ should work (untested) — capstone has macOS wheels | ✗ rebuild on macOS for native `libcapstone.dylib` |
| **Windows native** | likely works for `decode` and `serve`, but the system-LLDB integration is Linux-tested | ✗ rebuild on Windows for `capstone.dll` |
| **Windows + WSL** | ✓ same story as Linux | ✓ same as Linux x86-64 |

The host architecture you're analyzing crashes on doesn't matter — the
tool reads x86-64 and ARM64 RSODs from any host.

System **LLDB** is optional but unlocks PE+PDB minidump analysis and
callsite-arg reconstruction. It's auto-detected from the system Python
site-packages on Fedora/RHEL/Ubuntu; install it via your package manager
(see [Optional: system LLDB](#optional-system-lldb) below).

## Install

You have two paths. **Pick one.**

### A. From source (developers, or the only option on most platforms today)

```bash
git clone git@github.com:aximcode/rsod-decode.git
cd rsod-decode

# Recommended: a venv so you don't pollute system Python
python3 -m venv .venv
source .venv/bin/activate     # on Windows: .venv\Scripts\activate

# Editable install + the optional GDB backend + dev tools
pip install -e ".[gdb,dev]"

# (Optional) build the React frontend if you want the web UI
cd frontend && npm install && npm run build && cd ..

rsod --help
```

`pip install -e` puts the `rsod` console script on your `PATH` and
points it at the source tree, so edits take effect immediately.

Extras you can pick from `[]`:

- `gdb` — adds `pygdbmi` (the GDB cross-check backend). Also requires
  `gdb` on your `PATH`.
- `dev` — adds `pytest` for running the test suite.
- `browser` — adds `playwright` for the browser regression tests.

### B. Single-file zipapp (`rsod.pyzw`)

A self-contained Python zipapp that bundles Flask, capstone, the React
frontend, and all dependencies into one ~2.6 MB file. Only requires
Python 3.11+ on the target host.

There are no published release artifacts yet, so you build it yourself:

```bash
git clone git@github.com:aximcode/rsod-decode.git
cd rsod-decode
pip install -e ".[dev]"
cd frontend && npm install && npm run build && cd ..
python build_pyz.py            # → rsod.pyzw
```

Then copy `rsod.pyzw` anywhere and run it directly:

```bash
python rsod.pyzw serve
python rsod.pyzw decode rsod.txt app.efi.so -v
python rsod.pyzw history
```

The zipapp is **architecture-specific** because `libcapstone.so` is
baked into the bundle. A Linux x86-64 `rsod.pyzw` only runs on Linux
x86-64; rebuild on each target platform.

## First-run smoke test

```bash
# Web UI — opens a browser tab on localhost:5000
rsod serve

# Pre-load a crash on startup (browser opens to the analysis view)
rsod serve rsod.txt app.efi.so

# Text report to stdout
rsod decode rsod.txt app.efi.so -v

# List sessions you've already analyzed
rsod history

# Replay a stored session
rsod decode --session ab12cd34
```

The same commands work via `python rsod.pyzw <subcommand>` if you
went the zipapp route.

## Optional: system LLDB

LLDB unlocks PE+PDB minidump analysis (the only way to get full
parameter/local visibility for MSVC EPSA crashes) and callsite-arg
reconstruction (recovers tail-call-elided frames). The tool falls
back cleanly to pyelftools if LLDB isn't installed.

| Distro | Install |
|--------|---------|
| Fedora / RHEL | `sudo dnf install lldb python3-lldb` |
| Ubuntu / Debian | `sudo apt install lldb python3-lldb` |
| macOS | ships with Xcode Command Line Tools (`xcode-select --install`) |
| Windows | install LLVM from [llvm.org](https://llvm.org/) |

`rsod_decode/lldb_loader.py` finds the system lldb Python module
without needing a `--system-site-packages` venv.

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
