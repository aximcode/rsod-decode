
# RSOD Debugger — Design Document

## Overview

An interactive post-mortem crash debugger for UEFI RSOD (Red Screen
of Death) dumps.  Provides a GDB-like inspection experience through a web
UI that runs locally as a desktop application.

The user pastes or uploads an RSOD capture and a symbol file, and gets an
interactive analysis: clickable backtrace, per-frame parameter/local
inspection, disassembly, source context, and a full register view — all
in a navigable interface instead of a flat text file.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  Browser tab at http://localhost:PORT                 │
│  (stdlib webbrowser.open — no native window)          │
│                                                      │
│  ┌────────────────────────────────────────────────┐  │
│  │  React + TypeScript + Tailwind SPA             │  │
│  │                                                │  │
│  │  ┌─────────┐ ┌──────────────┐ ┌────────────┐  │  │
│  │  │Backtrace│ │ Detail Panel │ │ Registers  │  │  │
│  │  │ (left)  │ │  (center)    │ │  (right)   │  │  │
│  │  │         │ │ Params       │ │            │  │  │
│  │  │  #0 ▶   │ │ Locals       │ │ X0=...     │  │  │
│  │  │  #1     │ │ Disassembly  │ │ X1=...     │  │  │
│  │  │  #2     │ │ Source       │ │ ...        │  │  │
│  │  └─────────┘ └──────────────┘ └────────────┘  │  │
│  │                                                │  │
│  │  ┌────────────────────────────────────────────┐│  │
│  │  │ Raw RSOD (collapsible bottom)              ││  │
│  │  └────────────────────────────────────────────┘│  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
         │ HTTP (localhost)
         ▼
┌──────────────────────────────────────────────────────┐
│  Flask Backend (background thread)                    │
│                                                      │
│  /api/session          POST upload RSOD + symbols    │
│  /api/session/<id>     GET  crash summary + frames   │
│  /api/frame/<id>/<n>   GET  params, locals, disasm   │
│  /api/expand/<id>/<n>  GET  struct/array field walk  │
│  /api/eval/<id>/<n>    POST LLDB/GDB expression eval │
│  /api/disasm/<id>/<n>  GET  disassembly window       │
│  /api/source/<id>/<n>  GET  source file context      │
│  /api/resolve/<id>     POST resolve arbitrary addr   │
│  /api/backend/<id>     POST switch DWARF backend     │
│  /api/history          GET  list persisted sessions  │
│  /api/export/<id>      GET  download .rsod.zip bundle│
│  /api/import           POST upload a bundle          │
│  /ws/lldb/<id>         WS   LLDB terminal bridge     │
│  /ws/gdb/<id>          WS   GDB/MI terminal bridge   │
│                                                      │
│  ┌─────────────────────────────────────────────────┐ │
│  │  service.run_analysis pipeline                  │ │
│  │  decoder + dwarf_backend + lldb_backend +       │ │
│  │  gdb_backend + symbols + corefile + esr         │ │
│  └─────────────────────────────────────────────────┘ │
│                                                      │
│  SQLite session store at ~/.rsod-debug/sessions.db.  │
│  session_id is a 16-char sha256 prefix over the      │
│  input files, so re-uploads dedup and Alice/Bob      │
│  installs produce matching ids for the same crash.   │
│  In-memory _sessions dict is an LRU hot cache in     │
│  front; evicted or cross-restart sessions hydrate on │
│  demand by replaying service.run_analysis against    │
│  the files persisted under ~/.rsod-debug/files/<id>/.│
└──────────────────────────────────────────────────────┘
```

## Tech Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Backend | Flask 3.x + flask-sock | Lightweight, WebSocket support for LLDB/GDB terminals |
| Frontend | React 19 + TypeScript + Tailwind v4 | SPA for responsive frame-switching |
| Build | Vite | Fast dev server with HMR, proxy to Flask |
| Disassembly | capstone (ctypes wrapper) | Native ARM64/x86 disassembly |
| ELF/DWARF (baseline) | pyelftools | Standalone symbol + line + DIE walk |
| ELF+DWARF / PE+PDB (richer) | system LLDB via lldb_loader | Runtime var resolution, corefile unwind, minidump unwind |
| ELF+DWARF (cross-check) | GDB/MI via pygdbmi | Second opinion for CFI unwinding + expr eval |
| Demangling | cxxfilt | C++ name demangling |
| Session store | SQLite + in-memory LRU cache | Persistent history + permalinks; re-hydrates via `service.run_analysis` on restart |
| Browser launch | stdlib `webbrowser` | Default tab open — no native-window bindings |
| Distribution | stdlib zipapp (`rsod.pyzw`) | Single file; first-run extracts capstone + frontend/dist |

## Why a Web UI Instead of CLI Output

The CLI tool produces a flat text file.  The web UI provides interactive
analysis that a text file can't:

- **Click** a function in the backtrace → see its params, disassembly,
  and source side-by-side
- **Hover** any address anywhere → tooltip shows the resolved symbol
- **Search** symbols across the stack
- **Upload multiple symbol files** and see multi-module resolution
  update live
- **Save/share** analysis as a permalink or JSON export
- **Paste, upload, or drag-and-drop** — paste RSOD text directly, use a
  file picker, or drag files onto the upload zone
- **Git-pinned source** — specify a tag or commit hash to view source
  at the exact revision that produced the binary

## UI Layout

| Panel | Position | Content |
|-------|----------|---------|
| Crash Summary | Top banner | Exception type, ESR decode, PC, image — always visible |
| Backtrace | Left sidebar | Clickable frame list — click a frame to see its details |
| Detail Panel | Center | Tabs: Params, Locals, Disassembly, Source for selected frame |
| Register View | Right sidebar | Full register dump with symbol annotations, color-coded |
| Raw RSOD | Collapsible bottom | Original text with highlighted/linked addresses |
| Address Resolver | Command bar | GDB-like address/symbol lookup |

## UI Panels

### Crash Banner (top, always visible)

```
╔══════════════════════════════════════════════════════════╗
║  RSOD: Synchronous Exception — Data Abort (same EL)     ║
║  PC: 0x62FC  fHandleError  src/Platform/ErrorHandler.cpp:294  ║
║  ESR: 0x96000047  Translation fault L3  FAR: 0x0 (NULL)      ║
║  Image: firmware.efi.so  ARM64                                ║
╚══════════════════════════════════════════════════════════╝
```

### Backtrace Panel (left sidebar)

Clickable frame list.  Selected frame highlighted.  Shows symbol name,
module, and source location.  Call-verified frames marked with a check.

```
  ▶ #0  cAlertHandler::cAlertHandler  AlertHandler.cpp:145  [app.efi]
    #1  cTitleBar::Draw              TitleBar.cpp:221     [app.efi]
         ↳ (inlined)                TitleBar.cpp:528
    #2  fHandleError                 ErrorHandler.cpp:294 [app.efi]
    #3  fGetUserInput                ErrorHandler.cpp:576 [DxeCore.efi]
    #4  fRunTestSequence             TestRunner.cpp:858   [Shell.efi]
```

### Detail Panel (center, changes with selected frame)

Four tabs: **Params** | **Locals** | **Disassembly** | **Source**

**Params tab:**
```
  Name            Type                  Location   Value
  ─────────────── ───────────────────── ────────── ──────────────────
  this            const cExec*          X19        0x782D2538B0
  cc              EFI_STATUS            X22        0x18 (24)
  pErrCodes       char*                 X2         0x7DFFE390
  pErrMsg         char*                 X20        0x7DFFE2CC
  type            UINT8                 X4         0x01 (1)
```

**Locals tab:**
```
  Name            Type                  Location   Value
  ─────────────── ───────────────────── ────────── ──────────────────
  retState        EFI_STATUS            X22        0x18 (24)
  response        int                   [FP-4]     —
```

**Disassembly tab:**
```
  ErrorHandler.cpp:292
    62e0: mov    w0, #1
    62e4: str    w0, [x19, #0x1cc]
  ErrorHandler.cpp:294
    62f0: adrp   x0, #0x11f000
    62f4: ldr    x0, [x0, #0xf88]
    62f8: ldr    x0, [x0, #0x58]
  ► 62fc: cbnz   x0, #0x6244          ← crash/return here
    6300: cbz    w1, #0x6214
```

**Source tab:**
```
  290:
  291:     // If abort was not requested, prompt the user
  292:     if (rc != EFI_SUCCESS) {
  293:         ReportError(severity, "Operation failed: %s", msg);
► 294:         return PromptUser(severity, msg, detail);
  295:     }
  296:     return rc;
  297: }
```

### Register Panel (right sidebar)

Full register dump from the RSOD.  Values that resolve to symbols are
clickable links that navigate to that address in the backtrace or show
a tooltip with the symbol name.

```
  X0   0x782D2538B0  → cExec instance
  X1   0x00000018    (24)
  X2   0x7DFFE390    → pErrCodes
  X3   0x7DFFE2CC
  ...
  FP   0x7DFFE2A0
  LR   0x782B12B098  → Module.efi +0x1098
  SP   0x7DFFE2A0
  PC   0x00000001    [INVALID]
  ESR  0x8A000000    PC Alignment Fault
  FAR  0x00000001    [NULL deref]
```

### Raw RSOD Panel (bottom, collapsible)

The original RSOD text, syntax-highlighted.  Addresses are clickable —
clicking one resolves it and shows the symbol in a tooltip or navigates
to the corresponding frame.

### Address Resolver (command bar / search)

A GDB-like command input where the user can type an address and get it
resolved:

```
  > 0x180031BA1
  fMpLibRunWithJustBSP(mplib.obj) + 0x09D
```

Or type a symbol name to search:

```
  > fHandleError
  0x6120  cExec::fHandleError(EFI_STATUS, char*, char*, UINT8)
          src/Platform/ErrorHandler.cpp:294
```

## API Endpoints

### Session Management

```
POST /api/session
  Body: multipart/form-data
    rsod_log: <file>           RSOD text capture
    symbol_file: <file>        .map or .so/.efi ELF
    extra_symbols[]: <files>   Optional additional ELFs
    base: <hex>                Optional image base override
    tag: <string>              Optional git tag for source context
    commit: <string>           Optional git commit for source context
    source_root: <path>        Optional local source tree root
  Response: { session_id, crash_summary, frame_count }

GET /api/session/<id>
  Response: { crash_summary, frames[], registers{}, format }

DELETE /api/session/<id>
  Deletes session and associated files
```

### Frame Inspection

```
GET /api/frame/<session_id>/<frame_index>
  Response: {
    index, address, module, symbol, offset,
    source_loc, inlines[],
    params[]: { name, type, location, reg_name, value },
    locals[]: { name, type, location, reg_name, value }
  }
```

### Disassembly

```
GET /api/disasm/<session_id>/<frame_index>?context=24
  Response: {
    instructions[]: { address, mnemonic, op_str, is_target, source_line }
  }
```

### Source Context

```
GET /api/source/<session_id>/<frame_index>?context=5
  Response: {
    file, target_line,
    lines[]: { number, text, is_target }
  }
```

### Address Resolution

```
POST /api/resolve/<session_id>
  Body: { address: "0x180031BA1" }
  Response: { symbol, offset, source_loc, object_file }
```

### Backend Switching

```
POST /api/backend/<session_id>
  Body: { backend: "lldb" | "gdb" | "pyelftools" }
  Response: { backend: "<active>" }
```

Switches the session's DWARF backend on demand. The LLDB and GDB
backends are instantiated lazily on first switch via
`service.reinit_backend`, so the initial upload doesn't pay for
backends the user may never ask for.

### WebSocket Terminals

```
/ws/lldb/<session_id>   — in-process SBCommandInterpreter bridge
/ws/gdb/<session_id>    — pygdbmi / PTY-backed GDB terminal
```

Both multiplex an xterm.js-driven terminal tab in the UI with the
session's shared LLDB/GDB state, so the user can run ad-hoc
commands (`register read`, `expression`, etc.) without leaving the
browser.

### Session History

```
GET /api/history?limit=100&before=<iso-ts>
  Response: { sessions[]: {
    id, created_at, image_name, exception_desc,
    crash_pc, crash_symbol, frame_count, backend,
    imported_from   // provenance pointer if created via /api/import
  }}
```

Drives the history list in the upload view. Sessions are ordered
newest-first; `before` pages backward through older rows.

### Export / Import Bundles

```
GET /api/export/<id>
  Response: application/zip
  Content-Disposition: attachment; filename="crash-<date>-<short8>.rsod.zip"

POST /api/import
  Body: multipart/form-data
    file: <zip bundle produced by /api/export>
  Response: { session_id, imported_from, crash_summary, frame_count }
```

The bundle is a flat zip containing `metadata.json`, `rsod.txt`,
and every symbol file from the session's `files/<id>/` directory.
Because `session_id` is a content hash over the inputs (see
"Session Storage"), Alice's id and Bob's id for the same crash
**match across installs** — so `/api/import` typically hits the
dedup fast path and returns the same id that `#session/<id>`
links to on Alice's machine. `imported_from` records the original
id from the bundle's `metadata.json` as an audit marker ("this
row arrived via /api/import"); under content hashing the pointer
is usually tautological but is preserved for provenance UI.

Permalinks across restarts (and across installs, once a bundle is
imported) come for free: `#session/<id>` hits
`GET /api/session/<id>`, which hydrates from SQLite on cache miss
by re-running `service.run_analysis` against the persisted inputs.

## Project Structure

```
rsod-decode/
├── pyproject.toml          — Packaging, deps, pytest config
├── src/rsod_decode/
│   ├── __init__.py
│   ├── __main__.py         — `rsod decode|serve` subcommand dispatcher
│   ├── server.py           — `rsod serve` entry point (Flask launcher + pre-load)
│   ├── cli.py              — `rsod decode` entry point (text-only)
│   ├── app.py              — Flask routes — thin JSON serializer over service.py
│   ├── service.py          — Shared analysis pipeline: analyze + backend init
│   │                         + source_loc backfill + tail-call reconstruction
│   │                         + frame-level resolve_frame_vars
│   ├── session.py          — Session dataclass + from/as_analysis_context
│   ├── storage.py          — SQLite session store (schema v2, migrations)
│   ├── data_dir.py         — ~/.rsod-debug/ path + RSOD_DATA_DIR override
│   ├── pdb_routing.py      — MSVC PE / .map / .pdb companion detection
│   ├── resource_paths.py   — frontend_dist() helper (pyzw-aware)
│   ├── serializers.py      — VarInfo → dict + crash_info_to_dict
│   ├── decoder.py          — analyze_rsod pipeline + text formatters
│   ├── dwarf_backend.py    — DwarfInfo class (pyelftools + capstone)
│   ├── pe_backend.py       — PEBinary class (pefile + capstone)
│   ├── gdb_backend.py      — GDB/MI DWARF backend (ELF-only cross-check)
│   ├── gdb_bridge.py       — PTY-based GDB terminal bridge (/ws/gdb)
│   ├── lldb_backend.py     — LLDB backend (ELF corefile + PE+PDB minidump)
│   ├── lldb_bridge.py      — In-process SBCommandInterpreter for /ws/lldb
│   ├── lldb_loader.py      — sys.path shim to import system lldb from a venv
│   ├── corefile.py         — Synthetic ELF core generator (ELFOSABI_LINUX)
│   ├── symbols.py          — SymbolTable, MapSymbol, map file parser,
│   │                         + LLDB-driven PDB symbol enumeration
│   ├── esr.py              — ARM64 ESR decode tables
│   └── models.py           — Shared dataclasses (CrashInfo, FrameInfo, etc.)
├── frontend/
│   ├── src/
│   │   ├── App.tsx         — Main layout + routing
│   │   ├── api.ts          — Backend API client
│   │   ├── types.ts        — TypeScript interfaces matching backend models
│   │   ├── components/
│   │   │   ├── CrashBanner.tsx
│   │   │   ├── BacktracePanel.tsx
│   │   │   ├── DetailPanel.tsx
│   │   │   ├── ParamsTab.tsx
│   │   │   ├── LocalsTab.tsx
│   │   │   ├── DisassemblyView.tsx
│   │   │   ├── SourceView.tsx
│   │   │   ├── RegisterPanel.tsx
│   │   │   ├── RawRsodPanel.tsx
│   │   │   ├── AddressResolver.tsx
│   │   │   ├── UploadForm.tsx
│   │   │   └── SessionHistory.tsx
│   │   └── hooks/
│   │       └── useSession.ts  — Session state management
│   ├── index.html
│   ├── package.json
│   ├── tsconfig.json
│   ├── tailwind.config.js
│   └── vite.config.ts      — Proxy /api to Flask in dev mode
├── tests/                  — Regression tests (parser + Flask API)
├── build_pyz.py            — Package as .pyzw zipapp
├── README.md               — User-facing docs
└── DESIGN.md               — This file
```

## Data Flow

```
1. User drags files onto drop zone, uses file picker, or pastes RSOD text
   Optional: specify git tag/commit for source context, base address override
   ↓
2. POST /api/session (multipart: files + optional tag/commit/base fields)
   ↓
3. Backend:
   a. detect_format() → uefi_x86 / uefi_arm64 / edk2_x64
   b. load_symbols() → SymbolTable + DwarfInfo (for ELF)
   c. extract_crash_info() → CrashInfo
   d. resolve addresses → line_info per module
   e. decode_x86() or decode_arm64() → annotated lines + frames
   f. Stage inputs under files/.staging/<uuid>/, content-hash to the
      session_id, dedup fast-path if the id already exists, else
      promote the staging dir to files/<id>/ and persist to SQLite.
      Either way the in-memory Session lands in the LRU hot cache.
   g. Return session_id + crash summary + frame list
   ↓
4. Frontend loads session, shows crash banner + backtrace
   ↓
5. User clicks frame #N
   ↓
6. GET /api/frame/<session>/<N>
   → Backend calls dwarf.get_params(addr), dwarf.get_locals(addr)
   → Returns params + locals with register values from CrashInfo
   ↓
7. Frontend shows params/locals in detail panel
   ↓
8. User clicks Disassembly tab
   ↓
9. GET /api/disasm/<session>/<N>
   → Backend calls dwarf.disassemble_around(addr)
   → Backend calls dwarf.source_lines_for_addrs()
   → Returns instruction list with source annotations
   ↓
10. Frontend renders disassembly with highlighted target instruction
```

## Browser Launch

`rsod serve` starts Flask on the configured host/port, waits for
the TCP port to accept connections via a short poll loop, then
opens the default browser via stdlib `webbrowser.open` on a
background thread. `--no-browser` skips the browser open for
headless invocations (CI, Playwright, curl probes). There is no
native-window binding — a regular browser tab at
`http://localhost:PORT` is the UX.

Launch:
```
rsod serve                         # opens browser to localhost:5000
rsod serve --no-browser            # headless (curl/Playwright)
rsod serve --port 9090             # custom port
rsod serve rsod.txt app.so -v      # pre-load a session on startup
```

## .pyzw Packaging

Both the CLI and web UI ship in a single unified `rsod.pyzw` zipapp.
`rsod decode` runs the text-report CLI; `rsod serve` launches the
Flask web UI and opens a browser tab. Imports are lazy in the
`rsod_decode.__main__` dispatcher so each subcommand only pays the
startup cost of its own code path.

Build:
```
cd frontend && npm run build   # produces frontend/dist/ (~600 KB)
python build_pyz.py            # → rsod.pyzw (~2.6 MB)
```

`build_pyz.py` refuses to run when `frontend/dist/index.html` is
missing — the React build is a hard precondition, not automated.

Contents (layout inside the zip):
```
rsod.pyzw/
├── __main__.py              bootstrap (extract + dispatch)
├── rsod_decode/             application code
├── flask/ werkzeug/ jinja2/ markupsafe/ blinker/
├── itsdangerous/ click/
├── flask_sock/ simple_websocket/ wsproto/ h11/
├── elftools/ capstone/ cxxfilt/ pefile.py pygdbmi/
└── frontend/dist/           React build output
```

Dependencies are staged with `pip install --target build/pyzw-staging
--no-compile --no-deps`, listing the full transitive closure
explicitly. `--no-deps` keeps the bundle deterministic across
rebuilds; the explicit list in `build_pyz._expand_deps()` is the
single source of truth for what lands in the artifact.

Excluded on purpose:
- `pywebview`, `playwright` — the web UI opens a browser tab via
  stdlib `webbrowser`; no native-window binding is bundled
- LLDB Python bindings — C extension tied to a specific LLVM
  version, discovered at runtime from the host's system install via
  `lldb_loader.py`. The loader returns `None` gracefully when the
  module is absent, so the pyzw still runs on LLDB-less hosts (ELF
  fixtures resolve fine; the PE+PDB path degrades to pyelftools).
- `tests/`, `tests/fixtures/`, `.venv/`, `.git/`
- `.dist-info` / `.egg-info` metadata (pruned after `pip install`)

First-run behavior:
- `__main__.py` hashes the zipapp's bytes (sha256, first 16 hex
  chars) and extracts two prefixes — `capstone/` and
  `frontend/dist/` — into `~/.cache/rsod-decode/libs/<hash16>/`.
  Capstone is extracted because `libcapstone.so` is loaded via
  `ctypes.CDLL` through a `__file__`-relative path that zipimport
  can't serve; `frontend/dist/` is extracted because Flask's
  `send_from_directory` needs a filesystem path for index.html +
  assets.
- The extraction dir is prepended to `sys.path` and
  `RSOD_FRONTEND_DIST` is set in the environment. `server.py`'s
  `resource_paths.frontend_dist()` checks that env var first before
  falling back to the editable-install layout.
- Subsequent runs skip extraction when a `.extracted` marker exists
  in the cache dir. Rebuilding the pyzw changes the content hash,
  so users automatically get fresh extraction without touching the
  old cache.

Distribution constraints:
- `libcapstone.so` makes the pyzw **architecture-specific**: a
  Linux-x86_64 build runs only on Linux x86_64. Build separate
  artifacts per platform if cross-distribution matters.
- Python 3.10+ on the target host (same as editable install).
- System LLDB is optional but gives the CLI + web UI access to
  callsite-arg reconstruction, PE+PDB minidump unwinding, and live
  variable value resolution. Without it both subcommands still run,
  just with the pyelftools fallback.

## Session Storage

### Persistent layer

SQLite at `~/.rsod-debug/sessions.db` (override via
`RSOD_DATA_DIR`). [src/rsod_decode/storage.py](src/rsod_decode/storage.py)
owns the schema + CRUD, [src/rsod_decode/data_dir.py](src/rsod_decode/data_dir.py)
owns the path resolution. The design hinge is that **storage holds
inputs, not results**: each row records the rsod text + form fields
+ a list of symbol files, and `service.run_analysis` is re-run on
every hydration. The analysis is deterministic, so there's no
versioned result format to migrate and no drift between stored and
recomputed frames.

### Session id is a content hash

`session_id` is `sha256(rsod.txt | <primary basename> | <primary
bytes> | … | <extra basename> | <extra bytes>)[:16]` — 16 hex chars,
64 bits, computed by `storage.compute_session_id(files_dir)`. Two
consequences:

- **Dedup is automatic.** Re-uploading the same inputs returns the
  existing row instead of creating a duplicate. `INSERT OR IGNORE`
  in `save_session` is the defensive backstop; the create_session
  and import_session routes check for an existing row up front and
  skip `run_analysis` entirely on a hit (HTTP 200 + `deduplicated:
  true`). Fresh uploads return the usual 201.
- **Cross-install permalinks are free.** Alice and Bob independently
  computing the hash over the same inputs produce the same id, so
  Bob importing Alice's bundle lands in a row with Alice's id. The
  exact same `#session/abc123def4567890` link resolves on any
  install that has imported (or independently uploaded) the same
  crash. Bundles are still the transport for symbol files; the id
  is just a stable reference.

Uploads stage files under `files/.staging/<uuid>/` first, compute
the hash, then either `rename` the staging dir to `files/<id>/`
(fresh) or `rmtree` it (dedup). Staging lives under `.staging/` so
the top level of `files/` only contains real session ids.

Schema v2:

```
sessions(
    id, created_at, rsod_format, image_name, image_base,
    exception_desc, crash_pc, crash_symbol, frame_count,
    backend, rsod_text, base_override, dwarf_prefix,
    imported_from   -- v2: original id when the row came from /api/import
) WITHOUT ROWID;

session_files(
    session_id, filename, file_type, rel_path
)  -- file_type ∈ {'primary','companion','pdb','extra'}
```

On-disk layout:

```
~/.rsod-debug/
├── sessions.db
└── files/<session_id>/
    ├── rsod.txt
    ├── <primary symbol file>
    ├── <companion>        (MSVC map or pe, if any)
    ├── <pdb>              (if any)
    └── <extra symbol files>
```

Schema version is tracked via `PRAGMA user_version`.
`storage.init_db()` is idempotent and runs inline migrations
(v1 → v2 is a single `ALTER TABLE`).

### In-memory hot cache

[src/rsod_decode/session.py](src/rsod_decode/session.py) keeps a
module-level `_sessions: dict[str, Session]` capped at
`MAX_SESSIONS = 50` in front of SQLite. Cleanup is split into two
paths:

- `evict_from_memory` — closes LLDB/GDB backends, drops the pyelftools
  binary, clears `frame_cache`, and removes the session from the
  dict. **Leaves persistent files and the SQLite row alone.** Used
  for LRU eviction.
- `delete_session` — everything `evict_from_memory` does, plus
  `storage.delete_session(id)` which drops the row and
  `rmtree`s `files/<id>/`. Only called from `DELETE /api/session/<id>`.

Every `Session` in memory holds:

- `result: AnalysisResult` — the shared core's parse output (frames,
  registers, stack mem, call_verified map)
- `source` / `extra_sources` — `SymbolSource` for the primary module
  + each extra the user uploaded
- `rsod_text` — the raw upload, cached for the `/api/session` GET
- `temp_dir` — short-lived scratch (GDB terminal corefile, etc.);
  **not** the persistent files dir. `None` until a bridge needs it
- `lldb_dwarf` / `gdb_dwarf` — richer backend instances, populated
  lazily by service.run_analysis / service.reinit_backend
- `frame_cache: dict[int, dict]` — per-frame JSON response cache so
  repeated `/api/frame/<id>/<n>` hits don't re-run DWARF walks

Restarting `rsod serve` now preserves history: on first access to an
evicted or cross-restart session, `_get_session` calls
`storage.hydrate_inputs`, re-runs `service.run_analysis` against the
persisted files, and stuffs the result back into the in-memory
dict. Permalinks (`#session/<id>`) work through the same path.

### Export / import bundle format

A `GET /api/export/<id>` response is a flat zip:

```
crash-<date>-<short8>.rsod.zip
├── metadata.json     — schema_version, session_id, file roles
├── rsod.txt          — original capture
├── <primary>         — symbol file (basename only)
├── <companion>       — MSVC map or pe, if present
├── <pdb>             — if present
└── <extras>…         — additional symbol files
```

`metadata.json` schema (v1):

```json
{
  "schema_version": 1,
  "session_id": "<original id>",
  "created_at": "<iso>",
  "rsod_filename": "rsod.txt",
  "primary_filename": "<basename>",
  "companion_filename": "<basename or null>",
  "pdb_filename": "<basename or null>",
  "extra_filenames": ["<basename>", "…"],
  "base_override": <int or null>,
  "dwarf_prefix": "<str or null>"
}
```

`POST /api/import` accepts the same shape and runs it through
`_extract_bundle`, which enforces (before touching disk):

- Member names must be flat basenames — rejects `..`, absolute
  paths, `/` or `\` separators, empty / whitespace-only names.
- Directories, symlinks (via POSIX mode `S_IFLNK` in the zip's
  `external_attr` high word), and other non-regular members are
  rejected outright.
- Total uncompressed size is capped at `BUNDLE_MAX_UNCOMPRESSED`
  (500 MiB) — the zip-bomb backstop.
- `metadata.json` must parse as a JSON object with an integer
  `schema_version ≤ BUNDLE_SCHEMA_VERSION`.

Imports compute the content hash over the unpacked inputs (after
discarding `metadata.json`, which isn't part of the canonical
input set), then dedup the same way uploads do: existing id →
HTTP 200 with `deduplicated: true`; fresh → HTTP 201. Either way
the new row's `imported_from` captures the `session_id` field
from `metadata.json` for audit purposes.

## What We Reuse vs Build New

### Reuse from current rsod-decode.py (extract into backend modules):

- `DwarfInfo` class → `backend/dwarf_info.py`
- `SymbolTable`, `MapSymbol`, `_build_table`, `parse_map_file` → `backend/symbols.py`
- `detect_format`, `extract_crash_info`, RSOD line patterns → `backend/decoder.py`
- `decode_x86`, `decode_arm64`, frame building → `backend/decoder.py`
- ESR decode tables → `backend/esr.py`
- `CrashInfo`, `FrameInfo`, `VarInfo`, etc. → `backend/models.py`
- Path cleanup `clean_path` → `backend/models.py`

### Build new:

- `app.py` — Flask routes, session management, file handling
- All frontend components
- `server.py` — entry point with browser launch (stdlib `webbrowser`)
- `build_pyz.py` — packaging script

## Implementation Phases

### Phase 1: Backend API

Extract current code into backend modules. Add Flask routes. Session
storage. Test with curl/httpie.

### Phase 2: Frontend MVP

Upload form → crash banner + backtrace + detail panel (params tab only).
Vite dev server with proxy. Basic Tailwind layout.

### Phase 3: Full Detail Panel

Disassembly tab, source tab, locals tab. Address resolver command bar.
Register panel with symbol annotations.

### Phase 4: Polish

Dark mode. Session history. Raw RSOD panel with clickable addresses.
Keyboard navigation (up/down to switch frames). Search.

### Phase 5: Desktop Packaging

Unified `rsod.pyzw` zipapp via `build_pyz.py`. Single-file
distribution bundling the CLI, the Flask web UI, the React
frontend, and all Python deps. Browser is launched via stdlib
`webbrowser` (no pywebview).

## CLI Compatibility

Both interfaces ship in a single `rsod` console script via argparse
subcommands, and the same code path is distributable as
`rsod.pyzw`:

```
rsod decode putty.txt app.efi.map           # text output
rsod serve  putty.txt app.efi.map           # opens web UI
rsod serve                                  # opens UI, upload via browser

python rsod.pyzw decode putty.txt app.efi.map   # standalone
python rsod.pyzw serve  putty.txt app.efi.map   # standalone
```

Both subcommands share the same `rsod_decode.service` analysis
pipeline, so they see identical backtraces, resolved values, and
tail-call-reconstructed frames regardless of which interface the
user picks.
