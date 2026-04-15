
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
│  Native Window (pywebview)                           │
│  or Chrome --app mode                                │
│  or browser tab at localhost:PORT                     │
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
│  /api/resolve          POST resolve arbitrary addr   │
│  /api/source           GET  source file context      │
│  /api/registers/<id>   GET  full register dump       │
│  /api/history          GET  past sessions            │
│                                                      │
│  ┌─────────────────────────────────────────────────┐ │
│  │  Core Analysis Engine                           │ │
│  │  (decoder, dwarf_info, symbols, esr)            │ │
│  └─────────────────────────────────────────────────┘ │
│                                                      │
│  SQLite session store (~/.rsod-debug/sessions.db)     │
└──────────────────────────────────────────────────────┘
```

## Tech Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Backend | Flask 3.x | Lightweight, proven pattern for local tool UIs |
| Frontend | React 19 + TypeScript | SPA for responsive frame-switching |
| Styling | Tailwind CSS | Rapid UI development, dark mode |
| Build | Vite | Fast dev server with HMR, proxy to Flask |
| Disassembly | capstone (Python) | Native ARM64/x86 disassembly |
| ELF/DWARF | pyelftools | Symbol resolution, source lines, params |
| Demangling | cxxfilt | C++ name demangling |
| Native window | pywebview (optional) | Desktop app feel, no browser chrome |
| Database | SQLite | Session history, zero setup |
| Distribution | .pyzw zipapp | Single file, no installer |

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
- **History** of analyzed RSODs stored in SQLite for recall
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

POST /api/search/<session_id>
  Body: { query: "fPromptTestError" }
  Response: { matches[]: { address, name, source_loc } }
```

### Session History and Export

```
GET /api/history
  Response: { sessions[]: { id, date, image, exception, frame_count } }

GET /api/export/<session_id>?format=json
  Response: Full session data as JSON (shareable, importable)

GET /api/export/<session_id>?format=text
  Response: CLI-style text output (same as rsod-decode.py)

POST /api/import
  Body: JSON export from another instance
  Response: { session_id }
```

Permalink support: `http://localhost:PORT/#session/<id>` opens a
specific saved analysis.  JSON export/import allows sharing crash
analyses between team members without sharing symbol files.

## Project Structure

```
rsod-decode/
├── pyproject.toml          — Packaging, deps, pytest config
├── src/rsod_decode/
│   ├── __init__.py
│   ├── server.py           — rsod-debug entry point (Flask launcher + CLI pre-load)
│   ├── cli.py              — rsod-decode entry point (text-only)
│   ├── app.py              — Flask app, routes, session management
│   ├── decoder.py          — RSOD text parsing, format detection
│   ├── dwarf_backend.py    — DwarfInfo class (pyelftools + capstone)
│   ├── pe_backend.py       — PEBinary class (pefile + capstone)
│   ├── gdb_backend.py      — GDB/MI DWARF backend (Phase-5 deletion pending)
│   ├── gdb_bridge.py       — PTY-based GDB terminal bridge (Phase-5 pending)
│   ├── lldb_backend.py     — LLDB backend (ELF corefile + PE+PDB static)
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
   f. Store session in SQLite + temp files
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

## Native Window Strategy

Three-tier approach for maximum compatibility:

1. **pywebview** — `pip install pywebview` (optional dependency)
   - Creates native OS window: macOS WebKit, Windows Edge WebView2, Linux WebKitGTK
   - Flask runs in background thread
   - Best UX: looks like a real desktop app

2. **Chrome/Edge --app mode** — fallback
   - Detects Chrome or Edge installation
   - Opens in app mode (no address bar, minimal chrome)
   - Nearly as good as native window

3. **Browser tab** — last resort
   - Opens `http://localhost:PORT` in default browser
   - Full functionality, just has browser chrome

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

SQLite database at `~/.rsod-debug/sessions.db`:

```sql
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    created_at TEXT,
    rsod_format TEXT,
    image_name TEXT,
    exception_desc TEXT,
    crash_pc INTEGER,
    crash_symbol TEXT,
    frame_count INTEGER,
    rsod_text TEXT,        -- original RSOD capture
    crash_info TEXT        -- JSON: full CrashInfo
);

CREATE TABLE session_files (
    session_id TEXT,
    filename TEXT,
    file_type TEXT,        -- 'rsod_log', 'symbol', 'extra_symbol'
    file_path TEXT,        -- path in ~/.rsod-debug/files/
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);
```

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

- `backend/app.py` — Flask routes, session management, file handling
- All frontend components
- `rsod-debug.py` — entry point with pywebview/browser launch
- `build_pyz.py` — packaging script
- SQLite session store

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

pywebview integration. Chrome --app fallback. build_pyz.py for .pyzw
distribution.

## CLI Compatibility

The CLI tool continues to work standalone:

```
rsod-decode putty.txt app.efi.map        # text output
rsod-debug  putty.txt app.efi.map        # opens web UI
rsod-debug                               # opens UI, upload via browser
```

Both share the same `rsod_decode` package modules.
