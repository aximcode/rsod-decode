"""Browser-level regression tests via Playwright.

Spawns a werkzeug dev server in a thread so Playwright can hit real
HTTP, uploads fixture sessions through the Flask test client (which
shares the module-level session store with the thread-served app so
both views see the same registered sessions), then drives a headless
Chromium browser to click frames and verify tab content. Marked
`playwright`; skips cleanly when Playwright or a built `frontend/dist`
isn't available.

Run just these tests:

    pytest -q -m playwright
"""
from __future__ import annotations

import io
import re
import socket
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

try:
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_OK = True
except ImportError:
    _PLAYWRIGHT_OK = False

if TYPE_CHECKING:
    from playwright.sync_api import Browser, Page

from ._datasets import DATASET_SPECS, DatasetSpec, FIXTURES_DIR, REPO_ROOT

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not _PLAYWRIGHT_OK, reason='playwright not installed'),
]


# ---------------------------------------------------------------------
# Server fixture (werkzeug dev server in a thread, serves the SPA)
# ---------------------------------------------------------------------


def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f'port {port} never opened')


@pytest.fixture(scope='module')
def live_server():
    """Start the Flask app on a real ephemeral port in a background thread.

    Yields `(app, base_url)`. The `app` is reused via its test client to
    POST /api/session and register sessions, and `base_url` is the http
    origin that Playwright hits to load the SPA.
    """
    from flask import send_from_directory
    from werkzeug.serving import make_server
    from rsod_decode.app import create_app

    dist_dir = REPO_ROOT / 'frontend' / 'dist'
    if not dist_dir.is_dir() or not (dist_dir / 'index.html').is_file():
        pytest.skip('frontend/dist not built; run `cd frontend && npm run build`')

    app = create_app(repo_root=REPO_ROOT, dwarf_prefix=None)

    @app.get('/')
    def _index():  # pyright: ignore[reportUnusedFunction]
        return send_from_directory(str(dist_dir), 'index.html')

    @app.get('/assets/<path:filename>')
    def _assets(filename: str):  # pyright: ignore[reportUnusedFunction]
        return send_from_directory(str(dist_dir / 'assets'), filename)

    port = _find_free_port()
    srv = make_server('127.0.0.1', port, app, threaded=True)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        _wait_for_port('127.0.0.1', port)
        yield app, f'http://127.0.0.1:{port}'
    finally:
        srv.shutdown()
        thread.join(timeout=5)


# ---------------------------------------------------------------------
# Playwright browser/page fixtures
# ---------------------------------------------------------------------


@pytest.fixture(scope='module')
def browser():
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True)
        try:
            yield b
        finally:
            b.close()


@pytest.fixture
def page(browser: 'Browser'):
    ctx = browser.new_context(viewport={'width': 1600, 'height': 900})
    p = ctx.new_page()
    try:
        yield p
    finally:
        ctx.close()


# ---------------------------------------------------------------------
# Session-upload helper (reuses the Flask test client so we don't have
# to hand-craft multipart bodies against the thread-served app).
# ---------------------------------------------------------------------


def _upload_session(app, spec: DatasetSpec) -> str:
    rsod_path = FIXTURES_DIR / spec.rsod_file
    if not spec.symbol_path.exists():
        pytest.skip(f'missing symbol file: {spec.symbol_path}')
    if spec.companion_path is not None and not spec.companion_path.exists():
        pytest.skip(f'missing companion file: {spec.companion_path}')

    client = app.test_client()
    extra_fps: list = []
    extras: list = []
    with spec.symbol_path.open('rb') as symbol_fp:
        data: dict = {
            'rsod_log': (io.BytesIO(rsod_path.read_bytes()), spec.rsod_file),
            'symbol_file': (symbol_fp, spec.symbol_path.name),
        }
        if spec.companion_path is not None:
            f = spec.companion_path.open('rb')
            extra_fps.append(f)
            extras.append((f, spec.companion_path.name))
        if spec.pdb_path is not None and spec.pdb_path.exists():
            f = spec.pdb_path.open('rb')
            extra_fps.append(f)
            extras.append((f, spec.pdb_path.name))
        if extras:
            data['extra_symbols[]'] = extras if len(extras) > 1 else extras[0]
        if spec.base_override is not None:
            data['base'] = f'{spec.base_override:X}'
        try:
            response = client.post(
                '/api/session', data=data, content_type='multipart/form-data')
        finally:
            for f in extra_fps:
                f.close()

    assert response.status_code == 201, response.get_json()
    return response.get_json()['session_id']


def _open_session(page: 'Page', base_url: str, session_id: str) -> None:
    page.goto(f'{base_url}/#session/{session_id}')
    # CrashBanner is the first thing the SPA paints once the session
    # loads; waiting on it proves the initial API calls landed.
    page.get_by_text('RSOD', exact=True).first.wait_for(timeout=10_000)


# ---------------------------------------------------------------------
# Dell AArch64 ELF+DWARF coverage — all seven detail tabs on frame 0
# ---------------------------------------------------------------------


def test_browser_dell_aa64_frame_tabs(live_server, page: 'Page') -> None:
    app, base_url = live_server
    session_id = _upload_session(app, DATASET_SPECS['dell_aa64'])
    _open_session(page, base_url, session_id)

    # Backend auto-detect picks lldb; the current-backend button is
    # rendered disabled on purpose.
    assert page.get_by_role('button', name='lldb').is_disabled()

    # Backtrace: frame 0 = dispatch_crash. Waiting for the exact symbol
    # confirms both that analyze_rsod resolved it and that the
    # BacktracePanel rendered the full list.
    page.get_by_role('button', name=re.compile(r'dispatch_crash')).first.wait_for(
        timeout=10_000)

    # --- Params tab (frame 0 is selected by default) --------------
    page.get_by_role('button', name='Params').click()
    # dispatch_crash(CrashContext *ctx) — should show `ctx` with pointer type.
    ctx_row = page.get_by_role('row').filter(has_text='ctx')
    ctx_row.wait_for(timeout=5_000)
    assert 'CrashContext' in ctx_row.first.inner_text()

    # --- Locals tab ------------------------------------------------
    page.get_by_role('button', name='Locals').click()
    # dispatch_crash has one local: `mode` (const char *)
    mode_row = page.get_by_role('row').filter(has_text='mode')
    mode_row.wait_for(timeout=5_000)

    # --- Globals tab -----------------------------------------------
    page.get_by_role('button', name='Globals').click()
    # CrashTest fixture exposes g_run_count / g_default_config / g_crash_cookie
    page.get_by_role('row').filter(has_text='g_').first.wait_for(timeout=5_000)

    # --- Disassembly tab ------------------------------------------
    page.get_by_role('button', name='Disassembly').click()
    # ARM64 instructions — wait for a common mnemonic to show up.
    page.locator('text=/\\b(ret|mov|ldr|str|bl|adrp)\\b/').first.wait_for(
        timeout=5_000)

    # --- Source tab ------------------------------------------------
    page.get_by_role('button', name='Source').click()
    # frame.source_loc resolves to crashtest.c — any mention confirms
    # the file was found and rendered.
    page.get_by_text('crashtest.c').first.wait_for(timeout=5_000)

    # --- Memory tab ------------------------------------------------
    page.get_by_role('button', name='Memory').click()
    # Memory view renders hex byte groups; the "Address" header is a
    # stable anchor across backends.
    page.get_by_text('Address').first.wait_for(timeout=5_000)

    # --- RSOD Log tab ---------------------------------------------
    page.get_by_role('button', name='RSOD Log').click()
    # The raw log contains the characteristic Dell exception banner.
    page.get_by_text('Synchronous').first.wait_for(timeout=5_000)


def test_browser_dell_aa64_switch_frame_updates_detail(
    live_server, page: 'Page',
) -> None:
    """Clicking a non-crash frame updates the Params/Locals tabs.

    Frame 3 is `initialize_test` on the dell_aa64 fixture (the inner
    function that owns the CrashContext local). The detail panel
    should re-render with that frame's variables.
    """
    app, base_url = live_server
    session_id = _upload_session(app, DATASET_SPECS['dell_aa64'])
    _open_session(page, base_url, session_id)

    page.get_by_role('button', name=re.compile(r'initialize_test')).first.click()
    # Header of the detail panel shows `#3 initialize_test`
    page.get_by_text('initialize_test').first.wait_for(timeout=5_000)
    page.get_by_role('button', name='Locals').click()
    # initialize_test's local is `ctx` (CrashContext struct, not pointer)
    page.get_by_role('row').filter(has_text='ctx').first.wait_for(timeout=5_000)


# ---------------------------------------------------------------------
# PE+PDB coverage — initialize_test's ctx expansion and ground-truth
# values bubble through the browser UI identically to the API test.
# ---------------------------------------------------------------------


def test_browser_psa_x64_forcecrash_ctx_expand(live_server, page: 'Page') -> None:
    spec = DATASET_SPECS['psa_x64_forcecrash']
    if spec.pdb_path is None or not spec.pdb_path.exists():
        pytest.skip('psa_x64_forcecrash .pdb not present')

    app, base_url = live_server
    session_id = _upload_session(app, spec)
    _open_session(page, base_url, session_id)

    # Click initialize_test (frame 1) — MSVC tail-call chain means
    # this is the only real frame with a struct local we can expand.
    page.get_by_role('button', name=re.compile(r'initialize_test')).first.click()
    page.get_by_role('button', name='Locals').click()

    # ctx local — CrashContext struct
    ctx_row = page.get_by_role('row').filter(has_text='ctx').first
    ctx_row.wait_for(timeout=5_000)
    assert 'CrashContext' in ctx_row.inner_text()

    # Expand: the first button in the row is the ▶ toggle
    ctx_row.get_by_role('button').first.click()

    # After expansion, child fields render as sibling rows: depth,
    # cookie, tag, attempts, config. The tag field's string_preview
    # pulls "crashtest-v3" out of rdata — strong signal the PDB
    # type lookup + section read both worked.
    page.get_by_text('crashtest-v3').first.wait_for(timeout=5_000)

    # Also expand config (pointer → CrashTestConfig) to verify the
    # pointer-dereference + nested pe_type: var_key path.
    config_row = page.get_by_role('row').filter(has_text='config').first
    config_row.get_by_role('button').first.click()
    page.get_by_text('0xDEAD0000CAFE0000').first.wait_for(timeout=5_000)
