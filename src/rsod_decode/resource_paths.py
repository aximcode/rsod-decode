"""Filesystem paths for bundled resources.

Keeps server.py agnostic about whether it's running from an editable
install or from inside a pyzw whose bootstrap extracted static
assets to a cache dir.
"""
from __future__ import annotations

import os
from pathlib import Path


def frontend_dist() -> Path:
    """Return the filesystem path to the built React frontend.

    Inside a pyzw the bootstrap `__main__.py` extracts `frontend/dist`
    to `~/.cache/rsod-decode/libs/<hash>/frontend/dist` and sets
    `RSOD_FRONTEND_DIST` so Flask's `send_from_directory` can serve
    it from a real path. In an editable install the env var is
    unset, so we fall back to `<repo>/frontend/dist`.
    """
    env = os.environ.get('RSOD_FRONTEND_DIST')
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2] / 'frontend' / 'dist'
