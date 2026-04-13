"""Import shim for the system-installed lldb Python module.

The rsod-decode venv typically isn't created with --system-site-packages,
so a plain `import lldb` fails even when LLDB is installed on the host.
`import_lldb()` tries the normal import first and falls back to searching
well-known system paths, degrading to None rather than raising when the
module is genuinely unavailable. Mirrors the `gdb_available()` pattern in
session.py.
"""
from __future__ import annotations

import sys
from functools import lru_cache
from pathlib import Path
from types import ModuleType

_SEARCH_ROOTS: tuple[str, ...] = ("/usr/lib64", "/usr/lib")


@lru_cache(maxsize=1)
def import_lldb() -> ModuleType | None:
    """Return the lldb module, or None if it can't be imported.

    Tries the venv's own site-packages first. On miss, walks known system
    install roots (/usr/lib64/python3.*/site-packages, /usr/lib/...) and
    prepends the first match to sys.path before retrying the import.
    Cached so the path search only runs once per process.
    """
    try:
        import lldb  # type: ignore[import-not-found]
        return lldb
    except ImportError:
        pass

    for root in _SEARCH_ROOTS:
        root_path = Path(root)
        if not root_path.is_dir():
            continue
        candidates = sorted(
            root_path.glob("python3.*/site-packages"), reverse=True)
        for py_dir in candidates:
            if not (py_dir / "lldb").is_dir():
                continue
            py_str = str(py_dir)
            if py_str not in sys.path:
                sys.path.insert(0, py_str)
            try:
                import lldb  # type: ignore[import-not-found]
                return lldb
            except ImportError:
                continue
    return None
