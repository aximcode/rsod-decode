"""rsod history — list persisted sessions from ~/.rsod-debug/.

Prints a compact table to stdout:

    ID        IMAGE      EXCEPTION                  SYM          FRAMES  AGE
    ab12cd34  psa_x64    General Protection Fault    trigger_gp…       8  2h
    ef56ab78  CrashTest  Data Abort: Trans fault L3  crashtest…       17  3d
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from . import storage


def _ago(iso: str) -> str:
    """Human-readable relative time like '2h', '3d', '5w'."""
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return iso[:10]
    delta = datetime.now(timezone.utc) - dt
    secs = int(delta.total_seconds())
    if secs < 60:
        return 'now'
    if secs < 3600:
        return f'{secs // 60}m'
    if secs < 86400:
        return f'{secs // 3600}h'
    if secs < 604800:
        return f'{secs // 86400}d'
    return f'{secs // 604800}w'


def _trunc(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n - 1] + '\u2026'


def main() -> None:
    parser = argparse.ArgumentParser(
        description='List persisted RSOD sessions.')
    parser.add_argument('-n', '--limit', type=int, default=50,
                        help='Maximum rows to show (default: 50)')
    parser.add_argument('--json', action='store_true', dest='as_json',
                        help='Output raw JSON instead of a table')
    args = parser.parse_args()

    storage.init_db()
    rows = storage.list_sessions(limit=args.limit)

    if not rows:
        print('No saved sessions. Upload via `rsod serve` or POST /api/session.',
              file=sys.stderr)
        return

    if args.as_json:
        import json
        print(json.dumps([{
            'id': r.id,
            'created_at': r.created_at,
            'image_name': r.image_name,
            'exception_desc': r.exception_desc,
            'crash_pc': r.crash_pc,
            'crash_symbol': r.crash_symbol,
            'frame_count': r.frame_count,
            'backend': r.backend,
            'imported_from': r.imported_from,
        } for r in rows], indent=2))
        return

    # Table output — fixed-width columns tuned for 120-col terminals.
    hdr = (f'{"ID":<18}  {"IMAGE":<14}  {"EXCEPTION":<28}  '
           f'{"SYMBOL":<18}  {"FR":>3}  {"AGE":>4}')
    print(hdr)
    print('-' * len(hdr))
    for r in rows:
        sid = r.id[:8]
        img = _trunc(r.image_name, 14)
        exc = _trunc(r.exception_desc, 28)
        sym = _trunc(r.crash_symbol, 18)
        age = _ago(r.created_at)
        imp = ' *' if r.imported_from else ''
        print(f'{sid:<18}  {img:<14}  {exc:<28}  {sym:<18}  '
              f'{r.frame_count:>3}  {age:>4}{imp}')

    if any(r.imported_from for r in rows):
        print('\n* = imported from a bundle', file=sys.stderr)


if __name__ == '__main__':
    main()
