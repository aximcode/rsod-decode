"""Unified entry point for rsod — `decode` and `serve` subcommands.

Dispatches to `rsod_decode.cli:main` (text-report CLI) or
`rsod_decode.server:main` (Flask web UI + browser launcher) based on
argv[1]. Imports are lazy so `rsod decode` doesn't pay Flask's
import cost and `rsod serve` doesn't parse the CLI's argparse.

Invoked as:
    rsod decode <rsod.txt> <symbols> [options]
    rsod serve  [<rsod.txt> <symbols>] [options]

We avoid argparse here because the subcommands have their own
parsers; using argparse at the dispatcher layer would eagerly
intercept `--help` and prevent it from flowing through to the
subcommand's own help text.
"""
from __future__ import annotations

import sys


_USAGE = """usage: rsod {decode,serve} [args...]

RSOD crash analyzer — decode to text or serve a web UI.

  rsod decode  Write a text report to disk (CLI-only).
  rsod serve   Launch the Flask web UI + open a browser tab.

Run `rsod decode --help` or `rsod serve --help` for per-subcommand
options."""


def main() -> int:
    argv = sys.argv[1:]
    if not argv or argv[0] in ('-h', '--help'):
        print(_USAGE)
        return 0 if argv else 2

    command = argv[0]
    rest = argv[1:]
    if command not in ('decode', 'serve'):
        print(f"rsod: unknown command {command!r}", file=sys.stderr)
        print(_USAGE, file=sys.stderr)
        return 2

    # Rewrite argv so the subcommand's own argparse sees a clean
    # argv[0] and doesn't re-parse the subcommand token.
    sys.argv = [f'rsod {command}', *rest]

    if command == 'decode':
        from .cli import main as cli_main
        result = cli_main()
    else:
        from .server import main as server_main
        result = server_main()
    return 0 if result is None else int(result)


if __name__ == '__main__':
    raise SystemExit(main())
