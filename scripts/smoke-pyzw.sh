#!/usr/bin/env bash
# Pre-release smoke test for the rsod.pyzw zipapp.
#
# Builds the zipapp from a clean state, then exercises the three
# subcommands a real user would hit (serve, decode, history). The
# goal is to catch artifact-only failures the pytest suite can't see
# — most importantly that `serve` actually starts and answers HTTP,
# since the in-process Flask test_client used by pytest never
# touches werkzeug.serving.make_server (which is where the v0.1.0
# importlib.metadata.PackageNotFoundError surfaced).
#
# Usage:
#   bash scripts/smoke-pyzw.sh
#
# Exits non-zero on any failure. Cleans up the tmp data dir + the
# background server even if interrupted.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Random unprivileged port + per-run data dir so concurrent runs and
# the developer's real ~/.rsod-debug/ don't collide.
PORT=$((30000 + RANDOM % 20000))
DATA_DIR="$(mktemp -d -t rsod-pyzw-smoke.XXXXXX)"
SERVER_LOG="$(mktemp -t rsod-smoke-server.XXXXXX.log)"
SERVER_PID=""

cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$DATA_DIR" "$SERVER_LOG"
}
trap cleanup EXIT INT TERM

step()  { echo "" ; echo "=== $* ===" ; }
fatal() { echo "SMOKE FAIL: $*" >&2 ; exit 1 ; }

# ----------------------------------------------------------------------
step "1. Build frontend + zipapp"
# ----------------------------------------------------------------------

if [ ! -d frontend/node_modules ]; then
  ( cd frontend && npm install )
fi
( cd frontend && npm run build )
python build_pyz.py
[ -f rsod.pyzw ] || fatal "rsod.pyzw not produced"
ls -lh rsod.pyzw

PYZW="$REPO_ROOT/rsod.pyzw"
export RSOD_DATA_DIR="$DATA_DIR"

# Pick a fixture that's fully checked into the repo so the smoke
# is self-contained (no dependency on out-of-tree symbol roots).
FIX_DIR="tests/fixtures/psa"
RSOD_LOG="$FIX_DIR/rsod_psa_x64.txt"
SYM_MAP="$FIX_DIR/psa_x64.map"
SYM_EFI="$FIX_DIR/psa_x64.efi"
[ -f "$RSOD_LOG" ] || fatal "missing fixture $RSOD_LOG"
[ -f "$SYM_MAP" ] || fatal "missing fixture $SYM_MAP"

# ----------------------------------------------------------------------
step "2. rsod decode (file mode → persists session)"
# ----------------------------------------------------------------------
DECODE_OUT="$(mktemp -t rsod-smoke-decode.XXXXXX.txt)"
trap 'rm -f "$DECODE_OUT"; cleanup' EXIT INT TERM
python "$PYZW" decode "$RSOD_LOG" "$SYM_MAP" -s "$SYM_EFI" \
  --name "smoke-test" -o "$DECODE_OUT"
grep -q "Crash Summary" "$DECODE_OUT" || fatal "decode output missing Crash Summary"
grep -q "Backtrace"     "$DECODE_OUT" || fatal "decode output missing Backtrace"
echo "decode output: $(wc -l < "$DECODE_OUT") lines"

# ----------------------------------------------------------------------
step "3. rsod history (should list the decoded session)"
# ----------------------------------------------------------------------
HIST_JSON="$(python "$PYZW" history --json)"
SESSION_ID="$(echo "$HIST_JSON" | python -c \
  'import sys, json; rows=json.load(sys.stdin); print(rows[0]["id"])')"
[ -n "$SESSION_ID" ] || fatal "history JSON empty"
echo "session_id = $SESSION_ID"

# ----------------------------------------------------------------------
step "4. rsod decode --session (replay from store)"
# ----------------------------------------------------------------------
SHORT_ID="${SESSION_ID:0:8}"
REPLAY_OUT="$(python "$PYZW" decode --session "$SHORT_ID" 2>/dev/null)"
echo "$REPLAY_OUT" | grep -q "Crash Summary" || fatal "replay missing Crash Summary"
echo "$REPLAY_OUT" | grep -q "Backtrace"     || fatal "replay missing Backtrace"
echo "replay ok"

# ----------------------------------------------------------------------
step "5. rsod serve (the path that was broken in v0.1.0)"
# ----------------------------------------------------------------------
python "$PYZW" serve --port "$PORT" --no-browser --host 127.0.0.1 \
  > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

# Poll for HTTP 200 — give it up to 15 seconds for cold pyzw
# extraction + Flask startup.
url="http://127.0.0.1:$PORT/"
for i in $(seq 1 30); do
  if curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null | grep -q '^200$'; then
    echo "serve responding on $url after ${i}/30 polls"
    break
  fi
  sleep 0.5
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "--- server log ---"
    cat "$SERVER_LOG"
    fatal "serve process died during startup"
  fi
  if [ "$i" -eq 30 ]; then
    echo "--- server log ---"
    cat "$SERVER_LOG"
    fatal "serve never reached HTTP 200 on $url"
  fi
done

# ----------------------------------------------------------------------
step "6. /api/history through the live server"
# ----------------------------------------------------------------------
LIVE_HIST="$(curl -s "http://127.0.0.1:$PORT/api/history")"
echo "$LIVE_HIST" | python -c \
  'import sys, json; d=json.load(sys.stdin); assert any(s["id"].startswith("'"$SHORT_ID"'") for s in d["sessions"]), d' \
  || fatal "live /api/history missing the smoke session"
echo "live history ok"

echo ""
echo "=== smoke OK ==="
