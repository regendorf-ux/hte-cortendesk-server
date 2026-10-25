#!/usr/bin/env bash
# Compare THIS checkout's hte-console with PHP's answers captured by a server run of replay-pages.sh, on a machine without PHP
# and without building an image. The pages and the dialogs are compared exactly as run A of the replay compares them
# (the same code: `page-replay` with HTE_PAGEREPLAY_PHP_FROM); the CSV exports, the writes and the databases need PHP's
# Livewire and stay with the server run.
#
#   bash hte-console/replay/compare-local.sh "$HOME/apps/notes/phase7/hte-replay-capture.tgz"
#
# It unpacks the capture (the database PHP and hte-console started from, its throwaway app key, the moment and PHP's
# answers) into a temp directory, starts the local build on a copy of that database with its clock set to the captured
# moment (HTE_CONSOLE_CLOCK_START, so "5 minutes ago" and dates read as they did for PHP), and runs the comparison.
# The capture only fits the replay that took it: a page or dialog added to the replay since needs a new capture.
# Exit 0 = equal, 1 = differences (printed), 2 = could not run.
set -euo pipefail

CAPTURE="${1:?usage: compare-local.sh <hte-replay-capture.tgz>}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"
PORT="${HTE_COMPARE_PORT:-18089}"
PID=""
cleanup() {
  [ -n "$PID" ] && kill "$PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/php" "$WORK/data"
tar -C "$WORK/php" -xzf "$CAPTURE" || { echo "cannot unpack $CAPTURE" >&2; exit 2; }
for f in meta.json cortendesk.sqlite .app_key; do
  [ -f "$WORK/php/$f" ] || { echo "$CAPTURE has no $f: take a capture with replay-pages.sh from 0.7.18 on" >&2; exit 2; }
done
NOW="$(sed -n 's/.*"now": *\([0-9]*\).*/\1/p' "$WORK/php/meta.json")"
COOKIE="$(sed -n 's/.*"cookie": *"\([^"]*\)".*/\1/p' "$WORK/php/meta.json")"
cp "$WORK/php/cortendesk.sqlite" "$WORK/php/.app_key" "$WORK/data/"
chmod 600 "$WORK/data/cortendesk.sqlite"
echo "== PHP's answers from $(sed -n 's/.*"php_image": *"\([^"]*\)".*/\1/p' "$WORK/php/meta.json"), taken at $(date -u -r "$NOW" '+%Y-%m-%d %H:%M UTC' 2>/dev/null || echo "$NOW") ($(ls "$WORK/php" | grep -c '^[pd][0-9]') answers)"

echo "== building this checkout's hte-console"
cargo build -q -p hte-console --manifest-path "$ROOT/Cargo.toml"
BIN="${CARGO_TARGET_DIR:-$ROOT/target}/debug/hte-console"

echo "== the local console, on the captured database and clock"
HTE_CONSOLE_DATABASE="$WORK/data/cortendesk.sqlite" HTE_CONSOLE_APP_KEY_FILE="$WORK/data/.app_key" HTE_CONSOLE_SESSION_COOKIE="$COOKIE" \
  HTE_CONSOLE_API_VERSION=1.15.0-hte.1 CORTENDESK_UPDATE_CHECK=false HTE_CONSOLE_UPSTREAM="http://127.0.0.1:9" HTE_CONSOLE_SWEEPS="" \
  HTE_CONSOLE_LISTEN="127.0.0.1:$PORT" HTE_CONSOLE_TEMPLATES="$HERE/templates" HTE_CONSOLE_CLOCK_START="$NOW" \
  HTE_CONSOLE_BACKUPS_DIR=/data/backups RUST_LOG=error \
  "$BIN" >"$WORK/console.log" 2>&1 &
PID=$!
# any answer will do (/health/live is PHP's, forwarded to an upstream that is not there)
up() { [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/health/live" 2>/dev/null)" != 000 ]; }
for _ in $(seq 1 60); do
  up && break
  kill -0 "$PID" 2>/dev/null || { echo "the console stopped:" >&2; tail -5 "$WORK/console.log" >&2; exit 2; }
  sleep 0.5
done
up || { echo "the console did not start" >&2; tail -5 "$WORK/console.log" >&2; exit 2; }

echo "== pages and dialogs, against PHP's captured answers"
HTE_PAGEREPLAY_PHP_FROM="$WORK/php" HTE_CONSOLE_APP_KEY_FILE="$WORK/data/.app_key" HTE_CONSOLE_SESSION_COOKIE="$COOKIE" \
  "$BIN" page-replay - "http://127.0.0.1:$PORT" "$NOW"
