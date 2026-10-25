#!/usr/bin/env bash
# Re-copy the PHP console's static files that the pages share (CSS, shell/theme JS, images, fonts, bootstrap, remixicon,
# apexcharts) into assets/, byte for byte, so a page served here looks like the same page from PHP. htmx and
# js/hte-pages.js are ours and are never touched.
#   scripts/sync-assets.sh /path/to/php-console/public
set -euo pipefail
SRC="${1:?usage: sync-assets.sh <php public dir>}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
for d in css images fonts vendor/bootstrap vendor/remixicon vendor/apexcharts; do
  [ -d "$SRC/$d" ] || { echo "missing $SRC/$d" >&2; exit 1; }
  mkdir -p "$HERE/assets/$d"
  rsync -a --delete --exclude hte-pages.css "$SRC/$d/" "$HERE/assets/$d/"   # hte-pages.css is ours
done
for f in js/shell.js js/theme-init.js js/cortendesk.js; do
  [ -f "$SRC/$f" ] || { echo "missing $SRC/$f" >&2; exit 1; }
  cp -p "$SRC/$f" "$HERE/assets/$f"
done
echo "assets synced from $SRC; run: cargo test -p hte-console --test pages assets"
