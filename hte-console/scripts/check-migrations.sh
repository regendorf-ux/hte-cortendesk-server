#!/usr/bin/env bash
# Compare migrate.rs's list of the PHP console's migrations with the PHP fork's directory (the fork is archived at
# 1.15.0-hte.1; run this if a PHP release is ever read for ideas and its migrations are wanted here).
#   scripts/check-migrations.sh ~/Sites/cortendesk
set -euo pipefail
FORK="${1:?usage: check-migrations.sh <php console fork>}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
diff <(ls "$FORK/database/migrations" | sed 's/\.php$//' | sort) \
     <(sed -n '/^pub const PHP_MIGRATIONS/,/^\];/p' "$HERE/src/migrate.rs" | sed -n 's/^ *"\(.*\)",\{0,1\}$/\1/p' | sort) \
  && echo "migrate.rs lists exactly the fork's $(ls "$FORK/database/migrations" | wc -l | tr -d ' ') migrations"
