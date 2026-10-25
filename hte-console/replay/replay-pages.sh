#!/usr/bin/env bash
# Phase 7 replay: the pages hte-console 0.7.0 serves (Account, Alarms, Logs) against PHP's own, in THROWAWAY containers
# on placeholder data (`hte-console page-seed`: three people, three computers, log rows of several ages, one session each).
#   A. PHP (SESSION_DRIVER=database) and hte-console get the same database; `page-replay` signs in as each person with a
#      session cookie it makes itself and asks both the same pages (filters, paging, dates, CSV) and the same writes
#      (profile, password, theme: hte-console through its forms, PHP through Livewire). It compares the status, the
#      redirect, what a person reads, the sequence of CSS classes, and the CSV bytes.
#   B. The two databases after the writes are compared with `hte-console snapshot` (the rows PHP wrote and the rows
#      hte-console wrote must be the same, bar the session rows' ids and the salt of a bcrypt hash, which the script masks).
#   C. A mutation check: one log row is changed on the hte-console side only; a reads-only run must then FAIL. A replay
#      that cannot fail proves nothing.
# Touches nothing that runs: its own network, its own containers, a temp directory. Runs on the server (docker only).
#
#   HTE_CONSOLE_IMAGE=ghcr.io/regendorf-ux/hte-console:0.7.0 bash replay-pages.sh
#
# Exit 0 = every comparison equal and the mutation caught, 1 = a difference (printed), 2 = could not run.
# Every docker command reads </dev/null so the script can also be piped through `ssh host 'bash -s'`.
set -euo pipefail

CONSOLE_IMAGE="${HTE_CONSOLE_IMAGE:?set HTE_CONSOLE_IMAGE}"
PHP_IMAGE="${HTE_PHP_IMAGE:-ghcr.io/regendorf-ux/hte-cortendesk:1.15.0-hte.1}"
TAG="hte-pg-$$"
WORK="$(mktemp -d)"
NOW="$(date +%s)"
FAIL=0

cleanup() {
  docker rm -f "$TAG-php" "$TAG-rust" </dev/null >/dev/null 2>&1 || true
  docker network rm "$TAG" </dev/null >/dev/null 2>&1 || true
  rm -rf "$WORK" 2>/dev/null || docker run --rm -v "$WORK:/w" --entrypoint sh "$CONSOLE_IMAGE" -c 'rm -rf /w/*' </dev/null >/dev/null 2>&1 || true
}
trap cleanup EXIT

php_exec() { docker exec -u www-data -w /app "$TAG-php" "$@" </dev/null; }
tinker() { php_exec php artisan tinker --execute="$1" 2>/dev/null | tr -d '\r\n'; }
# hte-console's own commands against the copy it serves (as the database's owner)
rust_cmd() { docker run --rm --network none -u 82:82 -v "$WORK/rdata:/data" -e HTE_CONSOLE_DATABASE=/data/cortendesk.sqlite "$CONSOLE_IMAGE" "$@" </dev/null; }
start_rust() {
  docker rm -f "$TAG-rust" </dev/null >/dev/null 2>&1 || true
  docker run -d --name "$TAG-rust" --network "$TAG" -u 82:82 -v "$WORK/rdata:/data" \
    -e HTE_CONSOLE_DATABASE=/data/cortendesk.sqlite -e HTE_CONSOLE_APP_KEY_FILE=/data/.app_key -e HTE_CONSOLE_SESSION_COOKIE="$COOKIE" \
    -e HTE_CONSOLE_API_VERSION=1.15.0-hte.1 -e HTE_CONSOLE_UPSTREAM="http://$TAG-php:8080" -e HTE_CONSOLE_SWEEPS="" \
    "$CONSOLE_IMAGE" </dev/null >/dev/null
  for _ in $(seq 1 30); do
    docker run --rm --network "$TAG" --entrypoint wget "$PHP_IMAGE" -q -O /dev/null "http://$TAG-rust:8080/health/live" </dev/null 2>/dev/null && return 0
    sleep 1
  done
  echo "hte-console did not start" >&2; docker logs "$TAG-rust" </dev/null 2>&1 | tail -5 >&2; exit 2
}
replay() { # replay [extra docker env...]: prints page-replay's report, returns its exit code
  docker run --rm --network "$TAG" -v "$WORK/rdata:/data:ro" -e HTE_CONSOLE_APP_KEY_FILE=/data/.app_key -e HTE_CONSOLE_SESSION_COOKIE="$COOKIE" "$@" \
    "$CONSOLE_IMAGE" page-replay "http://$TAG-php:8080" "http://$TAG-rust:8080" "$NOW" </dev/null
}
state() { # state <sqlite-dir> : the data as comparable text (sessions keep their count, not their rows: PHP and hte-console mint different ids; a bcrypt hash is salted, so only its shape is compared)
  docker run --rm --network none -v "$1:/data:ro" "$CONSOLE_IMAGE" snapshot /data/cortendesk.sqlite </dev/null \
    | grep -vE '^(cache|cache_locks|sqlite_sequence|jobs|job_batches|failed_jobs|oidc_auth_requests|password_reset_tokens|password_resets|migrations)[ :]' \
    | grep -vE '^sessions \{' | sed -E 's/text:\$2y\$[^"]*/text:<bcrypt>/' || true
}

docker network create "$TAG" </dev/null >/dev/null
mkdir -p "$WORK/data" "$WORK/rdata"
chmod 777 "$WORK" "$WORK/data" "$WORK/rdata" </dev/null
docker run --rm --entrypoint cat "$PHP_IMAGE" /etc/supervisord.conf </dev/null | awk '/^\[program:scheduler\]/{skip=1; next} /^\[/{skip=0} !skip' > "$WORK/supervisord.conf"
echo "== a throwaway PHP console ($PHP_IMAGE): sessions in the database, no ID server, no scheduler, no update check"
docker run -d --name "$TAG-php" --network "$TAG" -v "$WORK/data:/data" -v "$WORK/supervisord.conf:/etc/supervisord.conf:ro" \
  -e CORTENDESK_EMBEDDED_SERVER=false -e APP_ENV=production -e APP_DEBUG=false -e SESSION_DRIVER=database -e CACHE_STORE=database \
  -e CORTENDESK_UPDATE_CHECK=false "$PHP_IMAGE" </dev/null >/dev/null
for _ in $(seq 1 60); do docker exec "$TAG-php" wget -q -O /dev/null http://127.0.0.1:8080/health/live </dev/null 2>/dev/null && break; sleep 2; done
docker exec "$TAG-php" wget -q -O /dev/null http://127.0.0.1:8080/health/live </dev/null || { echo "PHP did not start" >&2; exit 2; }
COOKIE="$(tinker 'echo config("session.cookie");')"
[ -n "$COOKIE" ] && [ "$(tinker 'echo config("session.driver");')" = database ] || { echo "PHP does not use the database session driver (cookie '$COOKIE')" >&2; exit 2; }
echo "session cookie: $COOKIE (driver: database)"

echo "== the placeholder data, in PHP's database, then a copy for hte-console"
docker run --rm --network none "$CONSOLE_IMAGE" page-seed "$NOW" </dev/null > "$WORK/seed.sql"
docker cp "$WORK/seed.sql" "$TAG-php:/tmp/seed.sql" </dev/null
docker exec -u www-data "$TAG-php" php -r '$d = new PDO("sqlite:/data/cortendesk.sqlite"); $d->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); $d->exec(file_get_contents("/tmp/seed.sql")); echo "seeded\n";' </dev/null
docker exec -u www-data "$TAG-php" php -r '$d = new PDO("sqlite:/data/cortendesk.sqlite"); $d->exec("VACUUM INTO \"/data/copy-for-rust.sqlite\"");' </dev/null
docker cp "$TAG-php:/data/copy-for-rust.sqlite" "$WORK/rdata/cortendesk.sqlite" </dev/null
docker cp "$TAG-php:/data/.app_key" "$WORK/rdata/.app_key" </dev/null
chmod 666 "$WORK/rdata/cortendesk.sqlite"; chmod 644 "$WORK/rdata/.app_key"   # docker cp makes them the caller's; the console runs as 82:82
state "$WORK/rdata" > "$WORK/before-rust.txt"
docker exec -u www-data "$TAG-php" php -r '$d = new PDO("sqlite:/data/cortendesk.sqlite"); $d->exec("VACUUM INTO \"/data/state-before.sqlite\"");' </dev/null
mkdir -p "$WORK/state-before"
docker cp "$TAG-php:/data/state-before.sqlite" "$WORK/state-before/cortendesk.sqlite" </dev/null
chmod 755 "$WORK/state-before"; chmod 644 "$WORK/state-before/cortendesk.sqlite"
state "$WORK/state-before" > "$WORK/before-php.txt"
if cmp -s "$WORK/before-php.txt" "$WORK/before-rust.txt"; then echo "   the two databases start equal ($(wc -l < "$WORK/before-php.txt") lines)"; else echo "   the copies differ before any request: cannot judge" >&2; exit 2; fi

start_rust

echo "== A. every page and write, both sides"
if replay; then echo "   equal: pages, redirects, text, classes, CSV"; else echo "   DIFFERENT (see the lines above)" >&2; FAIL=1; fi

echo "== B. the database after the writes, both sides"
docker stop "$TAG-rust" </dev/null >/dev/null
docker exec -u www-data "$TAG-php" php -r '$d = new PDO("sqlite:/data/cortendesk.sqlite"); $d->exec("VACUUM INTO \"/data/state-after.sqlite\"");' </dev/null
mkdir -p "$WORK/state-after"; chmod 755 "$WORK/state-after"
docker cp "$TAG-php:/data/state-after.sqlite" "$WORK/state-after/cortendesk.sqlite" </dev/null; chmod 644 "$WORK/state-after/cortendesk.sqlite"
state "$WORK/state-after" > "$WORK/after-php.txt"
state "$WORK/rdata" > "$WORK/after-rust.txt"
if cmp -s "$WORK/after-php.txt" "$WORK/after-rust.txt"; then
  echo "   equal: both databases after the same writes ($(wc -l < "$WORK/after-php.txt") lines)"
else
  echo "   DIFFERENT: the rows the two sides wrote" >&2; diff "$WORK/after-php.txt" "$WORK/after-rust.txt" | head -30 >&2; FAIL=1
fi
cmp -s "$WORK/before-php.txt" "$WORK/after-php.txt" && { echo "   the writes changed nothing in PHP's database: cannot judge" >&2; FAIL=1; }

echo "== C. a changed row on hte-console's side only must be caught"
printf "UPDATE alarm_logs SET info = 'tampered' WHERE id = (SELECT max(id) FROM alarm_logs);\n" > "$WORK/rdata/mutate.sql"
chmod 644 "$WORK/rdata/mutate.sql"
rust_cmd sql-apply /data/cortendesk.sqlite /data/mutate.sql
start_rust
if HTE_PAGEREPLAY_READS_ONLY=1 replay -e HTE_PAGEREPLAY_READS_ONLY=1 >"$WORK/mut.out" 2>&1; then
  echo "   the replay did NOT notice a changed log row: it cannot be trusted" >&2; cat "$WORK/mut.out" >&2; FAIL=1
else
  echo "   caught: $(head -1 "$WORK/mut.out")"
fi

echo
[ "$FAIL" = 0 ] && echo "page replay: PHP and hte-console agree on every page, on every write, and the check can fail" || echo "DIFFERENCES FOUND (see above)"
exit "$FAIL"
