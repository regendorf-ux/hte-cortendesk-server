#!/usr/bin/env bash
# Phase 6 replay: PHP's backup, restore and prune commands against hte-console's, in THROWAWAY containers on
# placeholder data. It proves, with PHP itself on the other side:
#   A. an archive PHP made (cortendesk:backup) restores in hte-console (restore) to exactly the data it was made from;
#   B. an archive hte-console made (backup) is read by PHP's BackupService and restores in PHP (cortendesk:restore)
#      to exactly the data it was made from;
#   C. `backup --scheduled` honours the marker the other side wrote (a second run on the same day is "Not due");
#   D. prune-logs and prune-invitations delete the same rows as PHP's commands on copies of one database.
# "Exactly" = `hte-console snapshot` of the database before and after, ignoring the tables a restore leaves alone.
# Touches nothing that runs: its own network, its own containers, a temp directory. Runs on the server (docker only).
#
#   HTE_CONSOLE_IMAGE=ghcr.io/regendorf-ux/hte-console:0.6.0 bash backup-roundtrip.sh
#
# Exit 0 = every comparison equal, 1 = a difference (printed), 2 = could not run.
# Every docker command reads </dev/null so the script can also be piped through `ssh host 'bash -s'`.
set -euo pipefail

CONSOLE_IMAGE="${HTE_CONSOLE_IMAGE:?set HTE_CONSOLE_IMAGE}"
PHP_IMAGE="${HTE_PHP_IMAGE:-ghcr.io/regendorf-ux/hte-cortendesk:1.15.0-hte.1}"
TAG="hte-bk-$$"
WORK="$(mktemp -d)"
LINK_SECRET="tok-5eed00000003c0de"
FAIL=0

cleanup() {
  docker rm -f "$TAG-php" </dev/null >/dev/null 2>&1 || true
  docker network rm "$TAG" </dev/null >/dev/null 2>&1 || true
  rm -rf "$WORK" 2>/dev/null || docker run --rm -v "$WORK:/w" --entrypoint sh "$CONSOLE_IMAGE" -c 'rm -rf /w/*' </dev/null >/dev/null 2>&1 || true
}
trap cleanup EXIT

php_exec() { docker exec -u www-data -w /app "$TAG-php" "$@" </dev/null; }
pdo() { docker exec -u www-data "$TAG-php" php -r '$d = new PDO("sqlite:/data/cortendesk.sqlite"); $d->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); $d->exec($argv[1]); echo "ok\n";' "$1" </dev/null >/dev/null; }
# hte-console against the PHP container's /data (the same directory, as in production), as the database's owner
rust() { docker run --rm --network "$TAG" -u 82:82 -v "$WORK/data:/data" \
  -e HTE_CONSOLE_DATABASE=/data/cortendesk.sqlite -e HTE_CONSOLE_CACHE_PREFIX="$CACHE_PREFIX" -e CORTENDESK_SERVER_SECRET="$LINK_SECRET" \
  -e HTE_CONSOLE_BACKUPS_DIR=/data/backups -e HTE_CONSOLE_API_VERSION=1.15.0-hte.1 "$CONSOLE_IMAGE" "$@" </dev/null; }
# the data as comparable text, without the tables a restore does not touch
data_state() { # data_state <label>: a consistent copy through PHP, then snapshot
  pdo "VACUUM INTO '/data/state-$1.sqlite'"
  docker run --rm --network none -v "$WORK/data:/data:ro" "$CONSOLE_IMAGE" snapshot "/data/state-$1.sqlite" </dev/null \
    | grep -vE '^(cache|cache_locks|sessions|sqlite_sequence|jobs|job_batches|failed_jobs|oidc_auth_requests|password_reset_tokens|password_resets|migrations)[ :]' || true
  docker exec "$TAG-php" rm -f "/data/state-$1.sqlite" </dev/null
}
same() { # same <what> <file-a> <file-b>
  if cmp -s "$2" "$3"; then echo "   equal: $1 ($(wc -l < "$2") lines)"; else echo "   DIFFERENT: $1" >&2; diff "$2" "$3" | head -20 >&2; FAIL=1; fi
}

docker network create "$TAG" </dev/null >/dev/null
mkdir -p "$WORK/data"
chmod 777 "$WORK" "$WORK/data" </dev/null
docker run --rm --entrypoint cat "$PHP_IMAGE" /etc/supervisord.conf </dev/null | awk '/^\[program:scheduler\]/{skip=1; next} /^\[/{skip=0} !skip' > "$WORK/supervisord.conf"
echo "== a throwaway PHP console ($PHP_IMAGE), no ID server, no scheduler"
docker run -d --name "$TAG-php" --network "$TAG" -v "$WORK/data:/data" -v "$WORK/supervisord.conf:/etc/supervisord.conf:ro" \
  -e CORTENDESK_EMBEDDED_SERVER=false -e APP_ENV=production -e APP_DEBUG=false -e CORTENDESK_SERVER_SECRET="$LINK_SECRET" -e CACHE_STORE=database \
  "$PHP_IMAGE" </dev/null >/dev/null
for _ in $(seq 1 60); do docker exec "$TAG-php" wget -q -O /dev/null http://127.0.0.1:8080/health/live </dev/null 2>/dev/null && break; sleep 2; done
docker exec "$TAG-php" wget -q -O /dev/null http://127.0.0.1:8080/health/live </dev/null || { echo "PHP did not start" >&2; exit 2; }
CACHE_PREFIX="$(php_exec php artisan tinker --execute='echo config("cache.prefix");' | tr -d '\r\n')"
[ -n "$CACHE_PREFIX" ] || { echo "no cache prefix" >&2; exit 2; }

echo "== seeding placeholders (an encrypted setting, an encrypted TOTP secret, logs of several ages, invitations)"
docker cp "$TAG-php:/data/.app_key" "$WORK/app_key" </dev/null; chmod 644 "$WORK/app_key"
cat > "$WORK/seed.sql" <<'SQL'
INSERT INTO users (id, username, name, email, password, is_admin, is_active, totp_secret, created_at, updated_at) VALUES
  (900001, 'user-seed0001', 'text-seed0001', 'user-seed0001@example.invalid', 'x', 1, 1, '@@ENCRYPT(JBSWY3DPEHPK3PXP)@@', datetime('now'), datetime('now')),
  (900002, 'user-seed0002', 'María "q" / é 日本', 'user-seed0002@example.invalid', 'x', 0, 1, NULL, datetime('now'), datetime('now'));
INSERT INTO settings (key, value, created_at, updated_at) VALUES ('oidc_client_secret', '@@ENCRYPT(placeholder-client-secret)@@', datetime('now'), datetime('now')), ('oidc_button_label', 'Sign in', NULL, NULL);
INSERT INTO devices (rustdesk_id, uuid, hostname, user_id, created_at, updated_at) VALUES ('100000001', 'dXVpZC1zZWVkMDAwMQ==', 'host-seed0001', 900001, datetime('now'), datetime('now'));
INSERT INTO alarm_logs (rustdesk_id, typ, info, created_at, updated_at) VALUES ('100000001', 1, 'a-old', datetime('now', '-400 days'), datetime('now')), ('100000001', 1, 'b-edge', datetime('now', '-29 days'), datetime('now')), ('100000001', 1, 'c-new', datetime('now', '-1 days'), datetime('now'));
INSERT INTO login_logs (username, client, created_at, updated_at) VALUES ('u', 'web', datetime('now', '-100 days'), datetime('now')), ('u', 'web', datetime('now', '-2 days'), datetime('now'));
INSERT INTO console_audits (username, action, summary, created_at) VALUES ('system', 'x', 'old', datetime('now', '-90 days')), ('system', 'x', 'new', datetime('now', '-1 days'));
INSERT INTO invitations (email, username, token_hash, expires_at, accepted_at, created_at, updated_at) VALUES
  ('a@example.invalid', 'a', 'h1', datetime('now', '-3 days'), NULL, datetime('now'), datetime('now')),
  ('b@example.invalid', 'b', 'h2', datetime('now', '+3 days'), NULL, datetime('now'), datetime('now')),
  ('c@example.invalid', 'c', 'h3', datetime('now', '-60 days'), datetime('now', '-45 days'), datetime('now'), datetime('now')),
  ('d@example.invalid', 'd', 'h4', datetime('now', '-60 days'), datetime('now', '-2 days'), datetime('now'), datetime('now'));
INSERT INTO trusted_devices (user_id, token_hash, expires_at, created_at, updated_at) VALUES (900001, 't1', datetime('now', '-1 days'), datetime('now'), datetime('now')), (900001, 't2', datetime('now', '+9 days'), datetime('now'), datetime('now'));
SQL
docker run --rm --network none -v "$WORK:/w:ro" -e HTE_CONSOLE_APP_KEY_FILE=/w/app_key "$CONSOLE_IMAGE" seed-expand /w/seed.sql http://unused </dev/null > "$WORK/seed.expanded.sql"
docker cp "$WORK/seed.expanded.sql" "$TAG-php:/tmp/seed.sql" </dev/null
docker exec -u www-data "$TAG-php" php -r '$d = new PDO("sqlite:/data/cortendesk.sqlite"); $d->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); $d->exec(file_get_contents("/tmp/seed.sql")); echo "seeded\n";' </dev/null
data_state base > "$WORK/s-base.txt"
wc -l "$WORK/s-base.txt"

mutate() { pdo "DELETE FROM devices; DELETE FROM alarm_logs; UPDATE settings SET value = 'changed' WHERE key = 'oidc_button_label'; DELETE FROM users WHERE id = 900002; INSERT INTO settings (key, value) VALUES ('junk', 'x')"; }

echo "== A. PHP makes the archive, hte-console restores it"
php_exec php artisan cortendesk:backup | tee "$WORK/php-backup.out"
A="$(ls -1 "$WORK/data/backups" | grep -E '\.tar$' | head -1)"
[ -n "$A" ] || { echo "PHP made no archive" >&2; exit 2; }
echo "   archive: $A"
mutate
data_state mutated > "$WORK/s-mutated.txt"
if cmp -s "$WORK/s-base.txt" "$WORK/s-mutated.txt"; then echo "   the mutation changed nothing: cannot judge" >&2; exit 2; fi
rust backups
rust restore "$A" --force
data_state restoredA > "$WORK/s-restoredA.txt"
same "PHP archive -> hte-console restore" "$WORK/s-base.txt" "$WORK/s-restoredA.txt"

echo "== B. hte-console makes the archive, PHP reads and restores it"
rust backup | tee "$WORK/rust-backup.out"
B="$(ls -1t "$WORK/data/backups" | grep -E '\.tar$' | head -1)"
[ "$B" != "$A" ] || { echo "hte-console made no archive" >&2; exit 2; }
echo "   archive: $B"
echo "   PHP's own reader says: $(php_exec php artisan tinker --execute='$b = app(App\Services\Backups\BackupService::class); $m = $b->readManifest($b->path("'"$B"'")); echo "format ", $m["format"], ", ", count($m["tables"]), " tables, ", array_sum($m["tables"]), " rows, files ", implode(",", $m["files"]);')"
echo "   PHP's listing: $(php_exec php artisan tinker --execute='echo count(app(App\Services\Backups\BackupService::class)->list()), " backups, newest ", app(App\Services\Backups\BackupService::class)->list()[0]["name"];')"
mutate
php_exec php artisan cortendesk:restore "$B" --force | tee "$WORK/php-restore.out"
data_state restoredB > "$WORK/s-restoredB.txt"
same "hte-console archive -> PHP restore" "$WORK/s-base.txt" "$WORK/s-restoredB.txt"

echo "== C. the daily marker is shared"
pdo "DELETE FROM settings WHERE key IN ('backup_last_scheduled_at', 'backup_last_result')"
php_exec php artisan cortendesk:backup --scheduled | tee "$WORK/c1.out"
rust backup --scheduled | tee "$WORK/c2.out"
grep -q '^Not due' "$WORK/c2.out" && echo "   equal: hte-console sees PHP's marker (Not due)" || { echo "   DIFFERENT: hte-console ran after PHP's scheduled backup" >&2; FAIL=1; }
pdo "DELETE FROM settings WHERE key = 'backup_last_scheduled_at'"
rust backup --scheduled >/dev/null
php_exec php artisan cortendesk:backup --scheduled | tee "$WORK/c3.out"
grep -q '^Not due' "$WORK/c3.out" && echo "   equal: PHP sees hte-console's marker (Not due)" || { echo "   DIFFERENT: PHP ran after hte-console's scheduled backup" >&2; FAIL=1; }
echo "   Settings -> Backups would show: $(php_exec php artisan tinker --execute='echo App\Models\Setting::get("backup_last_result");' | cut -c1-200)"

echo "== D. prune: the same rows go on copies of one database"
pdo "VACUUM INTO '/data/copy-for-rust.sqlite'"
mkdir -p "$WORK/rdata"; chmod 777 "$WORK/rdata"
docker cp "$TAG-php:/data/copy-for-rust.sqlite" "$WORK/rdata/cortendesk.sqlite" </dev/null
chmod 666 "$WORK/rdata/cortendesk.sqlite"   # docker cp makes it the caller's: the console below runs as 82:82
docker cp "$TAG-php:/data/.app_key" "$WORK/rdata/.app_key" </dev/null; chmod 644 "$WORK/rdata/.app_key"
php_exec php artisan cortendesk:prune-logs --days=30 | tee "$WORK/p1.out"
php_exec php artisan cortendesk:prune-invitations | tee "$WORK/p2.out"
docker run --rm --network none -u 82:82 -v "$WORK/rdata:/data" -e HTE_CONSOLE_DATABASE=/data/cortendesk.sqlite -e HTE_CONSOLE_CACHE_PREFIX="$CACHE_PREFIX" "$CONSOLE_IMAGE" prune-logs --days=30 </dev/null | tee "$WORK/r1.out"
docker run --rm --network none -u 82:82 -v "$WORK/rdata:/data" -e HTE_CONSOLE_DATABASE=/data/cortendesk.sqlite -e HTE_CONSOLE_CACHE_PREFIX="$CACHE_PREFIX" "$CONSOLE_IMAGE" prune-invitations </dev/null | tee "$WORK/r2.out"
same "prune-logs output" "$WORK/p1.out" "$WORK/r1.out"
same "prune-invitations output" "$WORK/p2.out" "$WORK/r2.out"
data_state php_pruned > "$WORK/s-php-pruned.txt"
docker run --rm --network none -v "$WORK/rdata:/data:ro" "$CONSOLE_IMAGE" snapshot /data/cortendesk.sqlite </dev/null \
  | grep -vE '^(cache|cache_locks|sessions|sqlite_sequence|jobs|job_batches|failed_jobs|oidc_auth_requests|password_reset_tokens|password_resets|migrations)[ :]' > "$WORK/s-rust-pruned.txt" || true
# the copy was taken after C, so the settings differ only if the commands touched them: compare the pruned tables
for t in alarm_logs login_logs console_audits invitations trusted_devices audit_connections audit_file_transfers notification_deliveries; do
  grep -E "^$t[ :]" "$WORK/s-php-pruned.txt" > "$WORK/a.txt" || true
  grep -E "^$t[ :]" "$WORK/s-rust-pruned.txt" > "$WORK/b.txt" || true
  same "table $t after pruning" "$WORK/a.txt" "$WORK/b.txt"
done

echo
[ "$FAIL" = 0 ] && echo "backup round trips: PHP and hte-console agree in both directions, on the marker and on pruning" || echo "DIFFERENCES FOUND (see above)"
exit "$FAIL"
