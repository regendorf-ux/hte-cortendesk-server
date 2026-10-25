#!/usr/bin/env bash
# Phase 8 replay: the console's sign-in (`/login`, `/login/oidc`, `/login/oidc/callback`, `/logout`) of hte-console against
# PHP's own, in THROWAWAY containers on placeholder data (phase 2's sign-in seed: a break-glass account, a disabled one, an
# SSO-created one, one waiting for approval, SSO accounts to link, a known identity, a disabled identity; SSO through the
# fake identity provider, TEST ONLY).
#   A. `web-signin-replay` runs the same scenario against both consoles with a cookie jar each: the sign-in page, every
#      password outcome, no CSRF token, the signed-in sign-in page, logout, the per-account throttle, and Microsoft sign-in
#      in every mode the fake provider has (each broken-token kind, a refusal, an outsider, a disabled account, linking by
#      e-mail, a known identity, provisioning). It compares status, redirect, visible text and CSS classes per step.
#   B. The two databases afterwards (`snapshot`): login_logs, alarm_logs, users (linking, provisioning, remember tokens).
#      Left out: sessions (PHP's and the bridge's rows have different ids by nature), hte_console_sessions (hte-console's
#      own table, PHP has none), cache rows (PHP keeps its rate limiters there, hte-console in memory), oidc_auth_requests.
#   C. A mutation check: one of hte-console's answers is changed before the comparison; the replay must then FAIL.
# Touches nothing that runs: its own network, its own containers, a temp directory. Runs on the server (docker only).
#
#   HTE_CONSOLE_IMAGE=ghcr.io/regendorf-ux/hte-console:0.8.0 bash replay-signin-web.sh
#
# Exit 0 = every comparison equal and the mutation caught, 1 = a difference (printed), 2 = could not run.
# Every docker command reads </dev/null so the script can also be piped through `ssh host 'bash -s'`.
set -euo pipefail

CONSOLE_IMAGE="${HTE_CONSOLE_IMAGE:?set HTE_CONSOLE_IMAGE}"
PHP_IMAGE="${HTE_PHP_IMAGE:-ghcr.io/regendorf-ux/hte-cortendesk:1.15.0-hte.1}"
TAG="hte-sw-$$"
WORK="$(mktemp -d)"
FAIL=0
IDP_SECRET="tok-5eed00000000c11e"   # the seed's oidc_client_secret (a placeholder, for the fake provider only)
COMMON_ENV=(-e "APP_NAME=HTE Remote" -e HTE_SIGNIN_DOMAIN=example.invalid -e CORTENDESK_UPDATE_CHECK=false)

cleanup() {
  docker rm -f "$TAG-php" "$TAG-rust" "$TAG-idp" </dev/null >/dev/null 2>&1 || true
  docker network rm "$TAG" </dev/null >/dev/null 2>&1 || true
  rm -rf "$WORK" 2>/dev/null || docker run --rm -v "$WORK:/w" --entrypoint sh "$CONSOLE_IMAGE" -c 'rm -rf /w/*' </dev/null >/dev/null 2>&1 || true
}
trap cleanup EXIT

php_exec() { docker exec -u www-data -w /app "$TAG-php" "$@" </dev/null; }
tinker() { php_exec php artisan tinker --execute="$1" 2>/dev/null | tr -d '\r\n'; }
up() { # up <url> <what>: wait for a health URL from inside the network
  for _ in $(seq 1 60); do
    docker run --rm --network "$TAG" --entrypoint wget "$PHP_IMAGE" -q -O /dev/null "$1" </dev/null 2>/dev/null && return 0
    sleep 2
  done
  echo "$2 did not start" >&2; exit 2
}
state() { # state <sqlite-dir> [rust]: the rows to compare as text
  local mode=ro user=0
  [ "${2:-}" = rust ] && { mode=rw; user=82:82; }
  docker run --rm -u "$user" --network none -e HTE_SNAPSHOT_MASK_TOKENS=1 -v "$1:/data:$mode" "$CONSOLE_IMAGE" snapshot /data/cortendesk.sqlite </dev/null \
    | grep -vE '^(cache|cache_locks|sqlite_sequence|jobs|job_batches|failed_jobs|oidc_auth_requests|password_reset_tokens|password_resets|migrations|sessions|hte_console_sessions)[ :]' \
    | sed -E 's/text:\$2y\$[^"]*/text:<bcrypt>/' || true
}

docker network create "$TAG" </dev/null >/dev/null
mkdir -p "$WORK/data" "$WORK/rdata"
chmod 777 "$WORK" "$WORK/data" "$WORK/rdata" </dev/null
docker run --rm --entrypoint cat "$PHP_IMAGE" /etc/supervisord.conf </dev/null | awk '/^\[program:scheduler\]/{skip=1; next} /^\[/{skip=0} !skip' > "$WORK/supervisord.conf"

echo "== a throwaway PHP console ($PHP_IMAGE): sessions and cache in the database, no ID server, no scheduler"
docker run -d --name "$TAG-php" --network "$TAG" -v "$WORK/data:/data" -v "$WORK/supervisord.conf:/etc/supervisord.conf:ro" \
  -e CORTENDESK_EMBEDDED_SERVER=false -e APP_ENV=production -e APP_DEBUG=false -e SESSION_DRIVER=database -e CACHE_STORE=database \
  "${COMMON_ENV[@]}" "$PHP_IMAGE" </dev/null >/dev/null
up "http://$TAG-php:8080/health/live" "PHP"
COOKIE="$(tinker 'echo config("session.cookie");')"
[ -n "$COOKIE" ] && [ "$(tinker 'echo config("session.driver");')" = database ] || { echo "PHP does not use the database session driver" >&2; exit 2; }
echo "PHP's session cookie: $COOKIE"

echo "== the fake identity provider (TEST ONLY)"
docker run -d --name "$TAG-idp" --network "$TAG" -e HTE_FAKE_IDP_ISSUER="http://$TAG-idp:8080" -e HTE_FAKE_IDP_CLIENT_SECRET="$IDP_SECRET" \
  "$CONSOLE_IMAGE" fake-idp </dev/null >/dev/null
up "http://$TAG-idp:8080/__fake-idp/health" "the fake provider"

echo "== the placeholder accounts and settings, in PHP's database, then a copy for hte-console"
docker cp "$TAG-php:/data/.app_key" "$WORK/rdata/.app_key" </dev/null
chmod 644 "$WORK/rdata/.app_key"
docker run --rm --network none -v "$WORK/rdata/.app_key:/app_key:ro" -e HTE_CONSOLE_APP_KEY_FILE=/app_key "$CONSOLE_IMAGE" web-signin-seed "http://$TAG-idp:8080" </dev/null > "$WORK/seed.sql"
docker cp "$WORK/seed.sql" "$TAG-php:/tmp/seed.sql" </dev/null
docker exec -u www-data "$TAG-php" php -r '$d = new PDO("sqlite:/data/cortendesk.sqlite"); $d->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); $d->exec(file_get_contents("/tmp/seed.sql")); echo "seeded\n";' </dev/null
docker exec -u www-data "$TAG-php" php -r '$d = new PDO("sqlite:/data/cortendesk.sqlite"); $d->exec("VACUUM INTO \"/data/copy-for-rust.sqlite\"");' </dev/null
docker cp "$TAG-php:/data/copy-for-rust.sqlite" "$WORK/rdata/cortendesk.sqlite" </dev/null
chmod 666 "$WORK/rdata/cortendesk.sqlite"
docker run --rm -u 0 --network none -v "$WORK/rdata:/data" --entrypoint chown "$CONSOLE_IMAGE" -R 82:82 /data </dev/null

echo "== hte-console with its own sign-in (HTE_CONSOLE_SIGNIN=1, the bridge on)"
docker run -d --name "$TAG-rust" --network "$TAG" -u 82:82 -v "$WORK/rdata:/data" \
  -e HTE_CONSOLE_DATABASE=/data/cortendesk.sqlite -e HTE_CONSOLE_APP_KEY_FILE=/data/.app_key -e HTE_CONSOLE_SESSION_COOKIE="$COOKIE" \
  -e HTE_CONSOLE_API_VERSION=1.15.0-hte.1 -e HTE_CONSOLE_UPSTREAM="http://$TAG-php:8080" -e HTE_CONSOLE_SWEEPS="" \
  -e HTE_CONSOLE_SIGNIN=1 -e HTE_CONSOLE_OIDC_ALLOW_HTTP=1 "${COMMON_ENV[@]}" \
  "$CONSOLE_IMAGE" </dev/null >/dev/null
up "http://$TAG-rust:8080/health/live" "hte-console"

replay() { docker run --rm --network "$TAG" "$@" "$CONSOLE_IMAGE" web-signin-replay "http://$TAG-php:8080" "http://$TAG-rust:8080" </dev/null; }

echo "== A. the sign-in scenario, both sides"
if replay; then echo "   equal: every step (the 'by design' lines above are phase 2's token hardening)"; else echo "   DIFFERENT (see the DIFFERENCE lines above)" >&2; FAIL=1; fi
LEAKS="$(docker logs "$TAG-rust" </dev/null 2>&1 | grep -ciE 'tok-5eed|password=|id_token=|code_verifier|state=' || true)"
if [ "$LEAKS" = 0 ]; then echo "   hte-console's log: no password, token, state or verifier"; else echo "   hte-console's log mentions a secret ($LEAKS lines)" >&2; FAIL=1; fi

echo "== B. the rows both sides wrote"
docker stop "$TAG-rust" </dev/null >/dev/null
docker exec -u www-data "$TAG-php" php -r '$d = new PDO("sqlite:/data/cortendesk.sqlite"); $d->exec("VACUUM INTO \"/data/state-after.sqlite\"");' </dev/null
mkdir -p "$WORK/state-after"; chmod 755 "$WORK/state-after"
docker cp "$TAG-php:/data/state-after.sqlite" "$WORK/state-after/cortendesk.sqlite" </dev/null; chmod 644 "$WORK/state-after/cortendesk.sqlite"
state "$WORK/state-after" > "$WORK/after-php.txt"
state "$WORK/rdata" rust > "$WORK/after-rust.txt"
if cmp -s "$WORK/after-php.txt" "$WORK/after-rust.txt"; then
  echo "   equal: $(grep -cE '^login_logs ' "$WORK/after-php.txt" || true) sign-in log rows, alarms, accounts ($(wc -l < "$WORK/after-php.txt") lines)"
else
  echo "   DIFFERENT: the rows the two sides wrote (- PHP, + hte-console)" >&2; { diff "$WORK/after-php.txt" "$WORK/after-rust.txt" | head -40 >&2; } || true; FAIL=1
fi
grep -qE '^login_logs: [1-9]' "$WORK/after-php.txt" || { echo "   PHP wrote no sign-in rows: cannot judge" >&2; FAIL=1; }

echo "== C. a changed answer on hte-console's side must be caught"
docker start "$TAG-rust" </dev/null >/dev/null
up "http://$TAG-rust:8080/health/live" "hte-console"
if replay -e HTE_WEBREPLAY_MUTATE=1 >"$WORK/mut.out" 2>&1; then
  echo "   the replay did NOT notice a changed answer: it cannot be trusted" >&2; FAIL=1
else
  echo "   caught: $(grep -m1 DIFFERENCE "$WORK/mut.out" | cut -c1-120)"
fi

echo
[ "$FAIL" = 0 ] && echo "sign-in replay: PHP and hte-console agree on every step and every row, and the check can fail" || echo "DIFFERENCES FOUND (see above)"
exit "$FAIL"
