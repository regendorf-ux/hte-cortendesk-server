#!/usr/bin/env bash
# Replay recorded fixtures against the PHP console in a THROWAWAY container with a database of placeholders,
# and report differences. Touches nothing that runs: its own network, its own containers, a temp directory.
# Runs on the VPS (docker only, no Rust) or in CI.
#
#   HTE_CONSOLE_IMAGE=<hte-console image>  HTE_CONSOLE_SANITISE_SALT=<same salt as the capture> \
#     replay.sh <fixtures-dir>
#
# Exit 0 = no differences, 1 = differences (printed), 2 = could not run.
# Every docker command reads </dev/null so the script can also be piped through `ssh host 'bash -s'`.
set -euo pipefail

FIXTURES="$(cd "${1:?usage: replay.sh <fixtures-dir>}" && pwd)"
CONSOLE_IMAGE="${HTE_CONSOLE_IMAGE:?set HTE_CONSOLE_IMAGE}"
PHP_IMAGE="${HTE_PHP_IMAGE:-ghcr.io/regendorf-ux/hte-cortendesk:1.15.0-hte.1}"
SALT="${HTE_CONSOLE_SANITISE_SALT:-}"
LITERALS="${HTE_CONSOLE_SANITISE_LITERALS:-}"
TAG="hte-replay-$$"
WORK="$(mktemp -d)"

cleanup() {
  docker rm -f "$TAG-php" </dev/null >/dev/null 2>&1 || true
  docker network rm "$TAG" </dev/null >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

console() { # run one hte-console subcommand with the fixtures mounted read-only
  docker run --rm --network "$TAG" -v "$FIXTURES:/fixtures:ro" \
    -e HTE_CONSOLE_SANITISE_SALT="$SALT" -e HTE_CONSOLE_SANITISE_LITERALS="$LITERALS" \
    "$CONSOLE_IMAGE" "$@" </dev/null
}

docker network create "$TAG" </dev/null >/dev/null

echo "== fixtures are clean?"
console scan /fixtures || { echo "scan found leftovers: not replaying" >&2; exit 2; }

echo "== starting a throwaway PHP console ($PHP_IMAGE), empty /data, no ID server"
mkdir -p "$WORK/data"
docker run -d --name "$TAG-php" --network "$TAG" -v "$WORK/data:/data" \
  -e CORTENDESK_EMBEDDED_SERVER=false -e APP_ENV=production -e APP_DEBUG=false \
  "$PHP_IMAGE" </dev/null >/dev/null

for _ in $(seq 1 60); do
  if docker exec "$TAG-php" wget -q -O /dev/null http://127.0.0.1:8080/health/live </dev/null 2>/dev/null; then break; fi
  sleep 2
done
docker exec "$TAG-php" wget -q -O /dev/null http://127.0.0.1:8080/health/live </dev/null || { echo "PHP console did not start" >&2; docker logs "$TAG-php" </dev/null 2>&1 | tail -20 >&2; exit 2; }

echo "== seeding the database with placeholders"
console seed-sql /fixtures > "$WORK/seed.sql"
docker cp "$WORK/seed.sql" "$TAG-php:/tmp/seed.sql" </dev/null
docker exec -u www-data "$TAG-php" php -r '$d = new PDO("sqlite:/data/cortendesk.sqlite"); $d->exec(file_get_contents("/tmp/seed.sql")); echo "seeded\n";' </dev/null

echo "== replaying"
set +e
console replay /fixtures "http://$TAG-php:8080"
status=$?
set -e
exit "$status"
