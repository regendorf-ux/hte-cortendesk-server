#!/usr/bin/env bash
# Replay recorded fixtures against the PHP console in a THROWAWAY container with a database of placeholders,
# and report differences. Touches nothing that runs: its own network, its own containers, a temp directory.
# Runs on the VPS (docker only, no Rust) or in CI.
#
#   HTE_CONSOLE_IMAGE=<hte-console image>  HTE_CONSOLE_SANITISE_SALT=<same salt as the capture> \
#     replay.sh <fixtures-dir> [<more-fixtures-dir> ...]   (a directory may also hold *.sql: extra seed)
#
# Several directories are merged (captured first or synthetic first: files replay in name order, and
# synthetic ones are named to sort before captured ones). After the real run it replays a copy with one
# expected answer changed and insists that this run FAILS: a replay that cannot see a difference is worthless.
# Exit 0 = no differences and the check caught the change, 1 = differences (printed), 2 = could not run.
# Every docker command reads </dev/null so the script can also be piped through `ssh host 'bash -s'`.
set -euo pipefail

[ "$#" -ge 1 ] || { echo "usage: replay.sh <fixtures-dir> [...]" >&2; exit 2; }
CONSOLE_IMAGE="${HTE_CONSOLE_IMAGE:?set HTE_CONSOLE_IMAGE}"
PHP_IMAGE="${HTE_PHP_IMAGE:-ghcr.io/regendorf-ux/hte-cortendesk:1.15.0-hte.1}"
SALT="${HTE_CONSOLE_SANITISE_SALT:-}"
LITERALS="${HTE_CONSOLE_SANITISE_LITERALS:-}"
TAG="hte-replay-$$"
WORK="$(mktemp -d)"
FIXTURES="$WORK/fixtures"
mkdir -p "$FIXTURES"
mkdir -p "$WORK/sql"
for d in "$@"; do
  find "$d" -maxdepth 1 -name '*.json' -exec cp -p {} "$FIXTURES"/ \; </dev/null
  find "$d" -maxdepth 1 -name '*.sql' -exec cp -p {} "$WORK/sql"/ \; </dev/null   # extra seed, applied in name order
done

cleanup() {
  docker rm -f "$TAG-php" </dev/null >/dev/null 2>&1 || true
  docker network rm "$TAG" </dev/null >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

console() { # run one hte-console subcommand with $FIXTURES mounted read-only
  docker run --rm --network "$TAG" -v "$FIXTURES:/fixtures:ro" \
    -e HTE_CONSOLE_SANITISE_SALT="$SALT" -e HTE_CONSOLE_SANITISE_LITERALS="$LITERALS" \
    "$CONSOLE_IMAGE" "$@" </dev/null
}

summary() { # one line per endpoint and kind: how many fixtures, how many matched, how many differ
  echo "== per kind"
  printf '%-10s %-10s %6s %6s %6s\n' endpoint kind total match differ
  for ep in heartbeat sysinfo audit; do
    for kind in captured synthetic; do
      if [ "$kind" = synthetic ]; then pat='^0000000000000-'; else pat='^[1-9]'; fi
      total="$(ls "$FIXTURES" | grep -E "$pat" | grep -c "api_${ep}" || true)"
      differ="$(grep -E '^[0-9]{13}-[0-9]{6}-.*\.json: ' "$1" | cut -d: -f1 | sort -u | grep -E "$pat" | grep -c "api_${ep}" || true)"
      [ "$total" -gt 0 ] || continue
      printf '%-10s %-10s %6s %6s %6s\n' "$ep" "$kind" "$total" "$((total - differ))" "$differ"
    done
  done
}

docker network create "$TAG" </dev/null >/dev/null

echo "== fixtures are clean?"
console scan /fixtures || { echo "scan found leftovers: not replaying" >&2; exit 2; }

echo "== starting a throwaway PHP console ($PHP_IMAGE), empty /data, no ID server"
mkdir -p "$WORK/data"
chmod 777 "$WORK" "$WORK/data" </dev/null   # throwaway: the PHP user must be able to write beside the database
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

# The strategy the captured answers imply: any heartbeat answer that carries strategy.config_options means
# the device was under a policy. Seed one default, enforcing strategy with exactly those options.
python3 - "$FIXTURES" > "$WORK/sql/00-strategy-from-fixtures.sql" <<'PY'
import glob, json, sys
opts = None
for f in sorted(glob.glob(sys.argv[1] + "/*.json")):
    fx = json.load(open(f))
    v = fx.get("response", {}).get("body", {}).get("value")
    if isinstance(v, dict) and isinstance(v.get("strategy"), dict) and v["strategy"].get("config_options"):
        opts = v["strategy"]["config_options"]
        break
if opts:
    o = json.dumps(opts).replace("'", "''")
    print("INSERT INTO strategies (name, enabled, is_default, enforce, options, created_at, updated_at) "
          f"VALUES ('text-seed0001', 1, 1, 1, '{o}', datetime('now'), datetime('now'));")
    print("UPDATE devices SET strategy_id_resolved = (SELECT id FROM strategies WHERE name = 'text-seed0001');")
PY

for f in "$WORK"/sql/*.sql; do
  [ -s "$f" ] || continue
  docker cp "$f" "$TAG-php:/tmp/extra.sql" </dev/null
  docker exec -u www-data "$TAG-php" php -r '$d = new PDO("sqlite:/data/cortendesk.sqlite"); $d->exec(file_get_contents("/tmp/extra.sql")); echo "extra seed ok\n";' </dev/null
done

echo "== replaying"
set +e
console replay /fixtures "http://$TAG-php:8080" > "$WORK/replay.out"
status=$?
set -e
cat "$WORK/replay.out"
summary "$WORK/replay.out"

echo "== proving the replay notices a change (this run must report a difference)"
cp -a "$FIXTURES" "$WORK/tampered" </dev/null
victim="$(ls "$WORK/tampered" </dev/null | grep -m1 'api_sysinfo-new-device' || ls "$WORK/tampered" </dev/null | head -1)"
sed -i 's/SYSINFO_UPDATED/SYSINFO_TAMPERED/; s/"status": 200/"status": 418/' "$WORK/tampered/$victim" </dev/null
saved="$FIXTURES"; FIXTURES="$WORK/tampered"
set +e
console replay /fixtures "http://$TAG-php:8080" > "$WORK/tamper.out"
caught=$?
set -e
head -5 "$WORK/tamper.out"
FIXTURES="$saved"
if [ "$caught" -ne 1 ]; then echo "THE REPLAY DID NOT NOTICE A CHANGED FIXTURE" >&2; exit 2; fi
echo "caught, as it should"
exit "$status"
