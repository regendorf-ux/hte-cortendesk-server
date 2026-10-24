#!/usr/bin/env bash
# Replay recorded fixtures against the PHP console AND against hte-console's native device endpoints, each in a
# THROWAWAY container on its own copy of the same placeholder database, and report differences: in the answers
# (each side against the fixtures) and in the database each side leaves behind (PHP's against hte-console's).
# Touches nothing that runs: its own network, its own containers, a temp directory. Runs on the VPS (docker only,
# no Rust) or in CI.
#
#   HTE_CONSOLE_IMAGE=<hte-console image>  HTE_CONSOLE_SANITISE_SALT=<same salt as the capture> \
#     replay.sh <fixtures-dir> [<more-fixtures-dir> ...]   (a directory may also hold *.sql: extra seed)
#
# Several directories are merged (captured first or synthetic first: files replay in name order, and
# synthetic ones are named to sort before captured ones). After the real runs it replays a copy with one
# expected answer changed and insists that this run FAILS: a replay that cannot see a difference is worthless.
# HTE_REPLAY_NATIVE=0 skips the hte-console half (phase 0 behaviour: PHP only). The replay is paced below the
# console's rate limit (110 a minute per address and device; HTE_CONSOLE_REPLAY_PER_MINUTE), so hours of captured
# heartbeats take a few minutes per side.
# Exit 0 = no differences anywhere and the check caught the change, 1 = differences (printed), 2 = could not run.
# Every docker command reads </dev/null so the script can also be piped through `ssh host 'bash -s'`.
set -euo pipefail

[ "$#" -ge 1 ] || { echo "usage: replay.sh <fixtures-dir> [...]" >&2; exit 2; }
CONSOLE_IMAGE="${HTE_CONSOLE_IMAGE:?set HTE_CONSOLE_IMAGE}"
PHP_IMAGE="${HTE_PHP_IMAGE:-ghcr.io/regendorf-ux/hte-cortendesk:1.15.0-hte.1}"
SALT="${HTE_CONSOLE_SANITISE_SALT:-}"
LITERALS="${HTE_CONSOLE_SANITISE_LITERALS:-}"
NATIVE="${HTE_REPLAY_NATIVE:-1}"
# A fixed subnet and a fixed address for the replaying container: the address both consoles record when a
# fixture carries no X-Forwarded-For must be the same on both sides. 10/8 is a trusted proxy range on both.
SUBNET="${HTE_REPLAY_SUBNET:-10.213.77.0/24}"
CLIENT_IP="${HTE_REPLAY_CLIENT_IP:-10.213.77.250}"
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
  docker rm -f "$TAG-php" "$TAG-rust" </dev/null >/dev/null 2>&1 || true
  docker network rm "$TAG" </dev/null >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

console() { # run one hte-console subcommand with $FIXTURES mounted read-only, from the fixed client address
  docker run --rm --network "$TAG" --ip "$CLIENT_IP" -v "$FIXTURES:/fixtures:ro" \
    -e HTE_CONSOLE_SANITISE_SALT="$SALT" -e HTE_CONSOLE_SANITISE_LITERALS="$LITERALS" \
    "$CONSOLE_IMAGE" "$@" </dev/null
}

snapshot() { # snapshot <data-dir> > file: the database in that directory as comparable text
  docker run --rm --network none -v "$1:/data" "$CONSOLE_IMAGE" snapshot /data/cortendesk.sqlite </dev/null
}

summary() { # one line per endpoint and kind: how many fixtures, how many matched, how many differ
  echo "== per kind ($2)"
  printf '%-10s %-10s %6s %6s %6s\n' endpoint kind total match differ
  for ep in heartbeat sysinfo audit version; do
    for kind in captured synthetic; do
      if [ "$kind" = synthetic ]; then pat='^0000000000000-'; else pat='^[1-9]'; fi
      total="$(ls "$FIXTURES" | grep -E "$pat" | grep -c "api_${ep}" || true)"
      differ="$(grep -E '^[0-9]{13}-[0-9]{6}-.*\.json: ' "$1" | cut -d: -f1 | sort -u | grep -E "$pat" | grep -c "api_${ep}" || true)"
      [ "$total" -gt 0 ] || continue
      printf '%-10s %-10s %6s %6s %6s\n' "$ep" "$kind" "$total" "$((total - differ))" "$differ"
    done
  done
}

wait_for() { # wait_for <container> <url>: up to two minutes
  for _ in $(seq 1 60); do
    if docker exec "$1" wget -q -O /dev/null "$2" </dev/null 2>/dev/null; then return 0; fi
    sleep 2
  done
  echo "$1 did not start" >&2
  docker logs "$1" </dev/null 2>&1 | tail -20 >&2
  return 1
}

docker network create --subnet "$SUBNET" "$TAG" </dev/null >/dev/null || { echo "cannot create network $SUBNET (set HTE_REPLAY_SUBNET)" >&2; exit 2; }

echo "== fixtures are clean?"
console scan /fixtures || { echo "scan found leftovers: not replaying" >&2; exit 2; }

echo "== starting a throwaway PHP console ($PHP_IMAGE), empty /data, no ID server, no scheduler"
mkdir -p "$WORK/data"
chmod 777 "$WORK" "$WORK/data" </dev/null   # throwaway: the PHP user must be able to write beside the database
# The image's own supervisord.conf without [program:scheduler]: only the replayed requests write the database.
docker run --rm --entrypoint cat "$PHP_IMAGE" /etc/supervisord.conf </dev/null \
  | awk '/^\[program:scheduler\]/{skip=1; next} /^\[/{skip=0} !skip' > "$WORK/supervisord.conf"
grep -q '^\[program:php-fpm\]' "$WORK/supervisord.conf" || { echo "unexpected supervisord.conf in $PHP_IMAGE" >&2; exit 2; }
docker run -d --name "$TAG-php" --network "$TAG" -v "$WORK/data:/data" -v "$WORK/supervisord.conf:/etc/supervisord.conf:ro" \
  -e CORTENDESK_EMBEDDED_SERVER=false -e APP_ENV=production -e APP_DEBUG=false \
  "$PHP_IMAGE" </dev/null >/dev/null
wait_for "$TAG-php" http://127.0.0.1:8080/health/live || exit 2

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

# One seeded database, two copies: PHP replays on the original, hte-console on the copy (VACUUM INTO is consistent).
docker exec -u www-data "$TAG-php" php -r '$d = new PDO("sqlite:/data/cortendesk.sqlite"); $d->exec("VACUUM INTO \"/data/seeded.sqlite\""); echo "snapshot taken\n";' </dev/null

echo "== replaying against PHP"
set +e
console replay /fixtures "http://$TAG-php:8080" > "$WORK/replay.out"
status=$?
set -e
cat "$WORK/replay.out"
summary "$WORK/replay.out" "PHP"

rust_status=0
db_status=0
if [ "$NATIVE" != 0 ]; then
  echo "== starting hte-console with native device endpoints on a copy of the seeded database"
  mkdir -p "$WORK/rdata"
  # through docker: the key is mode 600 for the PHP user, which the user running this script may not be
  docker cp "$TAG-php:/data/seeded.sqlite" "$WORK/rdata/cortendesk.sqlite" </dev/null
  docker cp "$TAG-php:/data/.app_key" "$WORK/rdata/.app_key" </dev/null
  chmod 777 "$WORK/rdata" </dev/null
  docker run -d --name "$TAG-rust" --network "$TAG" -v "$WORK/rdata:/data" \
    -e HTE_CONSOLE_DATABASE=/data/cortendesk.sqlite -e HTE_CONSOLE_LISTEN=0.0.0.0:8080 \
    "$CONSOLE_IMAGE" serve </dev/null >/dev/null
  wait_for "$TAG-rust" http://127.0.0.1:8080/__hte-console/health || exit 2

  echo "== replaying against hte-console"
  set +e
  console replay /fixtures "http://$TAG-rust:8080" > "$WORK/replay-rust.out"
  rust_status=$?
  set -e
  cat "$WORK/replay-rust.out"
  summary "$WORK/replay-rust.out" "hte-console"
  docker stop -t 20 "$TAG-rust" </dev/null >/dev/null   # SIGTERM: hte-console closes the database cleanly

  echo "== the database after the replay: PHP's against hte-console's"
  snapshot "$WORK/data" > "$WORK/php.snapshot"
  snapshot "$WORK/rdata" > "$WORK/rust.snapshot"
  grep -E '^[a-z_]+: [0-9]+ rows$' "$WORK/php.snapshot" | grep -vE ': 0 rows$' | tr '\n' ' '; echo
  if diff -u "$WORK/php.snapshot" "$WORK/rust.snapshot" > "$WORK/db.diff"; then
    echo "databases: identical (timestamps, guids, ciphertexts and strategy_version masked)"
  else
    db_status=1
    echo "databases DIFFER (- PHP, + hte-console):"
    head -100 "$WORK/db.diff"
  fi
fi

echo "== proving the replay notices a change (this run must report a difference)"
# Only the changed fixture is replayed: enough to prove a difference is seen, without another paced full run.
mkdir -p "$WORK/tampered"
# a glob, not ls | grep -m1: under pipefail grep's early exit fails ls and the fallback ran too (two names)
victim=""
for f in "$FIXTURES"/*api_sysinfo-new-device*.json "$FIXTURES"/*.json; do
  if [ -f "$f" ]; then victim="$(basename "$f")"; break; fi
done
[ -n "$victim" ] || { echo "no fixture to tamper with" >&2; exit 2; }
cp -p "$FIXTURES/$victim" "$WORK/tampered/" </dev/null
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

echo "== result: PHP answers $([ "$status" = 0 ] && echo match || echo DIFFER)$([ "$NATIVE" != 0 ] && echo ", hte-console answers $([ "$rust_status" = 0 ] && echo match || echo DIFFER), databases $([ "$db_status" = 0 ] && echo identical || echo DIFFER)")"
[ "$status" = 0 ] && [ "$rust_status" = 0 ] && [ "$db_status" = 0 ] || exit 1
exit 0
