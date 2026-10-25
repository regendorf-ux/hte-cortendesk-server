#!/usr/bin/env bash
# Replay recorded fixtures against the PHP console AND against hte-console's native device endpoints, each in a
# THROWAWAY container on its own copy of the same placeholder database, and report differences: in the answers
# (each side against the fixtures) and in the database each side leaves behind (PHP's against hte-console's).
# Touches nothing that runs: its own network, its own containers, a temp directory. Runs on the server (docker only,
# no Rust) or in CI.
#
#   HTE_CONSOLE_IMAGE=<hte-console image>  HTE_CONSOLE_SANITISE_SALT=<same salt as the capture> \
#     replay.sh <fixtures-dir> [<more-fixtures-dir> ...]   (a directory may also hold *.sql: extra seed)
#
# Several directories are merged (captured first or synthetic first: files replay in name order, and
# synthetic ones are named to sort before captured ones). After the real runs it replays a copy with one
# expected answer changed and insists that this run FAILS: a replay that cannot see a difference is worthless.
# HTE_REPLAY_NATIVE=0 skips the hte-console half (phase 0 behaviour: PHP only). Phase 2: a fake identity provider
# (`hte-console fake-idp`, TEST ONLY) runs beside them on the same throwaway network, and a seed file may carry
# @@IDP@@ and @@ENCRYPT(...)@@ markers (filled in with that provider's URL and the throwaway database's app key);
# fixtures/signin holds the synthetic sign-in fixtures (nothing of sign-in is ever captured); phase 4: fixtures/clientapi
# holds the synthetic client-API fixtures (address books, group tab, server-config, audit note) and its own seed
# (run it as `replay.sh fixtures/clientapi` alone: its lists assume only its own people and computers). The replay is paced below the
# console's rate limit (110 a minute per address and device; HTE_CONSOLE_REPLAY_PER_MINUTE), so hours of captured
# heartbeats take a few minutes per side.
# Phase 3: both consoles get the server link secret (a placeholder) and Laravel's database cache store (as the server
# runs once phase 3 is deployed); fixtures/serverlink holds the ID server's calls; after the replay the two consoles'
# policies are compared with each other (sign-in tokens minted at random reduced to the devices they map to). A
# directory holding `sweeps.plan` (fixtures/sweeps) is a scenario for the scheduled jobs: its steps run on PHP's
# database with PHP's own artisan commands and on hte-console's copy with `hte-console sweep`, then the two databases
# are compared again.
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
SWEEPS_DIR=""
for d in "$@"; do
  if [ -f "$d/sweeps.plan" ]; then SWEEPS_DIR="$d"; continue; fi   # phase 3: a scenario, not fixtures or seed
  find "$d" -maxdepth 1 -name '*.json' -exec cp -p {} "$FIXTURES"/ \; </dev/null
  find "$d" -maxdepth 1 -name '*.sql' -exec cp -p {} "$WORK/sql"/ \; </dev/null   # extra seed, applied in name order
done

IDP_SECRET="tok-5eed00000000c11e"   # the seed's oidc_client_secret (a placeholder, for the fake provider only)
LINK_SECRET="tok-5eed00000003c0de"  # the server link secret fixtures/serverlink present (a placeholder)

cleanup() {
  docker rm -f "$TAG-php" "$TAG-rust" "$TAG-idp" </dev/null >/dev/null 2>&1 || true
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
  for ep in heartbeat sysinfo audit version login-options login currentUser logout oidc_auth oidc_auth-query client_callback server_policy server_local-addrs server_refusals ab server-config device-group users peers webclient-config; do
    for kind in captured synthetic; do
      if [ "$kind" = synthetic ]; then pat='^000000000000[0-9]-'; else pat='^[1-9]'; fi
      # file names end the path slug with "-" (synthetic) or ".json" (captured); audit/* share one line
      slug="$(echo "$ep" | tr '-' '_')"
      case "$slug" in client_callback) m="-login_oidc_client_callback[-.]";; audit) m="-api_audit[_-]";; ab) m="-api_ab[_-]";; webclient_config) m="-webclient_config_index_js[-.]";; *) m="-api_${slug}[-.]";; esac
      total="$(ls "$FIXTURES" | grep -E "$pat" | grep -c -- "$m" || true)"
      differ="$(grep -E '^[0-9]{13}-[0-9]{6}-.*\.json: ' "$1" | cut -d: -f1 | sort -u | grep -E "$pat" | grep -c -- "$m" || true)"
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
  -e CORTENDESK_SERVER_SECRET="$LINK_SECRET" -e CACHE_STORE=database \
  "$PHP_IMAGE" </dev/null >/dev/null
wait_for "$TAG-php" http://127.0.0.1:8080/health/live || exit 2
# phase 3: PHP's cache prefix, for hte-console to write the cache rows PHP reads
CACHE_PREFIX="$(docker exec -u www-data -w /app "$TAG-php" php artisan tinker --execute='echo config("cache.prefix");' </dev/null | tr -d '\r\n')" \
  || { echo "could not ask PHP for its cache prefix" >&2; exit 2; }
[ -n "$CACHE_PREFIX" ] || { echo "could not read PHP's cache prefix" >&2; exit 2; }

echo "== starting the fake identity provider (TEST ONLY) for the sign-in fixtures"
docker run -d --name "$TAG-idp" --network "$TAG" \
  -e HTE_FAKE_IDP_ISSUER="http://$TAG-idp:8080" -e HTE_FAKE_IDP_CLIENT_SECRET="$IDP_SECRET" \
  "$CONSOLE_IMAGE" fake-idp </dev/null >/dev/null
wait_for "$TAG-idp" http://127.0.0.1:8080/__fake-idp/health || exit 2

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

# the throwaway database's app key, for @@ENCRYPT(...)@@ (through docker: mode 600 for the PHP user)
docker cp "$TAG-php:/data/.app_key" "$WORK/app_key" </dev/null
chmod 644 "$WORK/app_key" </dev/null
for f in "$WORK"/sql/*.sql; do
  [ -s "$f" ] || continue
  if grep -q '@@' "$f" </dev/null; then
    docker run --rm --network none -v "$WORK/sql:/sql:ro" -v "$WORK/app_key:/app_key:ro" -e HTE_CONSOLE_APP_KEY_FILE=/app_key \
      "$CONSOLE_IMAGE" seed-expand "/sql/$(basename "$f")" "http://$TAG-idp:8080" </dev/null > "$f.expanded"
    mv "$f.expanded" "$f"
  fi
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
  # HTE_CONSOLE_OIDC_ALLOW_HTTP: the fake provider speaks plain HTTP inside this throwaway network (never set it
  # on the server); no HTE_CONSOLE_PUBLIC_URL here, so the redirect URI is built from the Host header as PHP does
  docker run -d --name "$TAG-rust" --network "$TAG" -v "$WORK/rdata:/data" \
    -e HTE_CONSOLE_DATABASE=/data/cortendesk.sqlite -e HTE_CONSOLE_LISTEN=0.0.0.0:8080 -e HTE_CONSOLE_OIDC_ALLOW_HTTP=1 \
    -e CORTENDESK_SERVER_SECRET="$LINK_SECRET" -e HTE_CONSOLE_CACHE_PREFIX="$CACHE_PREFIX" \
    "$CONSOLE_IMAGE" serve </dev/null >/dev/null
  wait_for "$TAG-rust" http://127.0.0.1:8080/__hte-console/health || exit 2

  echo "== replaying against hte-console"
  set +e
  console replay /fixtures "http://$TAG-rust:8080" > "$WORK/replay-rust.out"
  rust_status=$?
  set -e
  cat "$WORK/replay-rust.out"
  summary "$WORK/replay-rust.out" "hte-console"

  echo "== the policy the ID server gets: PHP's against hte-console's"
  for side in php rust; do
    docker exec "$TAG-$side" wget -q -O - --header "Authorization: Bearer $LINK_SECRET" --header "User-Agent: hte-replay" \
      http://127.0.0.1:8080/api/server/policy </dev/null > "$WORK/policy-$side.json" || { echo "no policy from $side" >&2; exit 2; }
  done
  # sign-in tokens are minted at random on each side: a token both sides hold is compared exactly (hash -> device,
  # hash -> person); the ones only one side holds are reduced to the devices and people they map to
  python3 - "$WORK" <<'PY' || { echo "a policy is not JSON" >&2; exit 1; }
import json, sys
w = sys.argv[1]
php, rust = (json.load(open(f"{w}/policy-{s}.json")) for s in ("php", "rust"))
def norm(p, other):
    for path in (("tokens",), ("scope", "token_users")):
        mine, theirs = p, other
        for k in path[:-1]:
            mine, theirs = mine[k], theirs[k]
        m, t = mine[path[-1]], theirs[path[-1]]
        mine[path[-1]] = {"both": {k: v for k, v in m.items() if k in t}, "only": sorted(v for k, v in m.items() if k not in t)}
    return p
a, b = norm(json.loads(json.dumps(php)), rust), norm(json.loads(json.dumps(rust)), php)
for name, p in (("php", a), ("rust", b)):
    open(f"{w}/policy-{name}.norm", "w").write(json.dumps(p, indent=1))
PY
  policy_status=0
  if diff -u "$WORK/policy-php.norm" "$WORK/policy-rust.norm" > "$WORK/policy.diff"; then
    echo "policies: identical ($(python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); print(len(p["allow"]), "allowed,", len(p["incoming_only"]), "incoming only,", len(p["tokens"]), "tokens, scope", "on" if p["scope"]["enforce"] else "off", "with", len(p["scope"]["users"]), "people")' "$WORK/policy-php.json" </dev/null))"
  else
    policy_status=1
    echo "policies DIFFER (- PHP, + hte-console):"
    head -60 "$WORK/policy.diff"
  fi
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

  sweep_status=0
  if [ -n "$SWEEPS_DIR" ]; then
    echo "== the scheduled jobs: PHP's artisan commands against hte-console's sweeps ($(basename "$SWEEPS_DIR"))"
    mkdir -p "$WORK/steps"
    cp -p "$SWEEPS_DIR"/*.sql "$WORK/steps"/ </dev/null
    for f in "$WORK"/steps/*.sql; do
      if grep -q '@@' "$f" </dev/null; then
        docker run --rm --network none -v "$WORK/steps:/sql:ro" -v "$WORK/app_key:/app_key:ro" -e HTE_CONSOLE_APP_KEY_FILE=/app_key \
          "$CONSOLE_IMAGE" seed-expand "/sql/$(basename "$f")" "http://$TAG-idp:8080" </dev/null > "$f.expanded"
        mv "$f.expanded" "$f"
      fi
    done
    artisan_of() { case "$1" in reach) echo hte:reach-sweep;; passwords) echo hte:passwords;; stale) echo cortendesk:close-stale-sessions;; diagnostics) echo cortendesk:diagnostics-heartbeat;; *) echo "unknown job $1" >&2; return 1;; esac; }
    while read -r verb rest; do
      case "$verb" in ''|'#'*) continue;; esac
      case "$verb" in
        sql)
          docker cp "$WORK/steps/$rest" "$TAG-php:/tmp/step.sql" </dev/null
          docker exec -u www-data "$TAG-php" php -r '$d = new PDO("sqlite:/data/cortendesk.sqlite"); $d->exec(file_get_contents("/tmp/step.sql"));' </dev/null \
            || { echo "step $rest failed on PHP's database" >&2; exit 2; }
          docker run --rm --network none -v "$WORK/rdata:/data" -v "$WORK/steps:/steps:ro" "$CONSOLE_IMAGE" sql-apply /data/cortendesk.sqlite "/steps/$rest" </dev/null >/dev/null \
            || { echo "step $rest failed on hte-console's database" >&2; exit 2; }
          echo "  $rest";;
        sweep)
          for job in $rest; do
            docker exec -u www-data -w /app "$TAG-php" php artisan "$(artisan_of "$job")" --no-interaction </dev/null | sed 's/^/  php: /'
          done
          docker run --rm --network none -v "$WORK/rdata:/data" -e HTE_CONSOLE_DATABASE=/data/cortendesk.sqlite \
            -e HTE_CONSOLE_CACHE_PREFIX="$CACHE_PREFIX" "$CONSOLE_IMAGE" sweep $rest </dev/null | sed 's/^/  hte-console: /';;
        *) echo "sweeps.plan: unknown step $verb" >&2; exit 2;;
      esac
    done < "$SWEEPS_DIR/sweeps.plan"
    snapshot "$WORK/data" > "$WORK/php-sweeps.snapshot"
    snapshot "$WORK/rdata" > "$WORK/rust-sweeps.snapshot"
    grep -E '^(alarm_logs|audit_connections|console_audits|hte_device_passwords|address_books|address_book_entries|address_book_rules|hte_auto_books|cache): [0-9]+ rows$' "$WORK/php-sweeps.snapshot" | tr '\n' ' '; echo
    if diff -u "$WORK/php-sweeps.snapshot" "$WORK/rust-sweeps.snapshot" > "$WORK/sweeps.diff"; then
      echo "databases after the sweeps: identical"
    else
      sweep_status=1
      echo "databases after the sweeps DIFFER (- PHP, + hte-console):"
      head -100 "$WORK/sweeps.diff"
    fi
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
sed -i 's/SYSINFO_UPDATED/SYSINFO_TAMPERED/; s/"status": [0-9][0-9]*/"status": 418/' "$WORK/tampered/$victim" </dev/null
saved="$FIXTURES"; FIXTURES="$WORK/tampered"
set +e
console replay /fixtures "http://$TAG-php:8080" > "$WORK/tamper.out"
caught=$?
set -e
head -5 "$WORK/tamper.out"
FIXTURES="$saved"
if [ "$caught" -ne 1 ]; then echo "THE REPLAY DID NOT NOTICE A CHANGED FIXTURE" >&2; exit 2; fi
echo "caught, as it should"

echo "== result: PHP answers $([ "$status" = 0 ] && echo match || echo DIFFER)$([ "$NATIVE" != 0 ] && echo ", hte-console answers $([ "$rust_status" = 0 ] && echo match || echo DIFFER), databases $([ "$db_status" = 0 ] && echo identical || echo DIFFER), policies $([ "${policy_status:-0}" = 0 ] && echo identical || echo DIFFER)$([ -n "$SWEEPS_DIR" ] && echo ", sweeps $([ "${sweep_status:-0}" = 0 ] && echo identical || echo DIFFER)")")"
[ "$status" = 0 ] && [ "$rust_status" = 0 ] && [ "$db_status" = 0 ] && [ "${policy_status:-0}" = 0 ] && [ "${sweep_status:-0}" = 0 ] || exit 1
exit 0
