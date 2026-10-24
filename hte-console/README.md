# hte-console

HTE Remote's console, step by step in Rust (plan: `PHPLESS-PLAN.md` in HTE's private notes). Changes: `CHANGES.md`.

- **Phase 0, a shadow proxy.** In front of the PHP console: forwards every request, returns PHP's answer unchanged,
  records sanitised fixtures.
- **Phase 1, the device endpoints answered here** (0.1.0). `POST /api/heartbeat`, `/api/sysinfo`, `/api/audit/conn`,
  `/api/audit/file`, `/api/audit/alarm` and `GET /api/version`, ported line by line from the PHP console 1.15.0-hte.1
  onto the same SQLite file (no schema change; PHP keeps owning the schema). Everything else is still forwarded to
  PHP. The device endpoints are unauthenticated: bodies are capped (1 MiB), input is parsed with PHP's own rules
  and bad input gets PHP's own answer (see "What a bad request gets" below), nothing panics on input, SQL is never
  built from input, and no secret (app key, passwords, tokens) is logged.

```
hte-console serve                       # serve; with HTE_CONSOLE_DATABASE the device endpoints are native
hte-console scan <dir>                  # fail if a fixture holds anything real
hte-console seed-sql <dir>              # SQL (placeholders only) for a replay database
hte-console replay <dir> <base-url>     # replay and report differences (exit 1 when any)
hte-console snapshot <sqlite>           # the database as comparable text (PHP's state vs ours)
replay/replay.sh <dir>                  # all of that against throwaway PHP and hte-console containers
```

Environment (nothing HTE-specific is in this repository):

| Variable | Meaning |
|---|---|
| `HTE_CONSOLE_UPSTREAM` | the PHP console's URL (required without `HTE_CONSOLE_DATABASE`; with it, the rest is forwarded there, or 404 when unset) |
| `HTE_CONSOLE_LISTEN` | default `0.0.0.0:8080` |
| `HTE_CONSOLE_FIXTURES` | directory for fixtures; unset = forward only |
| `HTE_CONSOLE_CAPTURE_PREFIXES` | recorded path prefixes, default `/api/` |
| `HTE_CONSOLE_CAPTURE_MAX_BYTES` | default 262144 |
| `HTE_CONSOLE_SANITISE_SALT` | key of the placeholders (keep it the same between capture and replay) |
| `HTE_CONSOLE_SANITISE_LITERALS` | comma list of host names and domains always replaced |
| `HTE_CONSOLE_CONNECT_TIMEOUT_SECS`, `HTE_CONSOLE_REQUEST_TIMEOUT_SECS` | defaults 3 and 60 |
| **Phase 1** | |
| `HTE_CONSOLE_DATABASE` | the PHP console's SQLite file (`/data/cortendesk.sqlite`); setting it turns the device endpoints on |
| `APP_KEY` or `HTE_CONSOLE_APP_KEY_FILE` | Laravel's app key, as the PHP image reads it (env first, else `/data/.app_key`) |
| `HTE_CONSOLE_HBBS_DB` | hbbs's database for device keys, read only; default `/data/rustdesk/db_v2.sqlite3` |
| `HTE_CONSOLE_TRUSTED_PROXIES` | else `TRUSTED_PROXIES`, else PHP's default `127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`. Read as PHP reads it: addresses and ranges, `*` alone (every peer), `REMOTE_ADDR` (the request's own peer), `PRIVATE_SUBNETS` (Symfony's list); other entries trust nothing and are named in a warning at start |
| `HTE_CONSOLE_API_VERSION` | what `/api/version` says; else `CORTENDESK_API_VERSION`, else `1.15.0-hte.1` |
| `HTE_CONSOLE_DEVICE_MAX_BODY_BYTES` | default 1048576 |
| `HTE_CONSOLE_DB_BUSY_MS` | how long a write waits for PHP's lock, default 10000 |
| `HTE_CONSOLE_DB_WAL` | default 1: switch the file to WAL once (persistent; PHP needs no change) |

Run it as the user that owns the database file (compose `user:`), or as root: SQLite creates its `-wal`/`-shm`
files with the creating process's owner, and files PHP cannot write would break PHP. `serve` refuses to start
otherwise.

Health: `GET /__hte-console/health`. Upstream down: 502; too slow: 504. Fixture rules: `SANITISER.md`.
Build: `.github/workflows/hte-console.yml` on a tag `hte-console-v<version>` (cross, static musl).

## How the port is written

`src/php.rs` and `src/laravel.rs` reproduce what decides the answers: PHP's `json_decode`, casts, `base64_decode`,
`json_encode`; Laravel's input bag (TrimStrings, ConvertEmptyStringsToNull, JSON vs form vs query), Symfony's client
address behind trusted proxies, `Crypt`, Eloquent's dirty-only updates. `sync.rs`, `audit.rs`, `strategy.rs` and
`passwords.rs` follow the PHP methods of the same names statement by statement; `api.rs` is the HTTP side (the
`device-sync` rate limit, 405/OPTIONS/CORS, error bodies). `sqlite.rs` binds values with PDO's types so SQLite stores
what PHP would.

## What a bad request gets (as PHP)

| Input | Answer |
|---|---|
| invalid JSON, JSON nested deeper than 512, a body that is not `application/json` or a form | treated as no input: heartbeat `{}`, sysinfo `ID_NOT_FOUND`, audit `""` |
| an array where PHP casts to a string (`id`, `uuid`, sysinfo fields, file `info`) | 500 `{"message":"Server Error"}` (PHP's "Array to string conversion" becomes an exception) |
| the same inside an audit write (`ip`, `peer`, `path`, ...) | 500 `{"error":"Audit record not stored"}`, nonce forgotten so the retry stores |
| wrong method | 405 `{"message":"The GET method is not supported for route api/heartbeat. Supported methods: POST."}` |
| more than 120 posts a minute per device and address (6000 per address) | 429 `{"message":"Too Many Attempts."}` with `Retry-After` |
| a body over 1 MiB | 413 `{"message":"The POST data is too large."}` (PHP's own limit is higher; no device sends more than a few KB) |

Known differences, none visible to a RustDesk client: multipart bodies are not parsed (PHP would read their fields);
Apprise notifications (device online, pending approval, alarms) are not sent (HTE has Apprise off; `serve` warns at
start when `apprise_enabled` is 1); rate limits and audit nonces live in this process's memory (PHP keeps them in its
file cache), so a restart forgets them, as a PHP container restart does, and under a flood of more than 100 000
limiter keys (250 000 nonces) in one window the oldest are forgotten early instead of memory growing.

Known differences that depend on configuration HTE does not use:

- An empty `TRUSTED_PROXIES` (set, but to nothing) means PHP's default list here; PHP itself would then trust no
  proxy and record every device at Caddy's address. Leave it unset, or set it to the list wanted.
- Laravel's `APP_PREVIOUS_KEYS` is not read: after an `APP_KEY` rotation that keeps the old key there, PHP still opens
  passwords encrypted with the old key, hte-console answers those heartbeats with a 500. Rotate the key with PHP
  answering the device endpoints (phase 1 rollback), or re-encrypt first.
- The older offline marker in PHP's file cache (`apprise:device-offline:<sha1 of id>`, from before the
  `device_presence_notification_states` table) is not consulted when a device comes back; only the table row is.
  It only matters for Apprise offline alerts, which HTE does not send.
