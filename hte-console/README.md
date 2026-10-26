# hte-console

The console of HTE Remote, in Rust: the web pages, the RustDesk client's and the admin APIs, the link with the ID server
(`hbbs`) and the scheduled jobs. It runs inside the all-in-one image `ghcr.io/regendorf-ux/hte-rd-server` beside `hbbs` and
`hbbr` (repository `README.md`). It works on the SQLite database of CortenDesk's console (1.15 schema, 41 migrations), whose
pages and behaviour it reproduces; it checks that schema at start and only adds tables of its own (`src/migrate.rs`), so the previous console
console can run on the same data again. Changes: `CHANGES.md`. Credits and licences: `NOTICE`.

## What it serves

- **Device endpoints** (unauthenticated, from every client): heartbeat, sysinfo, connection/file/alarm audit, version.
- **Client sign-in and API**: password, two-factor, e-mailed code and OIDC sign-in for the RustDesk client; address books,
  the group tab and "Accessible devices", server config, the audit note; per-computer passwords for devices a person may reach.
- **Server link** for `hbbs`: the device policy with per-person reach (`scope`), local addresses, refusal reports (alarms).
- **Console pages**: dashboard, devices (detail, approval, reach card), users, groups, user groups, strategies, roles, address
  books, logs, API tokens, settings (server, SSO, mail, backups, retention), diagnostics, account (password, two-factor),
  invitations, password reset; the web client (`/webclient`, `/rdclient/*`).
- **Admin API** (`/api/v1/*`, bearer tokens) and `--assign`.
- **Jobs**: reach and password sweeps, stale sessions, diagnostics heartbeat (every minute); backup, log and invitation pruning
  (daily); presence snooze pruning; the release check (daily).
- **Static files**: `/assets/*` (embedded), `/rdclient/*`, `/robots.txt`, `/favicon.ico`, `/health/live`, `/health/ready`.

Not carried over from the previous console: Apprise notifications, live page updates, the client downloads page and setup wizard (a page
says so).

## Command line

`hte-console serve` (default) | `version` | `status` (name=value lines) | `migrate [--check]` | `backup [--no-copy]` |
`restore <archive>` | `release-locks` | `db-copy <dest>` | `sweep` | the replay and fixture tools the tests use (`replay`, `seed-sql`, `page-seed`, `page-replay`, `web-signin-replay`).

## Configuration

The variables most deployments set are in the repository's `README.md`. Every variable hte-console reads:

| Variable | Default | Meaning |
|---|---|---|
| `HTE_CONSOLE_DATABASE` | (image: `/data/cortendesk.sqlite`) | The SQLite database; without it hte-console only proxies (`HTE_CONSOLE_UPSTREAM`) |
| `HTE_CONSOLE_LISTEN` | `0.0.0.0:8080` | Listen address |
| `APP_KEY` / `HTE_CONSOLE_APP_KEY_FILE` | `/data/.app_key` | Laravel-compatible key for encrypted columns and settings |
| `APP_URL`, `HTE_CONSOLE_PUBLIC_URL` | | Public origin; links and the OIDC redirect URI come from it, never from the Host header |
| `APP_NAME` | `HTE Remote` | Titles, mail From name and subjects |
| `HTE_SIGNIN_DOMAIN` | empty | E-mail domain named on the sign-in page |
| `HTE_CONSOLE_TRUSTED_PROXIES` / `TRUSTED_PROXIES` | `127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16` | Proxies whose forwarding headers are believed |
| `HTE_CONSOLE_CACHE_PREFIX` / `CACHE_PREFIX` | slug of `APP_NAME` + `-cache-` | Prefix of cache rows and scheduler locks |
| `HTE_CONSOLE_SIGNIN` | `1` (image) | The console's own sign-in and session (`__Host-hte-remote`) |
| `HTE_CONSOLE_SESSION_COOKIE` | | The previous console's session cookie name, read only while `HTE_CONSOLE_LARAVEL_SESSIONS=1` |
| `HTE_CONSOLE_SESSION_IDLE_MIN`, `HTE_CONSOLE_SESSION_ABSOLUTE_HOURS` | `60`, `12` | Console session lifetime |
| `HTE_CONSOLE_LARAVEL_SESSIONS`, `HTE_CONSOLE_PHP_SESSION_BRIDGE` | `0` (image) | Transition switches for running beside the previous console |
| `HTE_CONSOLE_MIGRATE` | `1` (image) | Check the schema and apply hte-console's own tables at start |
| `HTE_CONSOLE_SWEEPS` | (image: all four) | `reach,passwords,stale,diagnostics` or `all` |
| `HTE_CONSOLE_JOBS` | (image: all three) | `backup,prune-logs,prune-invitations` or `all` |
| `HTE_CONSOLE_SNOOZE_PRUNE` | `1` (image) | Prune expired presence snoozes every minute |
| `HTE_CONSOLE_BACKUPS_DIR` / `HTE_REMOTE_BACKUPS_PATH` | `/data/backups` | Backup archives |
| `HTE_CONSOLE_LOG_RETENTION_DAYS` / `HTE_REMOTE_LOG_RETENTION_DAYS` | `365` | Default log retention (a setting overrides it) |
| `HTE_CONSOLE_HBBS_DB`, `HTE_CONSOLE_RUSTDESK_DIR` | `/data/rustdesk/...` | hbbs's peer database (read only) and key directory |
| `HTE_CONSOLE_ID_SERVER`, `HTE_CONSOLE_RELAY_SERVER`, `HTE_CONSOLE_PUBLIC_KEY` | `HTE_REMOTE_*` | What clients are told when the settings table has none |
| `HTE_REMOTE_SERVER_SECRET` / `HTE_CONSOLE_SERVER_SECRET_FILE` | `/data/.server_secret` | Secret shared with `hbbs` |
| `HTE_CONSOLE_API_VERSION` / `HTE_REMOTE_API_VERSION` | `1.15.0-hte.1` | What `/api/version` answers (the previous console's release the client API matches) |
| `HTE_REMOTE_ONLINE_WINDOW` | `60` | Online window in seconds (a setting overrides it) |
| `HTE_REMOTE_OIDC_DISABLED` | off | SSO kill switch |
| `HTE_REMOTE_UPDATE_CHECK`, `HTE_REMOTE_UPDATE_REPO` | on, `regendorf-ux/hte-rd-server` | The sidebar's release check |
| `HTE_REMOTE_CLIENT_URL_SCHEME`, `HTE_REMOTE_NATIVE_WEBCLIENT`, `HTE_REMOTE_WEBCLIENT_URL`, `HTE_REMOTE_RDGEN_URL`, `HTE_REMOTE_WS_ID_URL`, `HTE_REMOTE_WS_RELAY_URL` | | Client links and web client addresses, as in CortenDesk |
| `BCRYPT_ROUNDS` | `12` | Cost of new password hashes |
| `HTE_CONSOLE_*_MAX_BODY_BYTES`, `HTE_CONSOLE_UPLOAD_MAX_BYTES`, `HTE_CONSOLE_DB_BUSY_MS`, `HTE_CONSOLE_DB_WAL` | | Limits and SQLite tuning (defaults in `src/config.rs`) |
| `HTE_CONSOLE_UPSTREAM`, `HTE_CONSOLE_FIXTURES`, `HTE_CONSOLE_CAPTURE_*`, `HTE_CONSOLE_SANITISE_*`, `HTE_CONSOLE_PAGES` | | Proxy and fixture capture, for running beside the previous console |
| `HTE_CONSOLE_OIDC_ALLOW_HTTP`, `HTE_FAKE_IDP_*`, `HTE_PAGEREPLAY_*`, `HTE_WEBREPLAY_*`, `HTE_SNAPSHOT_MASK_TOKENS`, `HTE_CONSOLE_CLOCK_START` | | Tests and replays only, never on a server |

Every `HTE_REMOTE_<X>` was `CORTENDESK_<X>`: the old name is read when the new one is unset or empty, with one warning per
name (`src/envvar.rs`); `hte-console status` lists old names in use. `tests/naming.rs` keeps the old name off the screen.

## Compatibility with the previous console

hte-console reads and writes the database of CortenDesk 1.15 (the "previous console") in its own formats, so either can run on
the same data: Laravel-compatible encryption of settings and secrets (`src/laravel.rs`), bcrypt (`$2y$`), the cache and lock rows
of its scheduler (serialized values, `framework/schedule-<sha1>` lock names), its session rows, its backup archive format
(manifest `"app": "cortendesk"`) and its 41-migration schema (`src/migrate.rs`). `src/php.rs` models the values those formats hold.
Where hte-console answers differently on purpose, the code says so next to the answer.

## Tests

`cargo test -p hte-console`: unit tests, integration tests per area (`tests/*.rs`), the golden fixtures in `fixtures/` (answers
recorded from the previous console, all synthetic data, replayed against hte-console), and `tests/naming.rs` (no old name on screen,
no company or private detail, no leftover reference to the previous console outside the compatibility code).
