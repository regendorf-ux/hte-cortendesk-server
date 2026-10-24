# hte-console changes

New HTE code (AGPL-3.0), not a change to upstream. The fork-level statement is `../HTE.md`.

## 0.4.0 (2026-10-24): phase 4, the signed-in client

- Native: the address books (legacy `GET|POST /api/ab`, `POST /api/ab/get`, and the multi-book API under `/api/ab/`),
  `GET|POST /api/server-config`, the group tab (`/api/device-group/accessible`, `/api/users`, `/api/peers`), the session
  note and active-session lookup (`PUT /api/audit`, `GET /api/audit/conn/active`) and `GET /webclient-config/index.js`,
  ported from 1.15.0-hte.1 behind phase 2's bearer-token guard, with each person's reach (README section "Phase 4").
  `/webclient` and `/rdclient/*` stay PHP; the websocket bridge is Caddy's.
- `fixtures/clientapi/`: 118 synthetic fixtures and their seed, written by `replay/make-clientapi-fixtures.py`; the replay
  learns `"vars"` (preset variables), `{{name}}` in the path, masks `tm` and marks random UUIDs.
- Version 0.4.0 (0.3.0 is phase 3, built apart). New env: `HTE_CONSOLE_CLIENT_MAX_BODY_BYTES`, `HTE_CONSOLE_ID_SERVER`,
  `HTE_CONSOLE_PUBLIC_KEY`.

## 0.2.0 (2026-10-24): phase 2, the client sign-in

- Native: `GET /api/login-options`, `POST /api/login` (password, the TOTP step), `POST /api/logout`,
  `POST /api/currentUser`, `POST /api/oidc/auth`, `GET /api/oidc/auth-query`, `GET /login/oidc/client-callback`,
  ported from 1.15.0-hte.1 with what they write (tokens, OIDC requests, login logs, accounts, alarms, devices).
  README section "Phase 2" has the rules and the deliberate differences (RS256 only, exp required, azp with several
  audiences, Entra tenant, JWKS refetch, https-only provider, single-use state, redirect URI from
  `HTE_CONSOLE_PUBLIC_URL`, equal timing for unknown users, 64 KiB bodies).
- New: `hte-console fake-idp` (a fake OpenID provider, test only) and `hte-console seed-expand`; the replay learns
  run-time templates (`{{name}}`, captures, `{{totp}}`), a browser step through the fake provider, HTML checks for
  pages, and masks what sign-in mints at random (tokens, codes, state, nonce, verifier, bcrypt hashes, the TOTP step).
- `fixtures/signin/`: 151 synthetic sign-in fixtures and their seed, written by `replay/make-signin-fixtures.py`.
- The shadow never records sign-in paths. A replay template (`{{name}}`) counts as a placeholder in the leftover scan.
- From the independent review before release: the callback's token exchange and writes run in their own task with a
  guard, so a browser that disconnects mid-exchange no longer leaves the state marked in use (the retry read as
  expired until a restart); tests for that, a concurrent duplicate, `iat` ahead without `nbf`, the global 2FA switch,
  forwarded port/prefix and an IPv6 Host, and the `email_verified` forms.

## 0.1.2 (2026-10-24): review fixes

From a code review of 0.1.1 against PHP 1.15.0-hte.1, Laravel 13.35 and Symfony http-foundation 8.1:

- `TRUSTED_PROXIES` is read as `TrustConfiguredProxies` and Symfony read it: `*` alone trusts every peer,
  `REMOTE_ADDR` the request's own peer, `PRIVATE_SUBNETS`/`private_ranges` Symfony's list. 0.1.1 dropped such entries
  silently, so `*` would have recorded Caddy's address for every device. Entries that are no address are still
  ignored, as in PHP, and now named in a warning at start. Not HTE's configuration (it uses the default).
- The uuid pin is compared in constant time (`hash_equals`, as PHP).
- Rate-limit and nonce memory expire in two generations instead of scanning the whole map once full: a flood of
  new addresses or nonces costs nothing per request; memory stays bounded.
- `json_encode` leaves DEL (0x7f) as it is, like PHP (reachable only through a strategy value containing it).
- Checked and kept: 404/405/413 answers carry `Access-Control-Allow-Origin: *`, because Laravel renders those
  exceptions inside the middleware pipeline and HandleCors adds the header on the way out.
- README: the known differences that depend on configuration HTE does not use (empty `TRUSTED_PROXIES`,
  `APP_PREVIOUS_KEYS`, the older Apprise offline marker).
- `replay.sh`: the tamper check picks its fixture with a glob (under `pipefail`, `ls | grep -m1` with 900+ fixtures
  also ran the fallback and named two files). The replay itself is unchanged; the image does not contain it.
- Tests: trusted-proxy keywords and two `X-Forwarded-For` headers, form and `charset` bodies over HTTP, stored
  timestamps Carbon cannot read (500), the password hook on a pending device and with no or unreadable ciphertext,
  a soft-deleted strategy reached through a link, the CORS header on 405 and 413.

## 0.1.1 (2026-10-24): the replay paces itself

The first server replay with 0.1.0 (725 fixtures) compared 429s: 700 captured heartbeats from a few devices, sent in one
burst, tripped the console's own limit of 120 a minute per address and device, on PHP and on hte-console alike (the
databases came out identical, every other answer matched). `hte-console replay` now sends at most 110 a minute per
address and device id (`HTE_CONSOLE_REPLAY_PER_MINUTE`), waiting when needed; `replay.sh`'s tamper check replays only
the changed fixture. No change to the endpoints. A racy test of the 413 path now sends only the headers.

## 0.1.0 (2026-10-24): phase 1, the device endpoints

- `serve` with `HTE_CONSOLE_DATABASE` answers `POST /api/heartbeat`, `/api/sysinfo`, `/api/audit/conn`,
  `/api/audit/file`, `/api/audit/alarm` and `GET /api/version` itself, on the PHP console's SQLite file (WAL,
  busy timeout, foreign keys; no schema change). Ported from v1.15.0-hte.1: `SyncController`, the tokenless half of
  `AuditController`, `Strategy` (resolution and delivery), `DeviceEnrollment` (approval gate, default group,
  approval by a signed-in client), the presence marker of `CheckDeviceNotifications::reportOnline`, and HTE's
  password hook (`App\Hte\Passwords`: `hte_pw`, issue, confirm, book entries, the password sealed with
  `crypto_box_seal` to the device's ed25519 key from hbbs's `peer` table). Everything else is forwarded as in 0.0.x.
- PHP and Laravel semantics as a library (`php.rs`, `laravel.rs`), so answers to bad input are PHP's own.
- Hardening: 1 MiB body cap, the `device-sync` rate limit, no panics on input (a seeded fuzz test), bound
  parameters only, no secrets in logs, refuses to start under a uid that would leave WAL files PHP cannot write.
- `hte-console snapshot <sqlite>`; `replay.sh` replays against PHP and hte-console and compares the databases.
- Synthetic fixtures 009-024 (bad input, audit paths); raw request bodies in synthetic fixtures.
- Graceful stop on SIGTERM. Image built with `cross` (libsodium, SQLite).
- Not ported: Apprise notifications; multipart bodies.

## 0.0.2 (2026-10-24)

Status tokens recorded as text, replay classifies replies like capture, several fixture directories, a built-in
"does the replay notice a change" check, eight synthetic fixtures, extra seed SQL, the default strategy derived
from captured answers.

## 0.0.1 (2026-10-24): phase 0, the shadow proxy

Forwards every request to PHP and returns its answer unchanged; records sanitised fixtures (`SANITISER.md`);
`scan`, `seed-sql`, `replay`, `replay/replay.sh`.
