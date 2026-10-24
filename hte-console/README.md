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
- **Phase 2, the RustDesk client's sign-in answered here** (0.2.0). `GET /api/login-options`, `POST /api/login`
  (password, then the TOTP step), `POST /api/logout`, `POST /api/currentUser`, `POST /api/oidc/auth`,
  `GET /api/oidc/auth-query` and the browser's `GET /login/oidc/client-callback`, ported from `ClientAuthController`,
  `ClientOidcController`, `OidcService` (with firebase/php-jwt 7.1.0's checks and messages), `OidcUserResolver`,
  `TwoFactor` and `DeviceEnrollment::signedIn` (a pending device is approved and owned on sign-in). Section
  "Phase 2" below has the rules and the deliberate differences.

```
hte-console serve                       # serve; with HTE_CONSOLE_DATABASE the device endpoints are native
hte-console scan <dir>                  # fail if a fixture holds anything real
hte-console seed-sql <dir>              # SQL (placeholders only) for a replay database
hte-console replay <dir> <base-url>     # replay and report differences (exit 1 when any)
hte-console snapshot <sqlite>           # the database as comparable text (PHP's state vs ours)
hte-console seed-expand <sql> <idp>     # a phase 2 seed made concrete (fake provider URL, app-key ciphertexts)
hte-console fake-idp                    # a fake OpenID provider for the replay (TEST ONLY: src/fake_idp.rs)
replay/replay.sh <dir>                  # all of that against throwaway PHP and hte-console containers
replay/make-signin-fixtures.py          # writes fixtures/signin/ (the synthetic sign-in fixtures)
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
| **Phase 2** | |
| `HTE_CONSOLE_PUBLIC_URL` | the console's origin as browsers and the identity provider know it (`https://rustdesk.<domain>`). Set, the OIDC redirect URI and the page's links come from it and never from the Host header; unset, they are built from the request as Laravel does, and `serve` warns when SSO is on |
| `APP_NAME` | page titles, as the PHP image has it (default `CortenDesk`) |
| `CORTENDESK_OIDC_DISABLED` | PHP's kill switch for SSO, read the same way (`true`/`1`/`on`/`yes`) |
| `BCRYPT_ROUNDS` | cost of new bcrypt hashes (provisioned accounts), as Laravel (default 12) |
| `HTE_CONSOLE_SIGNIN_MAX_BODY_BYTES` | default 65536 |
| `HTE_CONSOLE_OIDC_ALLOW_HTTP` | `1` lets the identity provider be plain http: the replay's fake provider only, never on the server |

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

## Phase 2: client sign-in

Answers as PHP's for every valid client: the same JSON (PHP's `json_encode`, slashes escaped, `info` an object),
the same `{"error": ...}` texts on HTTP 200 (the client reads only bodies), the same 401/405/413/429/500 bodies, the
same throttles (`client-auth` 240 a minute per address around all four tokenless routes, `client-login` 20,
`client-oidc` 20, `client-oidc-poll` 400; nested as Laravel nests them, with its headers), the same writes:
`client_tokens` (48 random characters, 30 days, `last_used_at` on each use), `oidc_auth_requests` (code, state and
nonce 40 characters, verifier 96, 300 seconds), `login_logs`, `users` (linking by email once, then by (iss, sub);
provisioning under `oidc_new_user_policy`, `oidc_default_group_id`, `oidc_default_admin`; a random bcrypt password),
`alarm_logs` (brute force on the code step, once per 5 minutes), `devices` (registered, or approved and owned).
Break-glass sign-in is PHP's: `$2y$` bcrypt through PHP's own rules (a hash PHP does not call bcrypt is a 500, a
password ends at a NUL byte and after 72 bytes), the same refusals in the same order, the same throttles; the
TOTP step is otphp's (SHA-1, 6 digits, 30 s, one step either way, the highest match, a step used once).

Proven by `tests/signin_api.rs` (21 end-to-end tests with the fake identity provider of `src/fake_idp.rs`, which
makes valid tokens and every broken kind: wrong issuer, audience or nonce, alg none and HS256, expired, nbf ahead,
bad signature, unknown or missing kid, a short key, a key for another algorithm, no exp, several audiences, no
subject, a refusing provider, a failing token endpoint, no or a malformed ID token), and by the 151 synthetic
fixtures in `fixtures/signin/`, which `replay.sh` replays against PHP and hte-console with the fake provider beside
them and compares, answers and database. Sign-in traffic is never captured (the shadow refuses to record these
paths whatever its prefixes say).

### Deliberate differences (harder than PHP, invisible to a valid client)

| | PHP 1.15.0-hte.1 | hte-console |
|---|---|---|
| unknown user, disabled user, empty password | answered at once (the answer's timing tells which names exist) | one bcrypt check against a dummy hash, as long as a wrong password |
| ID token algorithm | any the provider advertises (HS* checked with the client secret) | RS256 only |
| `exp` | checked only when present | required |
| nonce | checked when one was sent (always, in the client flow) | always required |
| several audiences | any list holding the client id | `azp` must be the client id too |
| Microsoft issuer | issuer string compared | also `tid` must be the issuer's tenant |
| unknown `kid` | fails until the 5-minute cache expires | the key set is fetched again, at most once a minute (key rotation) |
| the provider's endpoints | any scheme, redirects followed, any size | https only, no redirects, answers read to at most 1 MiB, the same timeouts |
| a second callback with a used state | exchanges again and overwrites the result (a reload after success turned it into a failure; a second code could replace the token before the client collected it) | refused as expired (400); a concurrent duplicate too |
| redirect URI and page links | from the request's Host header | from `HTE_CONSOLE_PUBLIC_URL` when set |
| request bodies | PHP's limit | 64 KiB on these routes (413) |
| lookups by token, code, state | SQL equality | SQL equality, then compared again in constant time |
| the callback page | Laravel's web group: session and XSRF cookies | no cookies (nothing on the page uses them); `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` |

### Known differences, not visible to a RustDesk client at HTE

- Emailed sign-in codes are not ported (they need the mail relay): with `email_login_verification` on and mail
  configured, a password sign-in that would get a code is answered with PHP's own "cannot send verification codes"
  refusal. `serve` warns at start; the phase 2 deploy stops when it is on. HTE has it off.
- Apprise's failed-sign-in and pending-device notifications are not sent (Apprise is off at HTE).
- TOTP prompts, limiter counts, alarm cooldowns and the discovery/JWKS cache live in this process: a restart forgets
  them (a person mid-way through a TOTP prompt signs in again). PHP keeps them in its file cache.
- Laravel's error pages (500, 405, 413 on the callback page) are a short copy of its default page; the status is the same.
- Inputs that are type errors in PHP (an array where `?string` is declared, an array `kid`) are 500s here; PHP turns
  some of those inside the token check into a message. php-jwt's rarer JSON error texts (depth, control characters)
  read "Syntax error, malformed JSON" here. Keys of types other than RSA in the provider's key set are skipped (PHP
  parses EC and OKP keys and fails the whole set on a malformed one). No identity provider or client sends these.
- A signed-in console session in the same browser does not pass through PHP's web middleware on this page
  (`RequireTwoFactor` and friends); the page reads no session.
- The phase 2 routes add Laravel's rate-limit headers to a 500 too (as Laravel does); phase 1's device routes do not
  (a header-only difference, kept as it is).
