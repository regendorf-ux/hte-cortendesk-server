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
- **Phase 3, the server link and the sweeps** (0.3.0). The endpoints the ID server (hbbs) calls,
  `GET /api/server/policy` (with HTE's per-person `scope`), `POST /api/server/local-addrs` and
  `POST /api/server/refusals` (alarm 102), and the scheduled jobs `hte:reach-sweep` (alarm 103, 15 s),
  `hte:passwords` (rotation and the "HTE Remote" books), `cortendesk:close-stale-sessions` and
  `cortendesk:diagnostics-heartbeat`, ported from `ServerLinkController`, `ServerLink`, `VerifyServerSecret`,
  `App\Hte\{Reach,ReachSweep,RefusalsController,Passwords}` and `AuditConnection::closeStaleSessions`. Section
  "Phase 3" below.

- **Phase 5, the admin automation API answered here** (0.5.0). All 48 routes of `/api/v1/*` (users, devices, user and
  device groups, address books with peers, tags and rules, the four audit logs) and `POST /api/devices/cli`
  (`--assign`), ported from `routes/api.php`, `routes/client-cli.php`, `AdminApi\*`, `Api\DeviceCliController` and
  `ApiTokenCan`, behind PHP's own bearer check. Section "Phase 5" below.
- **Phase 6, local backups, restore and pruning** (0.6.0). `hte-console backup|backups|restore|prune-logs|
  prune-invitations` and the daily scheduler entries (`HTE_CONSOLE_JOBS`), ported from `BackupService`,
  `cortendesk:backup`, `cortendesk:restore`, `cortendesk:prune-logs` and `cortendesk:prune-invitations`, in PHP's
  archive format. Section "Phase 6" below.

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
hte-console sweep <job>...|all          # phase 3: run reach, passwords, stale, diagnostics once (under PHP's lock)
hte-console schedule-locks              # phase 3: the cache_locks key of each job PHP's scheduler would take
hte-console sql-apply <sqlite> <sql>    # phase 3, replay only: a scenario step on a throwaway database
replay/make-serverlink-fixtures.py      # writes fixtures/serverlink/ (the synthetic server-link fixtures)
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
| `HTE_CONSOLE_CLIENT_MAX_BODY_BYTES` | phase 4: default 2097152 (the legacy address book is pushed whole) |
| `HTE_CONSOLE_ID_SERVER`, `HTE_CONSOLE_PUBLIC_KEY` | phase 4: what `/api/server-config` says when the settings table has no `id_server`/`public_key` (else `CORTENDESK_ID_SERVER`, `CORTENDESK_PUBLIC_KEY`) |
| `HTE_CONSOLE_OIDC_ALLOW_HTTP` | `1` lets the identity provider be plain http: the replay's fake provider only, never on the server |
| **Phase 3** | |
| `CORTENDESK_SERVER_SECRET` | the server link secret, as PHP gets it; else the file `HTE_CONSOLE_SERVER_SECRET_FILE` (default `/data/.server_secret`, which the PHP image writes root-only: the deploy passes the variable). Empty: `/api/server/*` answer 404, as an unlinked PHP |
| `HTE_CONSOLE_CACHE_PREFIX` | PHP's `cache.prefix` (else `CACHE_PREFIX`, else `Str::slug(APP_NAME)-cache-`); the deploy passes PHP's own value |
| `HTE_CONSOLE_SWEEPS` | which scheduled jobs run here: `reach,passwords,stale,diagnostics` or `all`; default none |
| `HTE_CONSOLE_SERVER_LINK_MAX_BODY_BYTES` | default 4194304 (500 refusals of the longest values fit) |

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

## Phase 3: the server link and the sweeps

The ID server runs inside the PHP container and reaches the console at `CORTENDESK_CONSOLE_URL` (loopback by
default), so it moves here when that URL points at hte-console, not through Caddy. Answers as PHP's: the policy
byte for byte (`mode`, `allow` and `incoming_only` by device id, `tokens` and `scope.token_users` as sha256 of each
live token, ksorted, `ip_match`, and `scope` = `{enforce, users: {id: {name, all, devices}}, token_users}`, empty
while `hte_scope_enforce` is off; `{}` where PHP casts to an object), its ETag (sha256 of the body, quoted; 304 for a
matching `If-None-Match`, weakly compared), `VerifyServerSecret` (404 unlinked, 401 for a wrong bearer, `hash_equals`,
before the limiter), `throttle:600,1,server-link` with Laravel's headers, Laravel's validator for the two POST bodies
(the same 422 texts, keys and order: `src/validate.rs`), and the same writes: `devices.lan_ip`/`lan_ip_seen_at`
(never rolled back, never in the future, dirty-only), `alarm_logs` 102 (both device names, "nobody signed in").
Every pull is recorded where PHP records it (`ServerLink::recordPull`), in Laravel's cache.

The sweeps write what PHP's commands write: `audit_connections.disconnect_requested_at` (the console's own
disconnect, delivered by the heartbeat), `alarm_logs` 103 and a "system" line in `console_audits`; new passwords
(`hte_device_passwords`, the reasons PHP gives, `Str::limit` 60) and the automatic books (`address_books` "HTE
Remote", one rule, `address_book_entries` in step with `Device::visibleTo` and the confirmed passwords, a disabled
person's emptied; `hte_auto_books`); stale sessions closed after five silent minutes; the scheduler heartbeat.

**Laravel's cache and scheduler.** The pull marker and the scheduler heartbeat are read by PHP's Settings and Fleet
Diagnostics pages through `Cache::get`, so they are written into Laravel's **database** store (`cache` table, PHP's
prefix, PHP's `serialize`, ten-year expiry); the PHP container must run `CACHE_STORE=database` (its image defaults to
`file` inside the container). PHP's scheduler stays on for everything else; for each job taken over, hte-console
takes and keeps the very lock `withoutOverlapping` takes (`cache_locks`, `Event::mutexName()`, PHP's expiry: 1, 5,
30, 10 minutes), so PHP's `schedule:run` skips the job as it skips one still running. hte-console skips a tick while
PHP holds the lock, gives the locks back on a clean stop (PHP resumes at its next tick) and, if it dies, they expire.

Proven by `tests/server_link.rs` (30 end-to-end tests: ReachTest's and PasswordsTest's assertions for these paths
by their names, the exact policy body, ETag/304/HEAD/405, 404/401, the 600 limit across the three routes, the local
address rules, 422s, 300 random bodies, the scheduler lock against a PHP-held one, its refresh, its take-back after a restart, no lock after the stop, a
write failing half way, a full batch of the longest refusals, the sweeps scenario), by the 31
synthetic fixtures in `fixtures/serverlink/` and by `fixtures/sweeps/`, which `replay.sh` runs against PHP and
hte-console: answers, both policies against each other, and the databases after the sweeps' steps.

### Deliberate differences (invisible to the ID server)

| | PHP 1.15.0-hte.1 | hte-console |
|---|---|---|
| a sweep's writes for one session or one computer | separate statements: a failure half way (a busy database) can leave a disconnect without its alarm, or a lost person recorded without the new password (never rotated after) | one savepoint per row: all or none, the next run does it again; a run that succeeds ends as PHP's |
| a lock its own scheduler left (killed) | `withoutOverlapping` waits for the expiry (up to 30 minutes) | the service takes back locks a previous hte-console service left, at start (never PHP's, never a `sweep` run's) |
| a tick waiting when the process stops | n/a | does not take a lock after the locks were given back |
| request bodies | PHP's limit | 4 MiB on these routes (413); validated before the shared database connection is taken |

### Known differences, not visible to the ID server at HTE

- The security-alarm notification per refusal is not sent (Apprise; off at HTE, a no-op in PHP then).
- The validator is the subset these routes use; `mb_strwidth` (for `Str::limit` of log lines) knows the main wide
  blocks only, and `FILTER_VALIDATE_IP` is Rust's IPv6 parser with PHP's IPv4 rule. Text only HTE could send.
- A token whose sha256 is all digits would be an integer key in PHP and sort differently (1 in 10^13).
- The sweeps read every open session at once (PHP's `each()` reads in chunks of 1000; with more open sessions PHP
  could skip some in one run that the next run catches). HTE has a handful.

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

Proven by `tests/signin_api.rs` (22 end-to-end tests with the fake identity provider of `src/fake_idp.rs`, which
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
| a second callback with a used state | exchanges again and overwrites the result (a reload after success turned it into a failure; a second code could replace the token before the client collected it) | refused as expired (400); a concurrent duplicate too. The exchange runs in its own task: a browser that leaves mid-exchange neither stops the sign-in half way nor leaves the state marked in use |
| redirect URI and page links | from the request's Host header | from `HTE_CONSOLE_PUBLIC_URL` when set |
| request bodies | PHP's limit | 64 KiB on these routes (413) |
| lookups by token, code, state | SQL equality | SQL equality, then compared again in constant time |
| the callback page | Laravel's web group: session and XSRF cookies | no cookies (nothing on the page uses them); `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (a proxy's own policy wins: HTE's Caddy sets `strict-origin-when-cross-origin` for the whole site, which also keeps the code and state out of a cross-origin Referer) |

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
- Inherited from PHP, not changeable without a client change: the `state` binds the sign-in to the client's
  pending row, not to a browser, so someone who learns a pending state (it is in the authorize URL) could complete it
  with their own account. Single use, 300 seconds and `Referrer-Policy: no-referrer` narrow it. Two wrong TOTP codes
  sent at the same instant can both count as the same try (also PHP's); the 5-a-minute limiter still caps them.
- A signed-in console session in the same browser does not pass through PHP's web middleware on this page
  (`RequireTwoFactor` and friends); the page reads no session.
- The phase 2 routes add Laravel's rate-limit headers to a 500 too (as Laravel does); phase 1's device routes do not
  (a header-only difference, kept as it is).

## Phase 4: the signed-in client (address books, group tab, audit note, web client)

The routes of the `auth:client` group that HTE's RustDesk clients call, ported statement by statement from
`AddressBookController`, `GroupTabController`, `WebClientController` and `AuditController::note/activeConnection`
(`src/client.rs`): `GET /api/ab`, `POST /api/ab/get`, `POST /api/ab` (the legacy address book), `POST /api/ab/personal`,
`/settings`, `/shared/profiles`, `/peers`, `/tags/{guid}`, `/peer/add|update/{guid}`, `DELETE /peer/{guid}`,
`/tag/add|rename|update/{guid}`, `DELETE /tag/{guid}` (the multi-book API), `GET|POST /api/server-config`,
`GET /api/device-group/accessible`, `GET /api/users`, `GET /api/peers` (the group tab), `PUT /api/audit` (the note),
`GET /api/audit/conn/active`, and `GET /webclient-config/index.js`. The guard is phase 2's (`signin::authenticate`):
an unknown, expired or disabled-owner token is 401 `{"message":"Unauthenticated."}`, `last_used_at` is stamped. Each
person's reach is PHP's: `User::accessibleDeviceGroupIds`, `visibleUserIds`, `Device::scopeVisibleTo` (own computers
plus every accessible folder, approved and not deleted), `AddressBook::permissionFor` (owner, administrator, rules:
`everyone`/`user`/`group`, the highest wins), and HTE's `Passwords::hiddenBookFor` (another person's automatic book is
never listed, administrators included). The SQL keeps Eloquent's shapes so row order is the same.

Left to PHP, on purpose: `/webclient` (the page is bound to a login session and mints the websocket ticket) and the
static `/rdclient/*` files; the websocket itself is the Caddy bridge (`notes/phase4/`), not this crate.
Anything else under `/api/` keeps going to PHP. Paths that are not canonical (a trailing slash, other case) match no
native route and go to PHP, as before.

Same as PHP, including where it is odd: errors are `{"error": ...}` on HTTP 200; `pageSize` is clamped to 1..500 and a
present-but-empty query value takes the default (`$request->query()` is `all()[$k] ?? $d` after
`ConvertEmptyStringsToNull`); the legacy push is not a transaction (it deletes tags, inserts them, deletes entries,
inserts them: a failure half way leaves what was done, a duplicate tag name is a 500 after the old tags are gone);
success is an empty 200 body where PHP's is; 404/405/OPTIONS/preflight answer as Laravel's router does (the 405 lists the
other verbs of that URI in `Router::$verbs` order).

Configuration read at call time (no restart for settings): `id_server` and `public_key` come from the settings table
(PHP's `Setting::server`), else `HTE_CONSOLE_ID_SERVER`/`CORTENDESK_ID_SERVER` and
`HTE_CONSOLE_PUBLIC_KEY`/`CORTENDESK_PUBLIC_KEY`; the online window is the `online_window` setting, else
`CORTENDESK_ONLINE_WINDOW`, else 60 seconds (`0` means 60, as `Device::onlineWindow()`).

Proven by `tests/client_api.rs` (12 end-to-end tests: the 118 synthetic fixtures, routing, 413, reach, paging, the online
window, a form-encoded PUT, the non-transactional push, the note length, the log holding no secret) and by the fixtures in
`fixtures/clientapi/` (written by `replay/make-clientapi-fixtures.py` from the PHP source, with their seed), which
`replay.sh` replays against PHP and hte-console and compares, answers and database. Run that replay on its own
(`replay.sh fixtures/clientapi`): its lists assume only its own people and computers.

### Phase 4: deliberate differences

| | PHP 1.15.0-hte.1 | hte-console |
|---|---|---|
| request bodies | PHP's limit | 2 MiB on these routes (`HTE_CONSOLE_CLIENT_MAX_BODY_BYTES`: a whole legacy book is pushed at once), 413 over it |
| `GET /webclient-config/index.js` | Laravel's web group: session and XSRF cookies | no cookies (the script uses none); the origin is `HTE_CONSOLE_PUBLIC_URL` when set, else built from the request as the sign-in pages are |
| `tm` in `/api/server-config` peers | `now()->subDay()` precise timestamp, whole seconds | whole seconds as well; the replay masks it |
| a form-encoded `PUT`/`DELETE` body | read by Laravel | read the same way (clients send JSON) |
| the `X-Forwarded-For` the websocket sees | what the client sent | the Caddy bridge overwrites it with the real peer address (a client cannot choose the address hbbs records) |

### Phase 4: known differences, not visible to a RustDesk client at HTE

- A legacy push whose `tag_colors` decodes to a non-empty JSON string, with a tag named by digits: PHP's
  `$tagColors[$name] ?? 0` reads the character at that offset of the string as the colour; here it is 0. The client
  never sends it (`tag_colors` is an object).

## Phase 5: the admin automation API (`/api/v1/*`) and `--assign`

`src/admin.rs` (route table, guard, throttle, bindings, ability check, envelope), `src/admin_ctl.rs` (the controllers),
`src/device_cli.rs` (`POST /api/devices/cli`), `src/duplicates.rs` (`DuplicateDevices`) and `src/email.rs`. Every route,
verb, status code, validation message, envelope (`{code,data,message}`, paginated `{code,data,total,current,total_pages,message}`),
audit line (`console_audits`, "... (API)") and database write is ported statement by statement from the PHP console
1.15.0-hte.1; the model events that matter (`Device` created/updated re-resolve the policy, `User`/`DeviceGroup` deleted
re-resolve every device, soft deletes, the `hashed` and `array` casts, dirty-only updates) are reproduced.

**Authentication is PHP's and nothing is reachable without it.** The chain on a v1 route is `auth:api-token`, then
`throttle:120,1,admin-api` (the client route: `client-cli`; key = sha1 of the owner), then the model bindings (404
`No query results for model [App\Models\X] <id>`), then `api-token-can:<resource>,<r|rw>`, then `last_used_at`.
The guard reads only `Authorization: Bearer <token>` (`''` and `'0'` are no token), finds the `api_tokens` row by the
sha256 of the token (an indexed equality on the hash; the plaintext is never stored or logged), requires `is_active`, an
`expires_at` that is null or in the future, an owner that exists, is active and still holds `consoleAllows('token','rw')`,
and refuses with 401 `{"message":"Unauthenticated."}`. `api-token-can` re-checks the token (401 envelope
`{code:401,...}`) and the matrix (403 envelope `Token lacks 'rw' permission on 'user'.`); matrix levels are ranked
rw > r > everything else, and an array level is a TypeError, a 500, as in PHP. Unknown routes are the Laravel 404 JSON
and wrong verbs the 405 with an `Allow` header, both before authentication, as Laravel's router does. HEAD is served as GET.

Proven by `tests/admin_api.rs` (8 tests: the 186 synthetic fixtures with database-state checks, every route refusing an
unknown bearer, the token-by-hash rules, the owner losing the right at once, the 120/min throttle, 413, malformed and
form bodies, preflight, no secret in the log) and `fixtures/adminapi/` (written by `replay/make-adminapi-fixtures.py`
from the PHP source, with their seed: people, API tokens by sha256, groups, computers, books, logs).
`replay.sh fixtures/adminapi` replays them against PHP and hte-console and compares answers and database; run it on its
own (its lists assume only its own people and computers).

### Phase 5: deliberate differences

| | PHP 1.15.0-hte.1 | hte-console |
|---|---|---|
| failed token guesses | only the `throttle` after a valid token | additionally a per-address limit of 300 failed authentications a minute (429), so a guessing run is slowed before it reaches the 120/min owner limit that needs a valid token; callers sharing one egress address with a script that keeps retrying a revoked token share its 300 a minute |
| request bodies | PHP's limit | 1 MiB (`HTE_CONSOLE_ADMIN_MAX_BODY_BYTES`), 413 over it |
| `email` validation | egulias/email-validator (RFC) | a narrower check (local part and dotted domain; no quoted strings, comments or IP literals) |
| `multipart/form-data` bodies | parsed | not parsed (the automation sends JSON); JSON and `application/x-www-form-urlencoded` are read as Laravel reads them |

### Phase 5: known differences, not visible to the automation at HTE

- Produced by PHP's exceptions, not by input: a 500 renders as `{"message":"Server Error"}` (Laravel without debug); a
  database constraint failure (a duplicate peer or tag, a null `owner_user_id`, a re-used `rustdesk_id` of a disabled
  device through `--assign`) is that 500 here too, and nothing is written.
- `Authorization: bearer <token>` (other case) is accepted, as in phases 2-4's shared helper (`laravel::bearer_token`); a valid token is still required. Whether Laravel 13's `bearerToken()` is case-sensitive could not be checked (no vendor tree here); the replay against PHP settles it.
- `POST /api/devices/cli/` (trailing slash) is not a native route and goes to PHP; `/api/v1/*` accepts it as Laravel does.
- `last_used_at` is stamped with whole seconds, as the models cast it.
## Phase 6: backups, restore, pruning

`src/backup.rs` (the archive, create, restore, retention), `src/prune.rs`, `src/housekeeping.rs` (the commands, the
scheduler entries, the command line), `src/tarfile.rs` (the tar container, by hand: ustar in, ustar and pax/GNU long
names out of what PHP's `PharData` and GNU tar write; an entry's name is never used as a path).

```
hte-console backup [--scheduled]        # cortendesk:backup (--scheduled: only when enabled and not yet done today)
hte-console backups                     # the local archives, newest first
hte-console restore <name|path> [--force]
hte-console prune-logs [--days=N]       # cortendesk:prune-logs
hte-console prune-invitations [--days=N]
```
All of them read the same environment as `serve` (`HTE_CONSOLE_DATABASE`, the app key, `HTE_CONSOLE_BACKUPS_DIR`...).

**The archive** is PHP's (format 1): `cortendesk-backup-YYYYMMDD-HHMMSS[-tag].tar`, a plain tar holding `manifest.json`
(`format`, `app`, `app_version`, `created_at`, `trigger`, `app_url`, `db_driver`, `tables` name to rows, `files`),
`db/<table>.ndjson.gz` (one JSON object per row, columns in table order, every table but the transient ones: `cache`,
`cache_locks`, `sessions`, `jobs`, `job_batches`, `failed_jobs`, `oidc_auth_requests`, `password_reset_tokens`,
`password_resets`) and `files/app_key`, `files/server_secret`, `files/rustdesk/{id_ed25519,id_ed25519.pub,db_v2.sqlite3}`;
beside it `<name>.tar.json`, the manifest again. Archive and sidecar are mode 0600 in a 0700 directory. The retention
tiers (newest N, first of each of the last N ISO weeks, first of each of the last N months; defaults 7/8/6; 0 turns a
tier off, all 0 keeps everything) run after every backup, as in PHP.

**Restore** replaces every data table except `migrations` (the live schema owns it) and the transient ones; columns the
live schema lacks are dropped and reported; tables the archive lacks are emptied (PHP deletes every live table first);
when the archive's app key differs from this install's, the encrypted columns (`settings.value`, `users.totp_secret`,
`address_book_entries.password_enc` and, beyond PHP, `hte_device_passwords.current_enc|confirmed_enc`) are re-keyed.
hbbs's files are staged as `<name>.restore` beside the originals for the PHP image's entrypoint to swap in at the next
start of the container, each written whole under a temporary name first (restart the PHP container to adopt them).
The database is never half-written: the new data is built in a temporary database (a `VACUUM INTO` copy of the live
schema, emptied and filled from the archive), checked (`integrity_check`; rows whose foreign key points nowhere are
reported, not refused, as PHP restores them unchecked; the row counts must equal the manifest's, a table with rows
whose file is missing is a cut archive), and only then applied to the live file in one `BEGIN IMMEDIATE` transaction
that deletes and refills the data tables from it. A crash or an error before COMMIT leaves the old content (SQLite's
atomicity, WAL or not); PHP and the request handlers see the old data or the new, never a mixture. A file swap would
leave PHP and this service holding the old file, which is why the swap is a transaction. If the schema changed
between the build and the swap (a migration ran), the restore stops without changing anything.

**Locks**: a backup or restore takes PHP's own `cortendesk:backup` cache lock (the Laravel database cache, which
phase 3 put PHP on), so a click on "Back up now" in PHP and a run here exclude each other. Stale work directories
(`.work-*`, `.restore-*`) of a killed run are removed by the next run.

**The daily entries** (`HTE_CONSOLE_JOBS=backup,prune-logs,prune-invitations` or `all`; UTC, as the app's
timezone): see the header of `housekeeping.rs` for how each avoids running twice. In short: the backup holds PHP's
schedule mutex like phase 3's jobs, shares the `cortendesk:backup` lock and runs once per calendar day by the shared
`backup_last_scheduled_at` marker; the two prune entries have no PHP mutex, so the deploy removes them from the PHP
container's schedule before listing them here.

### Phase 6: deliberate differences

| | PHP 1.15.0-hte.1 | hte-console |
|---|---|---|
| the dump | table after table while the database is written | one `VACUUM INTO` snapshot, every table from the same moment |
| restore | delete and insert in the live database | built and checked in a temporary database, applied in one transaction |
| a cut archive | restores what it can read (a truncated table silently) | refused: no end-of-archive, a cut member or a row count different from the manifest |
| `hte_device_passwords` on a cross-key restore | not re-keyed (its ciphertexts become unreadable) | re-keyed |
| off-site copy (FTP/S3) | made after a backup | not made; a configured target is reported in `backup_last_result` as a failed copy |
| Apprise on backup completed/failed | sent when configured | not sent (off at HTE; the deploy refuses to continue when on) |
| restore confirmation | `confirm()` prompt | prompt on a terminal, `--force` to skip |
| restore of rows with a foreign key to nothing | restored (foreign keys off) | restored, and listed as a warning |

### Phase 6: known differences, not visible at HTE

- The upload/download/delete routes of Settings -> Backups are PHP's Livewire page and stay PHP (they use the same
  directory and the same archives).
- A BLOB column is dumped as text with invalid UTF-8 replaced, as PHP's `JSON_INVALID_UTF8_SUBSTITUTE` does; the
  console's tables have none.
- U+2028/2029 are written unescaped (PHP escapes them); any JSON reader takes both.

## Phase 8: the console's sign-in and session cookie

`/login` (the HTE Remote welcome card: Microsoft sign-in, the break-glass password behind a link), `/login/oidc` and
`/login/oidc/callback` (OIDC authorization code with PKCE S256, nonce, and phase 2's token checks), `/logout`, with
hte-console's OWN session (`pages/websession.rs`, `pages/login.rs`). Design, switches and the transition with PHP's
remaining pages: `notes/phase8/NOTES.md`. Off unless `HTE_CONSOLE_SIGNIN=1`.

### Phase 8: deliberate differences

| | PHP 1.15.0-hte.1 | hte-console |
|---|---|---|
| session cookie | Laravel's encrypted `hte-remote-session`, the id in clear in `sessions` | `__Host-hte-remote` (random id), only sha256(id) in `hte_console_sessions` |
| lifetime | 120 min idle, no absolute limit; remember-me cookie for years | 60 min idle, 12 h absolute; "Remember me" only keeps the cookie across a browser restart within those 12 h |
| revocation | `revokeAllAccess` deletes `sessions` rows | the same, and every own session of the account dies with its `remember_token` (whoever rotated it) |
| logout | cycles the remember token | the same; so it signs the person out of every hte-console session |
| logout at the provider | `id_token_hint` (the ID token in a URL) | `client_id` (no token in a URL, none stored) |
| unknown or disabled account | answered at once | as long as a wrong password (dummy bcrypt) |
| TOTP enrolled, TOTP required, e-mailed codes | second step / enrolment | refused with a message (not used at HTE; deploy stops when on) |
| "Forgot password?" link | shown when mail is configured | never (reset not offered) |
| password reset, invitations | pages | "not available" (404) |
| a guest page | a session row per visit | one row per browser, at most 60 new rows a minute per address |
