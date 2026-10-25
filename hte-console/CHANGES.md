# hte-console changes

New HTE code (AGPL-3.0), not a change to upstream. The fork-level statement is `../HTE.md`.

## 0.7.12 (2026-10-25): the last two differences of the server replay of 0.7.11 (both on Settings -> Maintenance / Notifications)
- The option-group wrappers (Apprise scope pickers, snooze target) carry a `class` only when hidden, so the one in force has no empty `class=""`.
- Removed the extra "Pruning also runs nightly..." note under Prune now (the confirm dialog already says it saves the retention first).
- The replay leaves the About card out (PHP lists Laravel and PHP versions, hte-console its own) and lists it with the other by-design Settings item.

## 0.7.11 (2026-10-25): the last two differences of the server replay of 0.7.10 (131 requests, 2 differences, B equal, C caught)
- Both were Settings -> Notifications: hte-console ships both Apprise delivery-mode groups (the other one hidden with `d-none`, switched by a click handler,
  no server round trip) while PHP renders only the one in force. Kept as an improvement; the replay now leaves hidden `data-rd-group` blocks out of both sides
  and lists that as "by design". Strategy history: PHP's empty text and restore button.

## 0.7.10 (2026-10-25): the ten differences left in the server replay of 0.7.9
The 0.7.9 run (131 requests) went from 36 to 10 differences, section B was equal (214 lines: the API token step now matches), C caught the mutation. Fixed:
- Every POST control that stands where PHP has a link (Disconnect on the Dashboard, tag remove on the device page and in address books, Approve/Reject/Restore/Destroy,
  address-book Remove, phone-list icon buttons) is a class-free inline form around a button with PHP's exact classes; no `d-inline`, `d-contents` or `btn btn-link`.
  The replay reports only the first difference per page, so all such places were fixed, not just the ones named.
- User detail: the device platform icon carries `fs-18 align-middle` like PHP's component.
- Settings: "Test Connection" and "Send test email" (not ported, disabled) now have PHP's markup and text; "not available" moved to the button's tooltip.

## 0.7.9 (2026-10-25): the markup differences the server replay of 0.7.8 found (36), and the replay itself
Fixes (the replay compares what a person reads and the CSS class sequence of every page with PHP's):
- Dashboard (`/`): no extra "Dashboard" breadcrumb item (PHP shows none on this page).
- `/dashboard/stats` and `/dashboard/sessions` stay: they are the htmx refresh URLs of the two cards (PHP polls through Livewire, which has no URL); they
  answer under the same permission and reach rules as the page. The replay lists them as "by design".
- Devices list: the two hidden forms use the `hidden` attribute, so no extra `d-none` elements among the status chips.
- Device and user detail: the "Back to Devices" / "Back to Users" link before the card; the sidebar no longer marks Devices/Users on a detail page.
- Users and Groups row actions: buttons for the POST actions carry exactly PHP's link classes (`rd-act me-2`, `text-warning me-2`, `text-danger`), the forms
  are inline and class-free, and `hte-pages.css` draws them like the links beside them.
- Address books: no `flex-grow-1` on the narrow-screen book select's form (the CSS keeps it wide).
- Strategies: PHP's subtitle ("Client settings pushed to devices on their next heartbeat."), the "No default strategy" notice in a toolbar, the `d-none d-md-block`
  table with `rd-cell-title d-inline`, `text-muted d-block`, icon counts, an Enabled switch with its hidden label, the action order and classes, the
  empty state, and the phone card list (`d-md-none rd-cardlist`).
- Settings -> Security: the API Tokens card is PHP's (header with `rd-card-sub` and an `rd-card-actions` New Token button, responsive table, phone card
  list), shared with `/api-tokens` as one partial; shown only to people who may read tokens.
Replay:
- The PHP half of the API token step now drives the real Livewire component inside Settings (PHP has no `/api-tokens` page), so the token comparison applies.
- The report separates "by design: ..." (the htmx fragments; the Invitations card at the end of Users, left out of both sides) from "DIFFERENCE: ...".
- `replay-pages.sh` no longer stops when the database diff fails (a `diff | head` under `pipefail`): sections B and C and the final line always run.

## 0.7.8 (2026-10-25): phase 7b, Settings Backups, Prune now, API tokens, the replay's writes
- Settings -> Backups (local only: list, Back up now, download, delete, restore from a stored archive, schedule and retention) and
  Maintenance -> Prune now, on the phase 6 code. API tokens is a real page (`/api-tokens`: create, shown once, revoke).
  Still not ported: the connection/mail/Apprise test buttons, the off-site FTP/S3 settings, restore from an upload.
- `page-replay` now carries the writes of the new pages (PHP through Livewire, hte-console through its forms; `HTE_PAGEREPLAY_RUST_ONLY=1`
  runs hte-console's half alone); `snapshot` masks token hash/prefix with `HTE_SNAPSHOT_MASK_TOKENS=1`; the seed gains a pending computer.
- Web client: "Your computers" (`GET /webclient/devices`, the live reach rule) above a secondary ID field; `POST /webclient/credential` now answers for any computer in reach with a confirmed password (`hte_device_passwords`), no address-book entry needed.
- `Reply::Bytes` (a stored file as it is); the demo server's login takes `?to=` and `?theme=`.

## 0.7.7 (2026-10-25): phase 7b, the rest of the console's pages
- Pages: Dashboard (stat cards and sessions refreshing every 15 s, connection and platform charts, versions, alerts, Disconnect), Devices
  (list, filters, sort, columns, bulk, edit, approve/reject, groups, address books, detail page), Users (list, editor, assign devices, actions,
  person page), Groups, Address books (books, tags, entries, sharing rules), Strategies (editor with impact review, assign, history/restore,
  compliance), Settings (eight tabs; secrets are encrypted like Laravel's and never shown back; relay pool; presence snoozes).
- "Not available yet" pages for Roles, Invitations, Client downloads and Setup (not routed by default; PHP keeps them).
  (0.7.8 adds Prune now, the Backups tab and the API tokens page.)
- `page-seed` and `page-replay` cover the new pages' reads; the writes are covered by the integration tests (`tests/pages7b.rs`) only.
- CI: actions/checkout v7, upload-artifact v7, download-artifact v8 (Node 24 majors; were v4). Verified only by the next tag's CI run.
- Caddy: `phase7/caddy-pages-7b.sh` moves one page at a time.

## 0.7.6 (2026-10-25): the sidebar and top bar follow the theme (they were dark in both; PHP has the same fault), and the sidebar's HTE mark is no longer squashed (new css/hte-pages.css, which scripts/sync-assets.sh leaves alone)

## 0.7.5 (2026-10-25): an invalid theme answers 422 with the messages again (a documented, deliberate difference from PHP's redirect back); the replay expects exactly that

## 0.7.4 (2026-10-25): an invalid theme is Laravel's redirect back (PHP renders JSON errors for /api/* only), found by the second real-PHP replay; the replay treats http://host and http://host/ as one place

## 0.7.3 (2026-10-25): first real-PHP replay findings: Laravel's hasPages() (a page past the end keeps its pager) and empty first/last item in the pager; the replay fetches PHP's CSVs through Livewire's export call, asks for JSON on the theme calls, and turns the release check off on both sides

## 0.7.2 (2026-10-25): page-replay uses only the path of Livewire's announced update address, and reports an error part way together with the differences found before it

## 0.7.1 (2026-10-25): page-replay finds Livewire 4's hashed update address (`data-update-uri`); replay-pages.sh hands the copy to uid 82 and reads WAL databases writable

## 0.7.0 (2026-10-25): phase 7a, the page layer (sessions, CSRF, templates, htmx) and the first pages
- Reads PHP's session: the `hte-remote-session` cookie decrypted with `/data/.app_key`, the `sessions` table (PHP must run
  `SESSION_DRIVER=database`; `phase7/deploy.sh` flips it). A request without a valid session is forwarded to PHP, never served.
- CSRF compatible with Livewire and plain forms (`_token`, `X-CSRF-TOKEN`, `X-XSRF-TOKEN`, `Sec-Fetch-Site`); flashes with
  Laravel's one-request lifetime; `console-can` redirect.
- minijinja templates and the CSS/JS/images (HTE brand included) embedded in the binary; htmx 2.0.4 vendored, no CDN.
- Pages: Account (profile, password, theme; the 2FA card is read-only and links to PHP), Logs: Connections, File Transfers,
  Alarms, Logins, Console (filters, paging, CSV). Dashboard NOT ported.
- `page-seed` / `page-replay` (reads and writes against real PHP, databases compared), `replay/replay-pages.sh`,
  `examples/pages_demo.rs` (screenshots on synthetic data). `HTE_CONSOLE_PAGES=0` turns the pages off.
- Not routed by default: Caddy lines are in `phase7/NOTES.md`.

## 0.6.0 (2026-10-25): phase 6, local backups, restore, pruning and the daily scheduler entries
  Review (Opus 5.5, read-only) fixes: the archive is created 0600 from the start; the schema version is read before the
  restore's copy; staged server files are copied aside first and old `*.restore` files dropped, and a failure after the
  database commit says so ("The database WAS restored..."); a tar entry larger than the file is refused.
  Known, left on purpose: a stop during a running backup leaves the `cortendesk:backup` cache lock until its 3600 s expiry
  (and `panic = abort` skips the guard); the once-per-day check is read before the lock, so two `--scheduled` runs within
  the same second could both back up; no cap on the decompressed size of a restore (PHP has none either); an
  undecryptable value is carried over unchanged on re-keying.


Built on top of 0.4.1 (phase 5, the admin API, is built in parallel and is not in this version).

- `backup`, `backups`, `restore`, `prune-logs`, `prune-invitations` on the command line, and the three daily entries of
  PHP's schedule as scheduler jobs (`HTE_CONSOLE_JOBS`, none by default): `cortendesk:backup --scheduled` (03:30 UTC),
  `cortendesk:prune-logs` (04:10), `cortendesk:prune-invitations` (04:20). Ported from `BackupService`, `Backup`,
  `Restore`, `PruneLogs`, `PruneInvitations` of 1.15.0-hte.1 (`src/backup.rs`, `src/prune.rs`, `src/housekeeping.rs`,
  `src/tarfile.rs`).
- The archive is PHP's, byte layout and all: a plain tar of `manifest.json`, `db/<table>.ndjson.gz` and
  `files/{app_key,server_secret,rustdesk/*}`, plus the `.tar.json` sidecar. An archive PHP made restores here
  (proven on a real one from the live server) and one made here restores in PHP (`replay/backup-roundtrip.sh` runs
  that against PHP itself).
- Safer than PHP, invisible to its reader: the dump is one `VACUUM INTO` snapshot; a restore is built and checked
  (integrity, foreign keys, row counts against the manifest) in a temporary database and applied to the live one in a
  single transaction; a cut or incomplete archive is refused; `hte_device_passwords` is re-keyed with the others.
- Not ported (HTE has them off): off-site copies (FTP, S3), Apprise notifications, the upload/download routes of
  Settings -> Backups (UI), `cortendesk:check-device-notifications`. A configured off-site target is reported as a
  failed copy where Settings shows it; the deploy stops if one is set.
- New env: `HTE_CONSOLE_JOBS`, `HTE_CONSOLE_BACKUPS_DIR` (else `CORTENDESK_BACKUPS_PATH`, else `/data/backups`),
  `HTE_CONSOLE_RUSTDESK_DIR` (else the directory of `HTE_CONSOLE_HBBS_DB`), `HTE_CONSOLE_LOG_RETENTION_DAYS` (else
  `CORTENDESK_LOG_RETENTION_DAYS`, else 365). Dependency: `flate2` (already in the lockfile).

## 0.5.3 (2026-10-25): phase 5, a flaky test

- `signin_api::pkce_and_client_secret_reach_the_provider` (phase 2) failed about one run in 64: it replaced the first character of
  the random PKCE verifier with `x`, which is no change when the verifier already starts with `x`. It now always changes it. No change to the console.

## 0.5.2 (2026-10-25): phase 5, the replay against PHP found one difference

- `unique` and `exists` are not run for an attribute that already failed a rule (Laravel's
  `hasNotFailedPreviousRuleIfPresenceRule`): `owner_user_id: "abc"` gets the integer message only. The first replay against PHP 1.15.0-hte.1
  matched 185 of 186 fixtures, with hte-console 186 of 186 and identical databases; this was the one difference.

## 0.5.1 (2026-10-25): phase 5, replay fixes

- First replay against PHP: the throwaway PHP's own first-start administrator made the user lists one longer, so the
  adminapi seed deletes it; the snapshot masks a random book guid in `console_audits.target_id`. No change to the API.

## 0.5.0 (2026-10-24): phase 5, the admin automation API

- Native: the 48 routes of `/api/v1/*` and `POST /api/devices/cli` (`--assign`), ported from 1.15.0-hte.1 behind PHP's
  api-token guard, `throttle:120,1`, model bindings and `api-token-can` (README section "Phase 5"). Everything else
  keeps going where it went.
- Hardening beyond PHP: a per-address limit on failed API authentications (300 a minute, 429), a 1 MiB body cap.
- `fixtures/adminapi/`: 186 synthetic fixtures and their seed, written by `replay/make-adminapi-fixtures.py`; a synthetic
  fixture may list `"scan_ignore"` pointers (Laravel's own vocabulary: validation messages, action names) and
  `"sanitise_expected"`; `seed-sql` no longer seeds `/api/v1/*` bearers as client tokens; the snapshot masks `remember_token`.
- Version 0.5.0. New env: `HTE_CONSOLE_ADMIN_MAX_BODY_BYTES`.

## 0.4.1 (2026-10-24): phase 4, the signed-in client, on top of phase 3

0.4.0 was tagged from a branch without phase 3 and must not be deployed; 0.4.1 is the same work merged with 0.3.0.

- Native: the address books (legacy `GET|POST /api/ab`, `POST /api/ab/get`, and the multi-book API under `/api/ab/`),
  `GET|POST /api/server-config`, the group tab (`/api/device-group/accessible`, `/api/users`, `/api/peers`), the session
  note and active-session lookup (`PUT /api/audit`, `GET /api/audit/conn/active`) and `GET /webclient-config/index.js`,
  ported from 1.15.0-hte.1 behind phase 2's bearer-token guard, with each person's reach (README section "Phase 4").
  `/webclient` and `/rdclient/*` stay PHP; the websocket bridge is Caddy's.
- `fixtures/clientapi/`: 118 synthetic fixtures and their seed, written by `replay/make-clientapi-fixtures.py`; the replay
  learns `"vars"` (preset variables), `{{name}}` in the path, masks `tm` and marks random UUIDs.
- Version 0.4.1. New env: `HTE_CONSOLE_CLIENT_MAX_BODY_BYTES`, `HTE_CONSOLE_ID_SERVER`,
  `HTE_CONSOLE_PUBLIC_KEY`.

## 0.3.0 (2026-10-24): phase 3, the server link and the sweeps

- Native: `GET /api/server/policy` (ServerLink::policy with HTE's `scope` block, ETag/304, the pull recorded in
  Laravel's cache), `POST /api/server/local-addrs`, `POST /api/server/refusals` (alarm 102), behind PHP's shared
  secret and `throttle:600,1,server-link`; Laravel's validator for their bodies (`src/validate.rs`).
- Scheduled jobs (`HTE_CONSOLE_SWEEPS`, none by default): the reach sweep (15 s, alarm 103), computer passwords
  (rotation on schedule and on access loss, the "HTE Remote" books), stale sessions, the diagnostics heartbeat; each
  under the lock PHP's scheduler takes for it (`cache_locks`), so PHP skips what hte-console runs and resumes when
  it stops. Needs the PHP container on `CACHE_STORE=database`.
- New: `hte-console sweep`, `schedule-locks`, `sql-apply` (replay only). The replay forwards `If-None-Match`, captures
  a response header (`capture_header`) and compares a body by digest (`"kind": "sha256"`); `seed-sql` never seeds the
  server link's bearer as a client token; the snapshot compares Laravel's `cache` table for the two keys hte-console
  writes (times masked) and masks lock owners. `replay.sh`: the secret and the database cache on both consoles, the
  two policies compared, and `fixtures/sweeps/` run step by step on both databases.
- `fixtures/serverlink/` (31 synthetic fixtures and the ReachTest world as a seed, written by
  `replay/make-serverlink-fixtures.py`), `fixtures/sweeps/` (a scenario of SQL steps and sweeps).
- From the independent review before release: the validator walks the body by reference (a 500-entry batch cloned
  it some 30 000 times) and runs before the shared database connection is taken; a 4 MiB limit of the link's own;
  the scheduler does not take a lock after the stop gave them back, and a restarted service takes back the locks a
  killed one left (owners `hte-console-svc-`/`hte-console-cli-`); each sweep row in a savepoint; a lock insert that
  fails for another reason than the key is an error; the replay compares tokens both policies hold exactly and exits
  2 when a setup step fails. Tests for each.
- Phase 1's `Passwords::issue` now cuts the reason as `Str::limit($reason, 60, '')` does (the sweep's reasons can be
  longer than 60 characters).

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
