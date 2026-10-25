# HTE's changes to CortenDesk Server

This fork is HTE's copy of [cortendesk-server](https://github.com/marcpope/cortendesk-server)
(AGPL-3.0) for HTE Remote. Branch `hte` = the upstream release tag plus the commits below. This
file is the statement of modifications the AGPL asks for (section 5(a)), kept apart from upstream's
`CHANGES.md` so merges stay clean.


**What this repository may hold (owner, 2026-10-16):** HTE's code and placeholders, nothing else. HTE's server addresses, keys, e-mail domain, device IDs and host names live in `/opt/hte-remote/.env` on the server, the Mac's gitignored files, the private apps repository and GitHub secrets. The history was rewritten on 2026-10-16 to take out what had been committed.

## 1.1.1-hte.4 and hte-console 0.9.0 (2026-10-25), phase 9: the PHP-free image

`Dockerfile.hte` builds ONE image, `ghcr.io/regendorf-ux/hte-cortendesk-server:1.1.1-hte.4`, with `hbbs`, `hbbr` and `hte-console` under
`supervisord` (uid 82, read-only root, no PHP, no nginx). `.github/workflows/hte-image.yml` builds `hte-console` beside hbbs/hbbr on the tag
`v1.1.1-hte.4` and refuses a tag that differs from `Cargo.toml`'s version. The image carries hbbs/hbbr `c153365` (the web client's relay fix).
`docker/hte/` holds `supervisord.conf` and `entrypoint.sh`.

`hte-console` 0.9.0: serves `/assets/*`, `/rdclient/*`, `/robots.txt`, `/favicon.ico` itself; new subcommands `version`, `migrate [--check]`,
`status`, `release-locks`, `db-copy`; `migrate.rs` checks the PHP fork's 41 migrations are recorded and applies its own additive ones
(never creates or alters a PHP table); `maintenance.rs` prunes presence snoozes (PHP's `pruneForSweep`). Scripts, checklist and notes:
`phase9/` in HTE's private notes. The PHP console (`regendorf-ux/hte-cortendesk`, branch `hte`, last PHP version 1.15.0-hte.1) is archived source:
it is no longer built into the server image; its AGPL source stays available at that repository for as long as the service runs.

## hte-console 0.1.0 (2026-10-24), phase 1: the device endpoints without PHP

`hte-console` now answers the unauthenticated device endpoints itself when `HTE_CONSOLE_DATABASE` is set:
`POST /api/heartbeat`, `/api/sysinfo`, `/api/audit/conn`, `/api/audit/file`, `/api/audit/alarm` and `GET /api/version`,
ported line by line from the PHP console (v1.15.0-hte.1, incl. HTE's per-computer password hook) onto the same SQLite
file, with no schema change. Everything else is still forwarded to PHP. Details, environment and the answers bad
input gets: `hte-console/README.md`; the list of changes: `hte-console/CHANGES.md`. `replay/replay.sh` now replays
the fixtures against PHP and hte-console and compares the databases both leave. 0.1.2 (same day) applies a code
review: trusted-proxy keywords as PHP reads them, a constant-time uuid compare, flood-proof rate-limit memory.

Upstream files touched: `Cargo.lock` gains rusqlite 0.27 and four small crates (rusqlite links the
libsqlite3-sys 0.24 hbbs's sqlx already uses; sodiumoxide, aes, cbc, chrono and libc were already locked); hbbs and
hbbr are unchanged. `.github/workflows/hte-console.yml` builds with `cross`, as `hte-image.yml` does.

## hte-console 0.0.1 (2026-10-24), a new crate beside hbbs

**`hte-console/`** is new HTE code, not a change to upstream: the first step of replacing the PHP console with Rust
(phase 0, a shadow proxy). A reverse proxy (axum) that forwards every request to the PHP console, returns its answer
unchanged and records sanitised request/response fixtures (`SANITISER.md`: ids, uuids, tokens, hosts, IPs, e-mail
addresses and user names become stable placeholders before anything is written), plus a replay runner
(`replay/replay.sh`, a throwaway PHP container with a database of placeholders). It reads nothing from `/data` and
answers nothing itself. Its own image (`ghcr.io/regendorf-ux/hte-console`) is built by
`.github/workflows/hte-console.yml` on a tag `hte-console-v<version>`.

0.0.2 (same day): plain status tokens (`SYSINFO_UPDATED`, `ID_NOT_FOUND`) are recorded and compared as text; replay classifies
a reply by the capture's own rules (an empty 200 matches an empty 200); the replay database's user has a high id
(the image's first start already creates user 1); `replay.sh` takes several fixture directories and checks that a
deliberately changed fixture is caught; `fixtures/synthetic/` holds eight fixtures written from the PHP source. `replay.sh` also applies `*.sql` found in the directories it is given and derives the default strategy from the captured answers.

Touches upstream files in one place: `Cargo.toml` lists `hte-console` as a workspace member (hbbs and hbbr do not
depend on it and build as before; `Cargo.lock` gains the new crate's dependencies). `hte-image.yml` is unchanged
and its `cargo test --workspace` now also runs this crate's tests.

## 1.1.1-hte.3 (2026-10-25) on upstream 1.1.1

**The in-browser client's sessions pass the relay gate again.** The browser sends only a
`PunchHoleRequest`; the target picks the relay uuid and answers hbbs with a `RelayResponse` that
names itself (`id`), so that `RelayResponse` is the only place hbbs can admit the session. In
`src/rendezvous_server.rs` the `RelayResponse` arm replaces that `id` with the server-signed `pk`
(they are one protobuf oneof) before the gate asked who answered, so `target_answers` always saw an
empty id and never admitted the uuid; hbbr then refused the browser ("Relay gate: refused ...
not admitted by hbbs") and the client said "relay connection lost". The arm now keeps the id before
`set_pk` and asks about that. Desktop sessions were unaffected (they admit at `RequestRelay`). Test:
`tests/hte_webclient_relay.rs` (browser over WebSocket with a person's ticket, a fake target, real
hbbs and hbbr): an in-reach session pairs; out of reach, signed out, a made-up uuid, a refused uuid
and a forged `RelayResponse` do not. One line changed in `src/rendezvous_server.rs`, `Cargo.toml`
version.

## 1.1.1-hte.2 (2026-10-16) on upstream 1.1.1

**The relay pairs only sessions the ID server let through** (`src/hte_relay_gate.rs`, new). Upstream
hbbr pairs any two connections presenting the same uuid and the server key, and the key is public.
With `HTE_RELAY_GATE_PORT` set on both servers (same host), hbbs sends each uuid it hands out for an
admitted session to hbbr as a loopback datagram (`hte1 <uuid>`), and hbbr pairs a uuid only when
hbbs named it in the last two minutes (the second side waits up to 3 s for that word). hbbs names a
uuid on a `RequestRelay` it admitted, and on a `RelayResponse` from a registered, approved target
coming from the address that target registered from (`hte_scope::target_answers`). Off without the
variable. Hooks marked `// HTE`: `src/relay_server.rs` (listener start, the check at pairing),
`src/rendezvous_server.rs` (two `admit` calls), `src/hbbr.rs` and `src/lib.rs` (`mod`). Test:
`tests/hte_relay_gate.rs` (unknown, refused and admitted uuids against real hbbs and hbbr). The
address check assumes clients reach the server over one address family (the server's name has no
AAAA record).

`examples/hte_probe.rs`: asks a live hbbs whether a session may start, as a client would.

## 1.1.1-hte.1 (2026-10-16) on upstream 1.1.1

**Per-person reach, enforced where sessions start** (`src/hte_scope.rs`, new):

- The policy pulled from the console may carry a `scope` block: per console user, whether they
  are an administrator (`all`) or the device ids they may reach (`devices`), plus `token_users`
  (sha256 of a client access token -> user id). While `scope.enforce` is true, `check_initiator`
  refuses a punch-hole or relay request whose target is outside the sender's set. The sender is the
  person `policy.rs` already identifies: the web-client ticket's subject (`web-<user id>`), the
  access token, or nobody (found by IP only, which is refused under enforcement).
- Refusal texts: "You are not given access to this device. Ask your administrator to add it to
  your scope." and, for nobody signed in, "Sign in to the console with your account to start
  sessions…".
- Refusals are posted to the console as `POST /api/server/refusals` (`{refusals: [{user_id,
  user_name, from, to, ip, reason, at}]}`), one per person, origin device and target per minute,
  kept for the next round when the console does not answer.
- The `policy` admin command's line ends with ` scope=on|off people=N`.

Hooks in upstream files, each marked `// HTE`: `src/policy.rs` (the `scope` field of `Snapshot`,
four calls in `check_initiator`, the summary in `install`/`describe`, one report call in the loop),
`src/lib.rs` (`mod hte_scope`), `Cargo.toml` (version `1.1.1-hte.1`).

Tests: unit tests in `src/hte_scope.rs`; end to end in `tests/hte_scope.rs` (real hbbs, fake
console). Everything upstream ships still passes.

Build: `.github/workflows/hte-image.yml` (push a tag `v<upstream>-hte.<n>` or run it by hand)
publishes `ghcr.io/regendorf-ux/hte-cortendesk-server:<upstream>-hte.<n>`, amd64.

## Rebuilding on a new upstream release

```
git fetch origin --tags                 # origin = marcpope/cortendesk-server
git checkout hte && git rebase v<new>   # resolve: the hooks above are small
# bump Cargo.toml version to <new>-hte.1, add a section here
cargo test --workspace
git push -f hte hte && git tag v<new>-hte.1 && git push hte v<new>-hte.1
```
The console image (regendorf-ux/hte-cortendesk) pins this image by its `SERVER_VERSION` build
argument; rebuild it after this one.
