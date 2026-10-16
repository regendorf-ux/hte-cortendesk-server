# HTE's changes to CortenDesk Server

This fork is HTE's copy of [cortendesk-server](https://github.com/marcpope/cortendesk-server)
(AGPL-3.0) for HTE Remote. Branch `hte` = the upstream release tag plus the commits below. This
file is the statement of modifications the AGPL asks for (section 5(a)), kept apart from upstream's
`CHANGES.md` so merges stay clean.

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
