# Golden fixtures

Recorded request/answer pairs that `cargo test -p hte-console` replays against hte-console. All are synthetic: written from the
previous console's behaviour (CortenDesk 1.15) with placeholder-shaped values (`user-…`, `host-…`, `tok-…`, ids starting `99`,
addresses from the documentation ranges), never captured from a real server. Each file carries `"synthetic": true`.

| Directory | What | Read by |
|---|---|---|
| `synthetic/` | device endpoints (heartbeat, sysinfo, audit) | `tests/device_api.rs` |
| `signin/` | the RustDesk client's sign-in (password, two-factor, OIDC with a fake provider), with its seed `*.sql` | `tests/signin_api.rs` |
| `clientapi/` | the signed-in client's endpoints (address books, group tab, server config) | `tests/client_api.rs` |
| `adminapi/` | the admin API (`/api/v1/*`) | `tests/admin_api.rs` |
| `serverlink/` | the ID server's policy pull, local addresses and refusals | `tests/server_link.rs` |
| `sweeps/` | a scenario of SQL steps and scheduled sweeps (`sweeps.plan`) | `tests/server_link.rs` |

A fixture's answer is compared as recorded; values that differ by design (times, random tokens) are masked by the rules in
`src/replay.rs`. Answers that name nested attributes (`addrs.0.id`) are compared as written.
