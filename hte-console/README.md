# hte-console

HTE Remote's console, step by step in Rust. **Phase 0: a shadow proxy.** It sits in front of the PHP console,
forwards every request, returns PHP's answer unchanged, and records sanitised fixtures. It computes no answers
and opens no database. Plan: `PHPLESS-PLAN.md` in HTE's private notes.

```
hte-console serve                       # the proxy
hte-console scan <dir>                  # fail if a fixture holds anything real
hte-console seed-sql <dir>              # SQL (placeholders only) for a replay database
hte-console replay <dir> <base-url>     # replay and report differences (exit 1 when any)
replay/replay.sh <dir>                  # all of that in a throwaway PHP container
```

Environment (nothing HTE-specific is in this repository):

| Variable | Meaning |
|---|---|
| `HTE_CONSOLE_UPSTREAM` | the PHP console's URL (required) |
| `HTE_CONSOLE_LISTEN` | default `0.0.0.0:8080` |
| `HTE_CONSOLE_FIXTURES` | directory for fixtures; unset = forward only |
| `HTE_CONSOLE_CAPTURE_PREFIXES` | recorded path prefixes, default `/api/` |
| `HTE_CONSOLE_CAPTURE_MAX_BYTES` | default 262144 |
| `HTE_CONSOLE_SANITISE_SALT` | key of the placeholders (keep it the same between capture and replay) |
| `HTE_CONSOLE_SANITISE_LITERALS` | comma list of host names and domains always replaced |
| `HTE_CONSOLE_CONNECT_TIMEOUT_SECS`, `HTE_CONSOLE_REQUEST_TIMEOUT_SECS` | defaults 3 and 60 |

Health: `GET /__hte-console/health`. Upstream down: 502; too slow: 504. Rules: `SANITISER.md`.
Build: `.github/workflows/hte-console.yml` on a tag `hte-console-v<version>`.
