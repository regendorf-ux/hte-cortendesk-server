# What the sanitiser replaces

The rules are in `src/sanitise.rs` (header comment) and tested in `tests/sanitiser.rs`. This is the plain-words version.

**When:** at capture time, before anything is written. There is no "raw" fixture, ever. A body that is not JSON or a
form (pages, binaries) is not stored, only its length. Headers are an allow-list; the rest are dropped.

**How:** a placeholder is `HMAC-SHA256(salt, kind | value)` cut short, so one real value always gives the same
placeholder (relationships survive: the id in the query is the id in the body), and nothing maps back without the
salt. The salt is `HTE_CONSOLE_SANITISE_SALT` in the environment, never in the repository.

| What | Placeholder | Found by |
|---|---|---|
| device id | `99` + 7 digits | key (`id`, `peer`, `from`, `to`, ...), learned |
| uuid | `00000000-0000-4000-8000-...` or base64 starting `UExBQ0VIT0xERVIh` | key (`uuid`), shape |
| token, secret, key, password, pk, code, session, cookie | `tok-` + 16 hex | key (substring), JWT shape, 32+ character opaque strings |
| e-mail | `user-...@example.invalid` | key, shape |
| host name / FQDN / URL host | `host-...` / `dom-....example.invalid` | key, shape, `HTE_CONSOLE_SANITISE_LITERALS` |
| IPv4 / IPv6 | `198.18.0.0/15` / `2001:db8::...` | shape |
| user name | `user-` + 8 hex | key, learned |
| free-text name, note, alias, address, url | `text-` + 8 hex | key |

Kept: numbers, booleans, switches (`Y`, `N`, `true`, `0`, empty), versions, status codes, keys that carry no identity.

**Learning:** an id, user or host seen under its key is also replaced wherever it appears inside free text, in that
pair and in every later one of the run (memory only, never written).

**The leftover scan:** placeholders are fixed points. `hte-console scan <dir>` sanitises every fixture again and
fails on any value that would change, and on any configured literal found anywhere in the file. It prints the
path of the problem, never the value. CI and the replay script run it first.

**Not covered:** a secret with a key that says nothing and a value that looks like prose (a 12-character password
under `"foo"`). That is why only `/api/` paths are recorded (`HTE_CONSOLE_CAPTURE_PREFIXES`), pages never are, and
a person reads the first fixtures before any is committed.
