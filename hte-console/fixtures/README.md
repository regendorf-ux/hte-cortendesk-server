# Fixtures

`synthetic/` holds fixtures written by hand from the PHP console's source (`SyncController`, `AuditController`),
for shapes real traffic has not produced yet. Each carries `"synthetic": true` and `"source"`. They hold placeholders
only and pass `hte-console scan`. They are expectations from reading the code: when a replay disagrees, the code
reading or the fixture is wrong, and the fixture is fixed (or replaced by a captured one), never the other way round.

`signin/` holds phase 2's sign-in fixtures, all synthetic (sign-in traffic carries credentials and is never
captured), written by `replay/make-signin-fixtures.py` from the PHP source, with their seed (`*.sql`, markers filled
in per replay by `hte-console seed-expand`). They need the fake identity provider (`hte-console fake-idp`), which
`replay.sh` starts. Passwords, names and addresses in them are placeholder-shaped test values.

`clientapi/` holds phase 4's client-API fixtures, all synthetic, written by `replay/make-clientapi-fixtures.py` from the PHP
source (address books, group tab, server-config, audit note, web client script), with their seed
(`0000000000004-clientapi-seed.sql`: five people, three folders, seven computers, eight books, five sessions). A guid in
a path is a `{{g<xx>}}` template whose value sits in the fixture's `"vars"` (the sanitiser would take a guid in a path
for a long token). Replay it on its own: `replay.sh fixtures/clientapi`.

Captured fixtures come from the shadow on the server and stay on the server until a person has read them.

`serverlink/` holds phase 3's server-link fixtures, all synthetic (the ID server's calls carry the server link secret
and are never captured), written by `replay/make-serverlink-fixtures.py` from the PHP source, with their seed (the
world of HTE's ReachTest). The policy's body depends on the whole replay database, so its fixtures check status and
type and `replay.sh` compares PHP's policy with hte-console's; 422 answers that name nested attributes (`addrs.0.id`,
which the leftover scan reads as a host name) are checked by digest, their text is in the generator.
`sweeps/` is phase 3's scenario for the scheduled jobs (`sweeps.plan`: SQL steps and sweeps, run by `replay.sh` on
both consoles' databases after the HTTP replay).
