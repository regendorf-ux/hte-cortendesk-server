# Fixtures

`synthetic/` holds fixtures written by hand from the PHP console's source (`SyncController`, `AuditController`),
for shapes real traffic has not produced yet. Each carries `"synthetic": true` and `"source"`. They hold placeholders
only and pass `hte-console scan`. They are expectations from reading the code: when a replay disagrees, the code
reading or the fixture is wrong, and the fixture is fixed (or replaced by a captured one), never the other way round.

Captured fixtures come from the shadow on the server and stay on the server until a person has read them.
