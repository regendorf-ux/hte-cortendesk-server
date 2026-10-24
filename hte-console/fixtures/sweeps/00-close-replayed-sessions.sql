-- SYNTHETIC. Sessions the HTTP replay left open belong to devices whose last check-in differs in time between the
-- two runs; closed here on both sides alike, so the sweeps below act on this scenario's sessions only.
UPDATE audit_connections SET closed_at = '2000-01-01 00:00:00' WHERE closed_at IS NULL;
