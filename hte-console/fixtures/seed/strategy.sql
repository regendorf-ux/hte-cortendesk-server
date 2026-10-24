-- Extra seed for the replay database: the live console has a default strategy that keeps direct IP
-- connections off (what every captured heartbeat answer carries). Placeholders only.
INSERT INTO strategies (name, enabled, is_default, enforce, options, created_at, updated_at)
  VALUES ('text-seed0001', 1, 1, 1, '{"direct-server":"N"}', datetime('now'), datetime('now'));
UPDATE devices SET strategy_id_resolved = (SELECT id FROM strategies WHERE name = 'text-seed0001');
