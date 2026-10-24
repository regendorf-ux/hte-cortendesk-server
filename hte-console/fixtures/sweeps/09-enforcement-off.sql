-- SYNTHETIC. Per-person reach off: the sweep does nothing, even for a session nobody could open now.
UPDATE settings SET value = '0' WHERE key = 'hte_scope_enforce';
INSERT INTO audit_connections (action, conn_id, rustdesk_id, from_peer, from_name, ip, session_id, conn_type, uuid, guid, created_at, updated_at) VALUES
 ('authorized', 93006, '990003002', '990003003', 'text-5eed3306', '198.18.3.56', 'text-5eed3406', 0, 'UExBQ0VIT0xERVIhAAAH1g==', '00000000-0000-4000-8000-000000930006', datetime('now'), datetime('now'));
