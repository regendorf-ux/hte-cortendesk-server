-- SYNTHETIC. The front desk's owner signs in there and opens 93005 to it: an owner may, it stays.
INSERT INTO client_tokens (user_id, token, device_id, expires_at, created_at, updated_at) VALUES (930002, 'tok-5eed00000003a102', '990003001', datetime('now', '+20 days'), datetime('now'), datetime('now'));
INSERT INTO audit_connections (action, conn_id, rustdesk_id, from_peer, from_name, ip, session_id, conn_type, uuid, guid, created_at, updated_at) VALUES
 ('authorized', 93005, '990003001', '990003001', 'text-5eed3305', '198.18.3.55', 'text-5eed3405', 0, 'UExBQ0VIT0xERVIhAAAH1Q==', '00000000-0000-4000-8000-000000930005', datetime('now'), datetime('now'));
