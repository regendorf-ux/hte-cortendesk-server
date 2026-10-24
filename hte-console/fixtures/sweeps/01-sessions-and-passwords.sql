-- SYNTHETIC. Open sessions: 93001 the Mac (everyone signed in there, the administrator too) to the server, stays;
-- 93002 from the web client, left alone; 93003 from the front desk, where nobody is signed in, closes (alarm 103);
-- 93004 to the server, an hour old, the server silent: the stale sweep closes it. Computer passwords on, every 7 days:
-- the front desk confirmed two days ago (not due), the server has none yet (first password), the pending laptop is
-- skipped, the Mac confirmed 40 days ago (due).
INSERT INTO settings (key, value, created_at, updated_at) VALUES ('hte_pw_enabled', '1', datetime('now'), datetime('now')), ('hte_pw_days', '7', datetime('now'), datetime('now'));
INSERT INTO audit_connections (action, conn_id, rustdesk_id, from_peer, from_name, ip, session_id, conn_type, uuid, guid, created_at, updated_at) VALUES
 ('authorized', 93001, '990003002', '990003004', 'text-5eed3301', '198.18.3.51', 'text-5eed3401', 0, 'UExBQ0VIT0xERVIhAAAH0Q==', '00000000-0000-4000-8000-000000930001', datetime('now'), datetime('now')),
 ('authorized', 93002, '990003001', 'web-5eed', 'text-5eed3302', '198.18.3.52', 'text-5eed3402', 0, 'UExBQ0VIT0xERVIhAAAH0g==', '00000000-0000-4000-8000-000000930002', datetime('now'), datetime('now')),
 ('authorized', 93003, '990003002', '990003001', 'text-5eed3303', '198.18.3.53', 'text-5eed3403', 1, 'UExBQ0VIT0xERVIhAAAH0w==', '00000000-0000-4000-8000-000000930003', datetime('now'), datetime('now')),
 ('authorized', 93004, '990003002', '990003004', 'text-5eed3304', '198.18.3.54', 'text-5eed3404', 0, 'UExBQ0VIT0xERVIhAAAH1A==', '00000000-0000-4000-8000-000000930004', datetime('now', '-1 hour'), datetime('now', '-1 hour'));
INSERT INTO hte_device_passwords (rustdesk_id, capable_at, current_version, current_enc, issued_at, issued_reason, confirmed_version, confirmed_enc, confirmed_at, created_at, updated_at) VALUES
 ('990003001', datetime('now'), 1, '@@ENCRYPT(tok-5eed00000003f001)@@', datetime('now', '-2 days'), 'first check-in', 1, '@@ENCRYPT(tok-5eed00000003f001)@@', datetime('now', '-2 days'), datetime('now'), datetime('now')),
 ('990003002', datetime('now'), 0, NULL, NULL, NULL, 0, NULL, NULL, datetime('now'), datetime('now')),
 ('990003003', datetime('now'), 0, NULL, NULL, NULL, 0, NULL, NULL, datetime('now'), datetime('now')),
 ('990003004', datetime('now'), 1, '@@ENCRYPT(tok-5eed00000003f004)@@', datetime('now', '-40 days'), 'first check-in', 1, '@@ENCRYPT(tok-5eed00000003f004)@@', datetime('now', '-40 days'), datetime('now'), datetime('now'));
