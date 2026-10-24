-- Phase 3 (server link and sweeps): the world of tests/Hte/ReachTest.php's hteFixture(), in placeholders only.
-- SYNTHETIC: nothing here was captured. 930001 is an administrator (owner in the Pest test), 930002 owns the front
-- desk (María), 930003 is in user group 930201, which holds device group 930101 (Juan), 930004 has nothing (Luis).
-- Devices: 990003001 the front desk (930002's, in 930101, incoming only), 990003002 the server (in 930101),
-- 990003003 a pending laptop (in 930101), 990003004 the administrator's Mac. Every person holds a client token on
-- the Mac. Per-person reach is on; computer passwords stay off here (the sweeps scenario switches them on).
INSERT INTO settings (key, value, created_at, updated_at) VALUES ('hte_scope_enforce', '1', datetime('now'), datetime('now'));
INSERT INTO users (id, username, name, email, password, is_admin, is_active, created_at, updated_at) VALUES
 (930001, 'user-5eed3001', 'text-5eed3001', 'user-5eed300001@example.invalid', 'x', 1, 1, datetime('now'), datetime('now')),
 (930002, 'user-5eed3002', 'text-5eed3002', 'user-5eed300002@example.invalid', 'x', 0, 1, datetime('now'), datetime('now')),
 (930003, 'user-5eed3003', 'text-5eed3003', 'user-5eed300003@example.invalid', 'x', 0, 1, datetime('now'), datetime('now')),
 (930004, 'user-5eed3004', 'text-5eed3004', 'user-5eed300004@example.invalid', 'x', 0, 1, datetime('now'), datetime('now'));
INSERT INTO device_groups (id, name, created_at, updated_at) VALUES (930101, 'text-5eed3101', datetime('now'), datetime('now'));
INSERT INTO user_groups (id, name, created_at, updated_at) VALUES (930201, 'text-5eed3201', datetime('now'), datetime('now'));
INSERT INTO user_group_user (user_group_id, user_id) VALUES (930201, 930003);
INSERT INTO device_group_user_group (device_group_id, user_group_id) VALUES (930101, 930201);
INSERT INTO devices (rustdesk_id, uuid, hostname, os, status, user_id, device_group_id, can_initiate, created_at, updated_at) VALUES
 ('990003001', 'UExBQ0VIT0xERVIhAAAD6Q==', 'host-5eed3001', 'windows / Windows 11 Pro', 'active', 930002, 930101, 0, datetime('now'), datetime('now')),
 ('990003002', 'UExBQ0VIT0xERVIhAAAD6g==', 'host-5eed3002', 'windows / Windows Server 2022', 'active', NULL, 930101, 1, datetime('now'), datetime('now')),
 ('990003003', 'UExBQ0VIT0xERVIhAAAD6w==', 'host-5eed3003', 'Mac OS 15.1', 'pending', NULL, 930101, 1, datetime('now'), datetime('now')),
 ('990003004', 'UExBQ0VIT0xERVIhAAAD7A==', 'host-5eed3004', 'Mac OS 15.1', 'active', 930001, NULL, 1, datetime('now'), datetime('now'));
INSERT INTO client_tokens (user_id, token, device_id, expires_at, created_at, updated_at) VALUES
 (930001, 'tok-5eed00000003a001', '990003004', datetime('now', '+20 days'), datetime('now'), datetime('now')),
 (930002, 'tok-5eed00000003a002', '990003004', datetime('now', '+20 days'), datetime('now'), datetime('now')),
 (930003, 'tok-5eed00000003a003', '990003004', datetime('now', '+20 days'), datetime('now'), datetime('now')),
 (930004, 'tok-5eed00000003a004', '990003004', datetime('now', '+20 days'), datetime('now'), datetime('now')),
 (930004, 'tok-5eed00000003a0e0', '990003004', datetime('now', '-1 minute'), datetime('now'), datetime('now'));
