-- Phase 4 (bearer-token client endpoints): the people, groups, computers, address books and sessions the synthetic
-- fixtures in this directory expect. SYNTHETIC: placeholders only, no real name, address, key or password.
-- Marker, filled in per replay by `hte-console seed-expand`: @@ENCRYPT(...)@@ (Crypt::encryptString under the replay
-- database's own app key). Applied after `hte-console seed-sql` (which gives every bearer a fixture shows to a
-- seed administrator): the tokens below are replaced by tokens with the right person and computer.
--
-- people (ids 94000x): 1 administrator "adm", 2 "anna" (note, group 1), 3 "ben" (no display name, groups 1 and 2),
--   4 "none" (no groups; sees device group 3 and the members of group 2 only through group accesses), 5 disabled
-- user groups: 1 {anna, ben}, 2 {ben, the disabled one}; group access: group 1 -> user group 2; user 4 -> user group 2,
--   user 4 -> device group 3, group 2 -> device group 3
-- device groups: 1 (granted to user group 1), 2 (granted to ben), 3 (by access only)
-- computers 990000411..417: 411 anna's, online; 412 ben's, in group 1, offline; 413 group 2; 414 group 3; 415 pending
--   (anna's); 416 deleted (anna's); 417 nobody's and in no group
-- address books: personal 940001 (anna's, with two peers and two tags), personal 940002 (its owner is gone);
--   shared 940010 (everyone: read), 940011 (ben: read/write, group 2: read; anna owns it), 940012 (group 1: full;
--   two peers, two tags), 940013 (no rule: administrators only), 940014 and 940015 (the automatic books of anna and ben)

DELETE FROM client_tokens WHERE token IN ('tok-5eed000000004a01', 'tok-5eed000000004a02', 'tok-5eed000000004a03', 'tok-5eed000000004a04', 'tok-5eed000000004a05', 'tok-5eed000000004a06', 'tok-5eed000000004a07');

INSERT INTO users (id, username, name, email, note, password, is_admin, is_active, created_at, updated_at) VALUES
 (940001, 'user-5eed0401', 'text-5eed0401', 'user-5eed040001@example.invalid', NULL, 'x', 1, 1, datetime('now'), datetime('now')),
 (940002, 'user-5eed0402', 'text-5eed0402', 'user-5eed040002@example.invalid', 'text-5eed0902', 'x', 0, 1, datetime('now'), datetime('now')),
 (940003, 'user-5eed0403', NULL, 'user-5eed040003@example.invalid', NULL, 'x', 0, 1, datetime('now'), datetime('now')),
 (940004, 'user-5eed0404', '', NULL, NULL, 'x', 0, 1, datetime('now'), datetime('now')),
 (940005, 'user-5eed0405', 'text-5eed0405', 'user-5eed040005@example.invalid', NULL, 'x', 0, 0, datetime('now'), datetime('now'));

INSERT INTO client_tokens (user_id, token, device_id, expires_at, created_at, updated_at) VALUES
 (940001, 'tok-5eed000000004a01', '990000401', NULL, datetime('now'), datetime('now')),
 (940002, 'tok-5eed000000004a02', '990000411', NULL, datetime('now'), datetime('now')),
 (940003, 'tok-5eed000000004a03', '990000412', datetime('now', '+30 days'), datetime('now'), datetime('now')),
 (940004, 'tok-5eed000000004a04', '990000414', NULL, datetime('now'), datetime('now')),
 (940005, 'tok-5eed000000004a05', '990000415', NULL, datetime('now'), datetime('now')),
 (940002, 'tok-5eed000000004a06', '990000411', '2020-01-01 00:00:00', datetime('now'), datetime('now')),
 (940002, 'tok-5eed000000004a07', NULL, NULL, datetime('now'), datetime('now'));

INSERT INTO user_groups (id, name, note, created_at, updated_at) VALUES
 (940001, 'text-5eed04a1', NULL, datetime('now'), datetime('now')),
 (940002, 'text-5eed04a2', NULL, datetime('now'), datetime('now'));
INSERT INTO user_group_user (user_id, user_group_id) VALUES (940002, 940001), (940003, 940001), (940003, 940002), (940005, 940002);

INSERT INTO device_groups (id, name, note, created_at, updated_at) VALUES
 (940001, 'text-5eed04b1', NULL, datetime('now'), datetime('now')),
 (940002, 'text-5eed04b2', NULL, datetime('now'), datetime('now')),
 (940003, 'text-5eed04b3', NULL, datetime('now'), datetime('now'));
INSERT INTO device_group_user_group (device_group_id, user_group_id) VALUES (940001, 940001);
INSERT INTO device_group_user (user_id, device_group_id) VALUES (940003, 940002);
INSERT INTO group_accesses (accessor_type, accessor_id, target_type, target_id, created_at, updated_at) VALUES
 ('user_group', 940001, 'user_group', 940002, datetime('now'), datetime('now')),
 ('user', 940004, 'user_group', 940002, datetime('now'), datetime('now')),
 ('user', 940004, 'device_group', 940003, datetime('now'), datetime('now')),
 ('user_group', 940002, 'device_group', 940003, datetime('now'), datetime('now'));

INSERT INTO devices (rustdesk_id, uuid, status, hostname, os, username, alias, note, user_id, device_group_id, last_online_at, deleted_at, created_at, updated_at) VALUES
 ('990000411', 'UExBQ0VIT0xERVIhAAAA0g==', 'active', 'host-5eed0411', 'windows', 'user-5eed0411', 'text-5eed0411', 'text-5eed0911', 940002, NULL, datetime('now'), NULL, datetime('now'), datetime('now')),
 ('990000412', 'UExBQ0VIT0xERVIhAAAA0w==', 'active', 'host-5eed0412', 'macos', '', '', NULL, 940003, 940001, '2020-01-01 00:00:00', NULL, datetime('now'), datetime('now')),
 ('990000413', 'UExBQ0VIT0xERVIhAAAA1A==', 'active', 'host-5eed0413', 'windows', NULL, NULL, NULL, NULL, 940002, NULL, NULL, datetime('now'), datetime('now')),
 ('990000414', 'UExBQ0VIT0xERVIhAAAA1Q==', 'active', 'host-5eed0414', 'linux', NULL, NULL, NULL, NULL, 940003, datetime('now'), NULL, datetime('now'), datetime('now')),
 ('990000415', 'UExBQ0VIT0xERVIhAAAA1g==', 'pending', 'host-5eed0415', 'windows', NULL, NULL, NULL, 940002, NULL, NULL, NULL, datetime('now'), datetime('now')),
 ('990000416', 'UExBQ0VIT0xERVIhAAAA1w==', 'active', 'host-5eed0416', 'windows', NULL, NULL, NULL, 940002, NULL, NULL, datetime('now'), datetime('now'), datetime('now')),
 ('990000417', 'UExBQ0VIT0xERVIhAAAA2A==', 'active', 'host-5eed0417', 'windows', NULL, NULL, NULL, NULL, NULL, NULL, NULL, datetime('now'), datetime('now'));

INSERT INTO settings (key, value, created_at, updated_at) VALUES
 ('id_server', 'host-5eed0401.example.invalid:21116', datetime('now'), datetime('now')),
 ('public_key', 'tok-5eed00000000a1b2', datetime('now'), datetime('now')),
 ('online_window', '63072000', datetime('now'), datetime('now'))
 ON CONFLICT(key) DO UPDATE SET value = excluded.value;

INSERT INTO address_books (id, guid, name, owner_user_id, is_personal, note, created_at, updated_at) VALUES
 (940001, '00000000-0000-4000-8000-0000000004a1', 'text-5eed04f1', 940002, 1, NULL, datetime('now'), datetime('now')),
 (940002, '00000000-0000-4000-8000-0000000004a2', 'text-5eed04f2', 999998, 1, NULL, datetime('now'), datetime('now')),
 (940010, '00000000-0000-4000-8000-0000000004c1', 'text-5eed04c1', 940001, 0, NULL, datetime('now'), datetime('now')),
 (940011, '00000000-0000-4000-8000-0000000004c2', 'text-5eed04c2', 940002, 0, 'text-5eed04ca', datetime('now'), datetime('now')),
 (940012, '00000000-0000-4000-8000-0000000004c3', 'text-5eed04c3', 940001, 0, NULL, datetime('now'), datetime('now')),
 (940013, '00000000-0000-4000-8000-0000000004c4', 'text-5eed04c4', 940001, 0, NULL, datetime('now'), datetime('now')),
 (940014, '00000000-0000-4000-8000-0000000004c5', 'text-5eed04c5', 940002, 0, NULL, datetime('now'), datetime('now')),
 (940015, '00000000-0000-4000-8000-0000000004c6', 'text-5eed04c6', 940003, 0, NULL, datetime('now'), datetime('now'));
INSERT INTO hte_auto_books (user_id, address_book_id, created_at, updated_at) VALUES (940002, 940014, datetime('now'), datetime('now')), (940003, 940015, datetime('now'), datetime('now'));
INSERT INTO address_book_rules (address_book_id, subject_type, subject_id, permission, created_at, updated_at) VALUES
 (940010, 'everyone', NULL, 1, datetime('now'), datetime('now')),
 (940011, 'user', 940003, 2, datetime('now'), datetime('now')),
 (940011, 'group', 940002, 1, datetime('now'), datetime('now')),
 (940012, 'group', 940001, 3, datetime('now'), datetime('now')),
 (940014, 'user', 940002, 1, datetime('now'), datetime('now')),
 (940015, 'user', 940003, 1, datetime('now'), datetime('now'));

INSERT INTO tags (id, address_book_id, name, color, created_at, updated_at) VALUES
 (940001, 940001, 'text-5eed04d1', 4278190080, datetime('now'), datetime('now')),
 (940002, 940001, 'text-5eed04d2', 5, datetime('now'), datetime('now')),
 (940003, 940012, 'text-5eed04e1', 1, datetime('now'), datetime('now')),
 (940004, 940012, 'text-5eed04e2', 0, datetime('now'), datetime('now'));

INSERT INTO address_book_entries (id, address_book_id, rustdesk_id, alias, hostname, platform, username, password_enc, hash, login_name, force_always_relay, rdp_port, rdp_username, tag_ids, created_at, updated_at) VALUES
 (940001, 940001, '990000421', 'text-5eed0421', 'host-5eed0421', 'Windows', 'user-5eed0421', NULL, 'tok-5eed000000000421', NULL, 0, NULL, NULL, '[940001]', datetime('now'), datetime('now')),
 (940002, 940001, '990000422', '', 'host-5eed0422', 'Mac OS', '', NULL, 'tok-5eed000000000422', 'user-5eed0922', 1, '3389', 'user-5eed0422', '[940001,940002]', datetime('now'), datetime('now')),
 (940003, 940012, '990000431', 'text-5eed0431', 'host-5eed0431', 'Linux', 'user-5eed0431', '@@ENCRYPT(tok-5eed000000000431)@@', NULL, NULL, 0, NULL, NULL, '[940003]', datetime('now'), datetime('now')),
 (940004, 940012, '990000432', '', 'host-5eed0432', 'Windows', '', NULL, NULL, NULL, 0, NULL, NULL, NULL, datetime('now'), datetime('now')),
 (940005, 940014, '990000411', 'text-5eed0411', 'host-5eed0411', 'Windows', 'user-5eed0411', '@@ENCRYPT(tok-5eed0000000004a5)@@', NULL, NULL, 0, NULL, NULL, '[]', datetime('now'), datetime('now')),
 (940006, 940015, '990000412', 'text-5eed0412', 'host-5eed0412', 'Mac OS', 'user-5eed0412', '@@ENCRYPT(tok-5eed0000000004a6)@@', NULL, NULL, 0, NULL, NULL, '[]', datetime('now'), datetime('now'));

INSERT INTO audit_connections (id, action, conn_id, rustdesk_id, from_peer, from_name, ip, session_id, conn_type, uuid, guid, note, note_user_id, created_at, updated_at) VALUES
 (940001, 'authorized', 1, '990000451', '990000411', 'text-5eed0411', '198.18.4.11', 'tok-5eed000000007001', 0, NULL, '00000000-0000-4000-8000-0000000004f1', NULL, NULL, datetime('now'), datetime('now')),
 (940002, 'authorized', 2, '990000451', '990000411', 'text-5eed0411', '198.18.4.11', 'tok-5eed000000007002', 0, NULL, NULL, NULL, NULL, datetime('now'), datetime('now')),
 (940003, 'authorized', 3, '990000451', '990000412', 'text-5eed0412', '198.18.4.12', 'tok-5eed000000007003', 0, NULL, '00000000-0000-4000-8000-0000000004f3', 'text-5eed04f3', 940003, datetime('now'), datetime('now')),
 (940004, 'authorized', 4, '990000451', '990000411', 'text-5eed0411', '198.18.4.11', 'tok-5eed000000007001', 1, NULL, '00000000-0000-4000-8000-0000000004f4', NULL, NULL, datetime('now'), datetime('now')),
 (940005, 'authorized', 5, '990000452', '990000411', 'text-5eed0411', '198.18.4.11', 'tok-5eed000000007005', 0, NULL, '00000000-0000-4000-8000-0000000004f5', 'text-5eed04f5', 940003, datetime('now'), datetime('now'));
