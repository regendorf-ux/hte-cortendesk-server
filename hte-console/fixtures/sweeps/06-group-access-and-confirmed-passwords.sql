-- SYNTHETIC. 930004 gets the device group through a group-access entry, and a user group of theirs through another;
-- the computers confirm the passwords they were sent: the books carry the new ones.
INSERT INTO user_groups (id, name, created_at, updated_at) VALUES (930202, 'text-5eed3202', datetime('now'), datetime('now'));
INSERT INTO user_group_user (user_group_id, user_id) VALUES (930202, 930004);
INSERT INTO group_accesses (accessor_type, accessor_id, target_type, target_id, created_at, updated_at) VALUES
 ('user', 930004, 'device_group', 930101, datetime('now'), datetime('now')),
 ('user_group', 930202, 'device_group', 930101, datetime('now'), datetime('now'));
UPDATE hte_device_passwords SET confirmed_version = current_version, confirmed_enc = current_enc, confirmed_at = datetime('now') WHERE current_version > 0;
