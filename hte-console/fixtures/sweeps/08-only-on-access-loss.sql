-- SYNTHETIC. "Only when someone loses access": a password confirmed 400 days ago is not changed.
UPDATE settings SET value = '0' WHERE key = 'hte_pw_days';
UPDATE hte_device_passwords SET confirmed_version = current_version, confirmed_enc = current_enc, confirmed_at = datetime('now', '-400 days') WHERE current_version > 0;
