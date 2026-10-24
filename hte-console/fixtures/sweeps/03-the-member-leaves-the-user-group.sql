-- SYNTHETIC. 930003 leaves user group 930201: 93001 closes (alarm 103, "... may no longer reach"); the front desk lost
-- a person and gets a new password; the server lost one too but still waits for its first to be confirmed.
DELETE FROM user_group_user WHERE user_id = 930003;
