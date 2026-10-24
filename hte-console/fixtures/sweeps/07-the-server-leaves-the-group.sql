-- SYNTHETIC. The server leaves the device group: only administrators reach it now; 930004 lost it (new password).
UPDATE devices SET device_group_id = NULL WHERE rustdesk_id = '990003002';
