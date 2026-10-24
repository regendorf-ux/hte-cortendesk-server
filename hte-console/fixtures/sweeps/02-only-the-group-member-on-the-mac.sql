-- SYNTHETIC. Only 930003 stays signed in on the Mac: the user group still holds the server's device group, 93001 stays.
DELETE FROM client_tokens WHERE device_id = '990003004' AND user_id <> 930003;
