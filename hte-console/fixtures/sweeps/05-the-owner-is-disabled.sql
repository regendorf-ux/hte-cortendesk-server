-- SYNTHETIC. The owner is disabled: 93005 closes ("the person signed in on ... is disabled"); their book is emptied.
UPDATE users SET is_active = 0 WHERE id = 930002;
