-- Phase 2 (client sign-in): the accounts, settings and devices the synthetic sign-in fixtures expect. Placeholders
-- only; the passwords are placeholder-shaped test values (bcrypt, cost 12), the TOTP secret is RFC 6238's test key.
-- Markers, filled in per replay by `hte-console seed-expand`: @@IDP@@ (the fake identity provider's URL, also its
-- issuer), @@ENCRYPT(...)@@ (Crypt::encryptString under the replay database's own app key).

-- 910002 break-glass: local, admin, password tok-5eed00000000b002
INSERT INTO users (id, username, name, email, password, is_admin, is_active, auth_provider, created_at, updated_at) VALUES
 (910002, 'user-5eed0002', 'text-5eed0002', 'user-5eed000002@example.invalid', '$2y$12$3wIwkZeCjcZyF8sX1rS5feMamonmbx8BhEuI6ocFNk.2/XQn8QAe2', 1, 1, 'local', datetime('now'), datetime('now'));
-- 910003 disabled, same password
INSERT INTO users (id, username, name, email, password, is_admin, is_active, auth_provider, created_at, updated_at) VALUES
 (910003, 'user-5eed0003', 'text-5eed0003', 'user-5eed000003@example.invalid', '$2y$12$3wIwkZeCjcZyF8sX1rS5feMamonmbx8BhEuI6ocFNk.2/XQn8QAe2', 0, 0, 'local', datetime('now'), datetime('now'));
-- 910004 created by the identity provider (password tok-5eed00000000b004, never usable)
INSERT INTO users (id, username, name, email, password, is_admin, is_active, auth_provider, oidc_iss, oidc_sub, oidc_status, created_at, updated_at) VALUES
 (910004, 'user-5eed0004', 'text-5eed0004', 'user-5eed000004@example.invalid', '$2y$12$qK2l4a.3oOYYGZWjXNHjG.TBa6vIGKOvEShLaYgeH06gQGRzG0EiC', 0, 1, 'oidc', '@@IDP@@', 'sub-5eed-u4', 'active', datetime('now'), datetime('now'));
-- 910005 local, waiting for approval
INSERT INTO users (id, username, name, email, password, is_admin, is_active, auth_provider, oidc_status, created_at, updated_at) VALUES
 (910005, 'user-5eed0005', 'text-5eed0005', 'user-5eed000005@example.invalid', '$2y$12$3wIwkZeCjcZyF8sX1rS5feMamonmbx8BhEuI6ocFNk.2/XQn8QAe2', 0, 1, 'local', 'pending', datetime('now'), datetime('now'));
-- 910006 with TOTP
INSERT INTO users (id, username, name, email, password, is_admin, is_active, auth_provider, totp_secret, totp_enabled, created_at, updated_at) VALUES
 (910006, 'user-5eed0006', 'text-5eed0006', 'user-5eed000006@example.invalid', '$2y$12$3wIwkZeCjcZyF8sX1rS5feMamonmbx8BhEuI6ocFNk.2/XQn8QAe2', 0, 1, 'local', '@@ENCRYPT(GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ)@@', 1, datetime('now'), datetime('now'));
-- 910008 local, linked by email on the first SSO sign-in (profile "linked")
INSERT INTO users (id, username, name, email, password, is_admin, is_active, auth_provider, created_at, updated_at) VALUES
 (910008, 'user-5eed0008', 'text-5eed0008', 'user-5eed000008@example.invalid', '$2y$12$3wIwkZeCjcZyF8sX1rS5feMamonmbx8BhEuI6ocFNk.2/XQn8QAe2', 0, 1, 'local', datetime('now'), datetime('now'));
-- 910009 already linked (profile "known"); its name is refreshed from the token
INSERT INTO users (id, username, name, email, password, is_admin, is_active, auth_provider, oidc_iss, oidc_sub, oidc_status, created_at, updated_at) VALUES
 (910009, 'user-5eed0009', 'text-01d00009', 'user-5eed000009@example.invalid', '$2y$12$3wIwkZeCjcZyF8sX1rS5feMamonmbx8BhEuI6ocFNk.2/XQn8QAe2', 0, 1, 'local', '@@IDP@@', 'sub-5eed-known', 'active', datetime('now'), datetime('now'));
-- 910010 linked but disabled (profile "disabled")
INSERT INTO users (id, username, name, email, password, is_admin, is_active, auth_provider, oidc_iss, oidc_sub, oidc_status, created_at, updated_at) VALUES
 (910010, 'user-5eed000a', 'text-5eed000a', 'user-5eed00000a@example.invalid', '$2y$12$3wIwkZeCjcZyF8sX1rS5feMamonmbx8BhEuI6ocFNk.2/XQn8QAe2', 0, 0, 'local', '@@IDP@@', 'sub-5eed-disabled', 'active', datetime('now'), datetime('now'));

-- SSO through the fake provider; password sign-in stays on (break-glass); new people are provisioned active;
-- a pending device is approved on sign-in. The approval gate stays off (phase 1's fixtures assume it off).
INSERT INTO settings (key, value, created_at, updated_at) VALUES
 ('oidc_enabled', '1', datetime('now'), datetime('now')),
 ('oidc_discovery_url', '@@IDP@@', datetime('now'), datetime('now')),
 ('oidc_client_id', 'client-seed', datetime('now'), datetime('now')),
 ('oidc_client_secret', 'tok-5eed00000000c11e', datetime('now'), datetime('now')),
 ('oidc_button_label', 'Sign in with Microsoft', datetime('now'), datetime('now')),
 ('oidc_new_user_policy', 'active', datetime('now'), datetime('now')),
 ('oidc_allowed_domains', 'example.invalid', datetime('now'), datetime('now')),
 ('auto_approve_signed_in', '1', datetime('now'), datetime('now'));

-- devices: two pending without an owner (one for a password sign-in, one for SSO), one deleted
INSERT INTO devices (rustdesk_id, uuid, status, created_at, updated_at) VALUES ('990000201', 'UExBQ0VIT0xERVIhAAAA0g==', 'pending', datetime('now'), datetime('now'));
INSERT INTO devices (rustdesk_id, uuid, status, created_at, updated_at) VALUES ('990000202', 'UExBQ0VIT0xERVIhAAAA0w==', 'pending', datetime('now'), datetime('now'));
INSERT INTO devices (rustdesk_id, uuid, status, deleted_at, created_at, updated_at) VALUES ('990000204', 'UExBQ0VIT0xERVIhAAAA1A==', 'pending', datetime('now'), datetime('now'), datetime('now'));
