-- OIDC Registration §2: explicit signed-then-encrypted response preferences.
-- Existing clients retain plaintext responses unless they opt in through a
-- validated replacement registration. Both columns are changed atomically
-- with the rest of the client row.
ALTER TABLE clients
    ADD COLUMN encrypt_id_token boolean NOT NULL DEFAULT false,
    ADD COLUMN encrypt_userinfo boolean NOT NULL DEFAULT false;
