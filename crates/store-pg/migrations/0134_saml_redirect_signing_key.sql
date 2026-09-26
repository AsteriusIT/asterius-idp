-- Operator-pinned SP key for HTTP-Redirect query signatures. Existing SPs
-- have no key and remain unable to pass signed validation until reprovisioned.
alter table saml_sp_trusts
    add column redirect_signing_public_key_der bytea,
    add constraint saml_redirect_key_size
        check (redirect_signing_public_key_der is null
               or length(redirect_signing_public_key_der) between 256 and 4096);
