-- Existing SP rows remain unusable for request validation until an operator
-- explicitly chooses the unsigned-request exception. Signed XML and Redirect
-- query signatures are not verified by this release.
alter table saml_sp_trusts
    add column allow_unsigned_requests boolean not null default false;
