-- NULL preserves the historical generated username for new OIDC accounts.
-- A configured value names one top-level, signed ID-token claim.
alter table oidc_identity_providers
    add column username_claim text
    check (username_claim is null or
           (length(username_claim) between 1 and 128 and
            username_claim = btrim(username_claim) and
            username_claim !~ '[[:cntrl:]]'));
