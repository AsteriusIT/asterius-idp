-- Existing rows may have been inserted outside the unfinished CP setup API.
-- Preserve them for an explicit recovery or migration; the application fails
-- closed on any active legacy row and writes only encrypted replacements.
alter table aggregated_claim_sources
    alter column signed_userinfo drop not null,
    add column ciphertext bytea,
    add column nonce bytea,
    add column kek_id text,
    add constraint aggregated_claim_sources_ciphertext_size
        check (ciphertext is null or octet_length(ciphertext) between 17 and 8208),
    add constraint aggregated_claim_sources_nonce_size
        check (nonce is null or octet_length(nonce) = 12),
    add constraint aggregated_claim_sources_storage_shape
        check (
            (signed_userinfo is not null and ciphertext is null and nonce is null and kek_id is null)
            or
            (signed_userinfo is null and ciphertext is not null and nonce is not null and kek_id is not null)
        );

create unique index aggregated_claim_sources_nonce_unique
    on aggregated_claim_sources (kek_id, nonce)
    where nonce is not null;
