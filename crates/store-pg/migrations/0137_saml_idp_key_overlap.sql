-- Permit a staged certificate to be distributed before activation and retain
-- the former active certificate until an operator explicitly retires it.
-- Existing tenants' sole key remains active after this migration.
alter table saml_idp_signing_keys
    drop constraint saml_idp_signing_keys_pkey;

alter table saml_idp_signing_keys
    add primary key (tenant_id, certificate_sha256),
    alter column private_key_ciphertext drop not null,
    alter column private_key_nonce drop not null,
    alter column kek_id drop not null,
    add column state text not null default 'active',
    add column activated_at timestamptz,
    add column retiring_at timestamptz,
    add column retired_at timestamptz,
    add constraint saml_idp_key_state
        check (state in ('pending', 'active', 'retiring', 'retired')),
    add constraint saml_idp_retired_material_erased
        check ((state = 'retired' and private_key_ciphertext is null
                and private_key_nonce is null and kek_id is null)
            or (state <> 'retired' and private_key_ciphertext is not null
                and private_key_nonce is not null and kek_id is not null));

update saml_idp_signing_keys
   set activated_at = created_at
 where state = 'active';

create unique index saml_idp_one_active_key
    on saml_idp_signing_keys (tenant_id) where state = 'active';

create unique index saml_idp_one_pending_key
    on saml_idp_signing_keys (tenant_id) where state = 'pending';

create unique index saml_idp_one_retiring_key
    on saml_idp_signing_keys (tenant_id) where state = 'retiring';

create index saml_idp_published_keys
    on saml_idp_signing_keys (tenant_id, state)
    where state in ('pending', 'active', 'retiring');
