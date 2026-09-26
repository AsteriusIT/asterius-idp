-- Absence is observed only after a complete bounded one-shot snapshot. The
-- first observation is a tombstone, never an immediate deactivation/deletion.
alter table ldap_user_owners
    add column missing_since timestamptz,
    add column disabled_by_ldap_at timestamptz;

alter table ldap_group_owners
    add column missing_since timestamptz;

create index ldap_user_owners_missing
    on ldap_user_owners (tenant_id, source_key, missing_since)
    where missing_since is not null;

create index ldap_group_owners_missing
    on ldap_group_owners (tenant_id, source_key, missing_since)
    where missing_since is not null;
