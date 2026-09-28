-- An upstream subject has meaning only within its exact issuer and provider.
-- Keep rows when a provider is disabled. Deletion requires explicit unlink.
alter table oidc_identity_providers
    add column allow_registration boolean not null default false;

alter table oidc_identity_providers
    add constraint oidc_identity_providers_exact_issuer
    unique (tenant_id, provider_id, issuer);

create table oidc_identity_bindings (
    tenant_id text not null,
    provider_id text not null,
    issuer text not null,
    upstream_subject text not null,
    user_id uuid not null,
    created_at timestamptz not null default now(),
    primary key (tenant_id, provider_id, issuer, upstream_subject),
    foreign key (tenant_id, provider_id, issuer)
        references oidc_identity_providers (tenant_id, provider_id, issuer) on delete restrict,
    foreign key (tenant_id, user_id)
        references users (tenant_id, user_id) on delete cascade,
    check (length(issuer) between 1 and 2048),
    check (length(upstream_subject) between 1 and 1024)
);

create unique index oidc_identity_bindings_one_subject_per_user
    on oidc_identity_bindings (tenant_id, provider_id, issuer, user_id);

create index oidc_identity_bindings_by_user
    on oidc_identity_bindings (tenant_id, user_id);
