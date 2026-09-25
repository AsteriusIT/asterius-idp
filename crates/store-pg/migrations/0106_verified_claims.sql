-- IDA verification records are separate from ordinary user claims: a claim
-- source or verified_at value alone must never become a verified_claims bundle.
create table verified_claim_bundles (
    tenant_id text not null,
    user_id uuid not null,
    bundle_id uuid not null,
    trust_framework text not null,
    verifier_issuer text not null,
    verified_at timestamptz not null,
    claims jsonb not null,
    created_at timestamptz not null default now(),
    revoked_at timestamptz,
    primary key (tenant_id, bundle_id),
    foreign key (tenant_id, user_id) references users (tenant_id, user_id) on delete cascade,
    check (jsonb_typeof(claims) = 'object')
);

create index verified_claim_bundles_by_user
    on verified_claim_bundles (tenant_id, user_id, created_at desc)
    where revoked_at is null;
