-- Retain upstream ordering when an operator deletes and recreates a trust.
create table workload_spiffe_bundle_history (
    tenant_id text not null references tenants(tenant_id) on delete cascade,
    trust_id text not null,
    trust_domain text not null,
    snapshot jsonb not null check(jsonb_typeof(snapshot) = 'object'),
    primary key (tenant_id, trust_id, trust_domain)
);
alter table workload_grant_bindings drop constraint workload_grant_bindings_provider_check;
alter table workload_grant_bindings add constraint workload_grant_bindings_provider_check
    check(provider in ('kubernetes', 'github', 'spiffe'));
alter table workload_grant_bindings add column source_subject text;
alter table workload_grant_bindings add column trust_domain text;
alter table workload_grant_bindings add constraint workload_spiffe_provenance_check
    check(provider <> 'spiffe' or (source_subject is not null and trust_domain is not null));
