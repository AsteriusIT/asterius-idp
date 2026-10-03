-- Correlation reads stay inside the tenant chain and resume by its event id.
create index audit_events_request_trace on audit_events (tenant_id, request_id, event_id desc)
    where request_id is not null;
create index audit_events_session_trace on audit_events (tenant_id, session_id, event_id desc)
    where session_id is not null;

-- Full bounded boolean traces expire independently of the immutable trail.
create table authorization_diagnostics (
    tenant_id text not null references tenants(tenant_id) on delete cascade,
    evidence_id uuid not null,
    diagnostics jsonb not null check (octet_length(diagnostics::text) <= 65536),
    created_at timestamptz not null,
    expires_at timestamptz not null check (expires_at > created_at),
    primary key (tenant_id, evidence_id)
);
create index authorization_diagnostics_expiry on authorization_diagnostics (tenant_id, expires_at);
