-- Keep verification evidence and process provenance with their verified bundle.
-- OIDC release filters these fields separately; this migration only retains them.
alter table verified_claim_bundles
    add column verification_process text,
    add column evidence jsonb not null default '[]'::jsonb,
    add constraint verified_claim_bundles_evidence_array
        check (jsonb_typeof(evidence) = 'array');
