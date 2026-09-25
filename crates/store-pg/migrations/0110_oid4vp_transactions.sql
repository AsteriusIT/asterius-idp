-- OID4VP direct_post state is a short-lived, single-use transaction secret.
-- Only its digest is stored. One conditional UPDATE consumes it before any
-- response can be accepted, including under concurrent requests/replicas.
CREATE TABLE oid4vp_transactions (
    tenant_id text NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    state_digest bytea NOT NULL,
    nonce text NOT NULL,
    client_id text NOT NULL,
    credential_id text NOT NULL,
    verifier_id text NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    PRIMARY KEY (tenant_id, state_digest),
    CONSTRAINT oid4vp_state_digest_length CHECK (octet_length(state_digest) = 32)
);

CREATE INDEX oid4vp_transactions_expiry ON oid4vp_transactions (tenant_id, expires_at);
