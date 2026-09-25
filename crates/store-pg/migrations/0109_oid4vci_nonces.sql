-- OpenID4VCI 1.0 §7: public, short-lived credential proof challenges.
-- Only a SHA-256 digest is stored. A single conditional UPDATE consumes a
-- nonce so concurrent credential requests cannot both pass freshness checks.
CREATE TABLE oid4vci_nonces (
    tenant_id text NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    nonce_digest bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    PRIMARY KEY (tenant_id, nonce_digest),
    CONSTRAINT oid4vci_nonce_digest_length CHECK (octet_length(nonce_digest) = 32)
);

CREATE INDEX oid4vci_nonces_expiry ON oid4vci_nonces (tenant_id, expires_at);
