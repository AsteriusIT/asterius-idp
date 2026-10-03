# Disposable online Kubernetes acceptance

Run `ASTERIUS_BIN=/path/to/verified/candidate bash scripts/kubernetes-online/run.sh`.
The runner requires the online candidate binary; it does not compile Rust. It
builds the production Go adapter, starts only its own nonce local PostgreSQL
DB/server9468/adapters9470+9471/opaque TLS transport9472/kind asterius-dd1y15, and cleans them on completion.
Existing cluster, issuer container and occupied listener names are refused.
All Kubernetes access uses an explicit own kubeconfig; human reads attach only
bearer credentials. PostgreSQL outages target only ast_online_* on localhost5433
and restore connection admission in finally. No shared server/database is stopped.

The initial browser sessions and historical methods are controlled seeds. A real
password proof reaches StepUp after an absent assigned ACR precondition and
rotates the secret cookie while preserving public SID. Real PAR/PKCE/private-key
JWT/DPoP/code/refresh, mTLS, exact grant revocation, group lifecycle, user disable,
logout, CC reviewer receipt revocation, table-lock timeout and outages are network
paths. No fresh WebAuthn ceremony is claimed. Console writes include real CSRF.
Only aggregate control names and timings are printed; keys/cookies/tokens live in
a0600 scratch directory which is removed. No fixture receipt/digest binding is
seeded: successful issuance must create them through production hooks.

The initial committed checkpoint6f19aa89 records the direct single-adapter run.
The current runner additionally exercises two production adapters behind an
opaque TCP/TLS connection selector: it never decrypts TLS, changes HTTP or
substitutes the API-server certificate. One replica is terminated before an
uncached human token verifies failover to the surviving replica. Then an already
completed encrypted positive is externally held25 seconds, its exact grant is
revoked, and late arrival plus the outer10-second cache is measured. A separate
fresh original-grant refresh is held beyond the upstream30-second deadline;
release35 seconds later must never create a late positive cache entry.

Separate sanitized evidence records18 passing groups and exact timings. The
25+10-second trial exercises the stacked mechanism without claiming to saturate
the literal40-second worst-case boundary. Primary database replication and
final-signature/storage races remain unmeasured.
Human normative delivery review remains pending; this script does not authorize
production rollout or main merge.
