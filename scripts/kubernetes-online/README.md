# Disposable online Kubernetes acceptance

Run `ASTERIUS_BIN=/path/to/verified/candidate bash scripts/kubernetes-online/run.sh`.
The runner requires the online candidate binary; it does not compile Rust. It
builds the production Go adapter, starts only its own nonce local PostgreSQL
DB/server9468/adapter9470/kind asterius-dd1y15, and cleans them on completion.
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

Committed evidence describes the direct single-adapter run. Additional replicas
and delayed TLS transport remain separate pending controls, not implied passes.
Human normative delivery review remains pending; this script does not authorize
production rollout or main merge.
