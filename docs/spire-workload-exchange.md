# SPIRE workload subject exchange

This implements the [approved JWT-SVID contract](adr/spire-jwt-svid-exchange.md).
Use SPIRE 1.15.3 with an exact HTTPS `jwt_issuer` and JWT-SVID TTL at most300s.
Register a confidential Asterius client with independent private_key_jwt or
explicit OAuth mTLS authentication, DPoP and token-exchange permission. The SVID
is the external subject; it never authenticates that client or enrolls its key.

A tenant administrator creates `/admin/api/v1/workload-trusts/{trust_id}` with
`expected_version:null` for a new trust, or the current positive version for
replacement. Use provider `spiffe`, the exact canonical SPIFFE subject, the
single audience `urn:asterius:workload:<tenant>:<trust-id>`, a stable `workload:`
principal, explicit clients/scopes/resources/actions, empty `required_claims`,
and a configured subset of ES256/PS256/RS256. Default state is disabled.

The key configuration is:

```json
{"kind":"spiffe_bundle","trust_domain":"example.test","bundle":"{\"keys\":[],\"spiffe_sequence\":1}"}
```

The example deliberately has no authority and cannot authorize issuance. Export
real public SPIFFE JSON from the authenticated SPIRE control plane using
`spire-server bundle show -format spiffe`. Install that document as the raw JSON
string in `bundle`; its raw representation preserves duplicate-key rejection.
OAuth use=sig keys cannot replace SPIFFE use=jwt-svid authority. No bundle URL,
X.509 trust, auto-federation or private-network SSRF exception is introduced.

Install old+new native authorities for planned overlap, activate the new SPIRE
JWT authority, verify native issuance, then install the bundle without retired
keys. Empty bundles revoke issuance. Once a sequence is installed, replacements
must not roll it back or omit it; unchanged sequence requires unchanged content.
The sequence floor is retained across trust deletion and recreation.

Bundle transport is operator managed: remote removal has no automatic delivery
bound. A previously issued SVID and its derived token cannot survive the SVID's
signed expiry, bounded to300s from iat. A compromised signing authority can issue
until installed trust is removed or disabled. Offline access-token validation
retains existing expiry and resource-server revocation requirements.

## Controlled native interoperability

Pull the server and agent digests pinned in `scripts/spire/runtime.py`, then run:

```sh
python3 scripts/spire/runtime.py --binary /absolute/path/to/verified/asterius \
  --evidence /tmp/spire-runtime-evidence.json
```

The fixture requires local PostgreSQL on127.0.0.1:5433, Docker, Node, OpenSSL and
psql; ports9453 and9450 must be free. It creates a nonce database/network and
unpublished SPIRE server/agent containers, registers unix:uid:1000, and obtains
native SVIDs through the real agent Workload API. It tests verified HTTPS,
independent client authentication, DPoP-protected API access and native authority
rotation. It removes its own database, containers, network and private keys.
Failure diagnostics remain in a separate0700 directory with0600 files and may
contain sensitive native output; do not publish them.

Operator state is seeded directly in the owned runtime database to exercise
verification and minting. Actual repository CAS and upstream-sequence admission
are tested by the CI-only `spiffe_sequence_floor_survives_deletion_and_recreation`
regression. A successful fixture does not claim general SPIFFE federation,
hardware attestation, zero-latency revocation or a full local Rust suite.

SPIRE agents cache same-audience JWT-SVIDs. Asterius deliberately consumes each
assertion once: asking the Workload API for a cached already-spent SVID does not
provide a second exchange. The controlled rotation fixture restarts its owned
agent to force fresh native issuance without rewriting or resigning any SVID.
A production workload must account for that caching and assertion lifetime in
its token acquisition lifecycle; this adapter does not waive replay protection.
