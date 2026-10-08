# Standalone Entra provisioning adapter

Approved boundary for ast-9mjp / ast-p3p3: native Entra authenticates to this
separate process with an operator-installed opaque credential. The adapter calls
existing Asterius SCIM with ES256 `private_key_jwt`, a fresh DPoP proof per
request, and exactly `admin.scim:read admin.scim:write` for the pinned tenant
issuer's `/admin/api/v1` resource. Asterius authentication and mandatory
`If-Match` remain intact. No server Rust change or new Asterius Bearer route.

Requires Node 24+ (built-in SQLite), no npm dependencies. Run checks:

```sh
node --test scripts/entra-scim-adapter/adapter.test.mjs
node scripts/entra-scim-adapter/server.mjs /private/adapter-config.json
```

Create a dedicated tenant automation client with ES256 private-key JWT,
client-credentials, DPoP, the two SCIM scopes and exact resource allowlist. Its
SCIM namespace must be reserved for this integration. Install its private P-256
PKCS8 key in a private regular file. Do not share another provisioning client's
namespace or reuse browser/API client credentials.

Example configuration (all paths operator-owned, configuration mode 0600):

```json
{
  "issuer": "https://id.example/t/disposable-tenant",
  "clientId": "dedicated-entra-client",
  "keyId": "registered-signing-key-id",
  "keyFile": "/private/client-key.pem",
  "publicBase": "https://adapter.example/integration/scim/v2",
  "credentialFile": "/private/entra-credential.json",
  "database": "/private/entra-state.sqlite",
  "bind": "127.0.0.1",
  "port": 9490
}
```

Expose only the loopback HTTP listener through an HTTPS reverse proxy with the
exact configured base path. Preserve path/headers and redact Authorization and
request/response bodies from proxy logs. Do not disable TLS certificate
verification. Backend issuer and adapter base are separately pinned.

Credential file (0600) contains the exact adapter audience and one or two
independently expiring records:

```json
{
  "audience": "https://adapter.example/integration/scim/v2",
  "tokens": [{
    "value": "OPERATOR_GENERATED_RANDOM_BASE64URL_TOKEN_AT_LEAST_43_CHARACTERS",
    "createdAt": "2026-10-08T12:00:00Z",
    "expiresAt": "2026-10-15T12:00:00Z",
    "revoked": false
  }]
}
```

Generate at least 256 random bits; install the plaintext only through Entra's
Secret Token setting and this private file. Seven days is the suggested lifetime;
30 days is enforced maximum. Rotate manually before expiry; two records allow
bounded operator-managed overlap. Replace the file atomically to revoke/rotate:
it is read afresh for every request. No positive authentication cache, refresh
or automatic renewal. Keep overlap under 24 hours operationally. Incoming
credentials never authenticate to Asterius. Logs contain only method/status.
The SQLite state contains provisioning identities and intents; protect and
back up it and its WAL alongside configuration, without committing them.

In Entra's SCIM provisioning configuration set Tenant URL to `publicBase` and
Secret Token to the isolated token. Configure these mappings only:

| Entra attribute | SCIM attribute |
| --- | --- |
| objectId | externalId (stable, immutable) |
| userPrincipalName | userName |
| accountEnabled | active (JSON boolean) |
| mail | emails[type eq "work"].value |

Remove default name, displayName on Users, roles, password and extension
mappings. Groups use displayName, immutable externalId and existing managed
User IDs as members. Unsupported fields and legacy string booleans are refused.
References and metadata locations translate between exact configured bases;
Asterius enforces membership/managed-group authority and security locks.

Queries accept exact `userName eq`, `displayName eq` for their respective types,
and `externalId eq` through the durable local mapping. Pagination is bounded to
startIndex 1..10001/count 0..200. Projection supports Users groups/emails and
Groups members only. Unknown/duplicate parameters fail. PATCH uses the existing
bounded user/group paths, 1..20 operations; externalId cannot change.

For mutations, a supplied exact ETag must match. When Entra omits it, the adapter
GETs the owned resource, then sends one conditional write with its current ETag.
A racing change returns 412; the adapter never refetches to overwrite it. Locked
409 and foreign 404 propagate. Successful identical writes may return a durable
receipt only while the same resulting ETag remains current.

Creates persist an intent before the upstream call and atomically record the
source identity/returned ID. A lost create response recovers only one exact
owned name plus matching externalId; it never adopts by email. Duplicate creates
with different content refuse 409. DELETE retries are idempotent for recorded
owned deletion. After a lost PATCH/PUT response, a changed upstream ETag makes
retries ambiguous: they refuse 409 for explicit reconciliation. Do not delete
journal entries to force a retry without examining current source/target state.
A stale process lock after a crash similarly requires confirming the old process
is gone before removing only this adapter's `.lock` file. One process per state
file; requests serialize. Deployment needs restart supervision and backups.

Eight focused local tests cover signed token/DPoP nonce+ath/audience, stale ETag,
locked/foreign mutations, durable lost-create recovery, reordered ambiguous
writes, projection, revoked credentials, persistence and deletion retries.
No native Entra job or live Asterius handoff has been run for this adapter.
Actual validateCredentials and full disposable user/group lifecycle, retry,
revocation and security controls remain required before interoperability closure.
Cloud application/job creation must be separately authorized after reviewing
its exact disposable payload and mappings.
