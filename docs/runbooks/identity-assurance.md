# Identity Assurance verification records

The admin API keeps verified identity bundles apart from ordinary user claims.
`source` and `verified_at` on a regular claim do not make it an OpenID Identity
Assurance assertion.

Tenant administrators with `admin.users:read` can list live records at
`GET /admin/api/v1/users/{user_id}/verified-claims`. Creating one uses `POST`
on the same path with an `Idempotency-Key` and JSON containing `verified_at`
(RFC 3339) and a `claims` object. Revocation uses
`DELETE /admin/api/v1/users/{user_id}/verified-claims/{bundle_id}`. Mutations
require a console session whose most recent authentication was a passkey
within two minutes; automation credentials are refused. The verifier is the
tenant issuer and the framework is fixed to `internal_admin_verification`.
The caller cannot supply either field.

Writes and revocations append a subject-bound audit event in the same database
transaction, recording the bundle identifier and framework but no claim
values. A revoked record is never returned by the live-record listing.

OIDC release is disabled by default. Set `ida_frameworks` in tenant settings to
an explicit list of permitted trust framework identifiers, for example
`["internal_admin_verification"]`. An empty list disables release. A client
must request `verified_claims` in the authorization `claims` parameter under
`id_token`, `userinfo`, or both. The consent page names each requested
attribute, destination, and framework. The grant records that request;
remembered consent cannot silently cover a different framework or attribute.

The server selects a current, nonrevoked bundle in an allowed framework at each
ID Token issuance and UserInfo response. It releases only requested attributes
with `verification` provenance, without the internal verifier issuer or any
evidence. Revoking a bundle removes it from later refresh ID Tokens and
UserInfo responses. Already issued ID Tokens remain valid until their expiry.
