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

OIDC release policy is tracked separately under `ast-s36.20.3`. Until it is
configured, the presence of a bundle does not cause an ID Token or UserInfo
response to include `verified_claims`.
