# OpenID4VCI identity credential profile

This server implements the OpenID4VCI 1.0 authorization-code flow for one
`jwt_vc_json` credential configuration per tenant. The only supported VC type
is `AsteriusIdentityCredential`. It asserts the current grant's subject and,
only when explicitly allowed by tenant policy, the user's verified email. It
does not issue degree, licence, role, group, or other scheme-specific claims.

## Enable a tenant

1. Activate an EdDSA signing key for the tenant.
2. Register `{issuer}/credential` as a resource server under
   `/admin/api/v1/resource-servers/{url-encoded-identifier}` with a `scopes`
   array containing the credential scope (for example `vc_identity`). If the
   policy releases email, include the standard `email` scope too. The resource
   must be registered in the same tenant as the issuer.
3. Add that resource to the wallet client's authorized resource list at
   `/admin/api/v1/clients/{client_id}/resources`. Register the same scope on
   the client. Existing OAuth client authentication, PKCE, DPoP or mTLS, and
   consent requirements still apply.
4. Update the tenant settings through
   `/admin/api/v1/tenants/{tenant_id}/settings`, retaining the other required
   settings fields. The `credential_issuance` member is:

   ```json
   {
     "id": "identity",
     "scope": "vc_identity",
     "credential_type": "AsteriusIdentityCredential",
     "claims": ["email"]
   }
   ```

   `claims: []` issues a subject-only credential. `email` requires a current,
   verified email address and an access token and grant carrying `email` as
   well as the credential scope; otherwise issuance is denied. Omit
   `credential_issuance` to preserve the current setting, or send `null` to
   disable it. A tenant that disables `grant_id` in access tokens cannot
   enable this profile, because issuance must re-check the exact grant.

Issuer metadata is served at `/.well-known/openid-credential-issuer` with the
tenant path inserted after that well-known name. For an issuer
`https://example.com/t/demo`, the metadata URL is
`https://example.com/.well-known/openid-credential-issuer/t/demo`. A direct
authorization-code offer is served at `{issuer}/credential-offer`; it contains
no subject data or grant code. An initiator can pass its URL as the
`credential_offer_uri` parameter of an `openid-credential-offer://` URI.

## Wallet flow

The wallet requests the configuration's scope and `{issuer}/credential`
resource through the normal authorization-code flow, obtains consent, and
redeems the code at the tenant token endpoint. The access token must name the
credential resource as audience and carry the same scope. A wallet requesting
a configuration with `email` also requests the standard `email` scope. This profile does
not implement the pre-authorized-code or deferred flows.

The wallet sends `POST {issuer}/nonce` without authentication. The response
contains `c_nonce` and `Cache-Control: no-store`. It signs a JWT key proof
with ES256, embeds its public P-256 JWK in the header, sets
`typ: openid4vci-proof+jwt`, `aud` to the exact tenant issuer, `iat` to the
current time, `nonce` to that challenge, and `iss` to its OAuth client ID if
it supplies `iss`. One nonce can be spent only once and expires after five
minutes. Public nonce requests are limited to 60 per address per five minutes.

The wallet sends `POST {issuer}/credential` with `Content-Type:
application/json`, its access token under the `DPoP` or `Bearer` scheme the
token's sender constraint requires, and the corresponding DPoP proof or
certificate. The JSON body is:

```json
{
  "credential_configuration_id": "identity",
  "proofs": {"jwt": ["<signed wallet key proof>"]}
```

The server re-checks the token audience, sender constraint, revocation,
scope, live grant, grant subject and active account. It then verifies and
consumes the wallet nonce, signs one EdDSA JWT VC bound to the proven wallet
JWK, and audits the issuance without storing the VC or its private claims.
The VC expires after one hour. Credential requests are limited to 120 per
address per five minutes. Encrypted requests/responses, multiple proofs,
other credential formats, and arbitrary claim sets are not advertised.

The protocol choices above follow [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html),
especially §§7–8, §12.2, and Appendix A.1.1 and F.1.
