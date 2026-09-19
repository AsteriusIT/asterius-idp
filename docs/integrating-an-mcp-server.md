# MCP servers with Asterius

Asterius supports a deliberately narrow MCP authorization integration:
confidential clients that authenticate with `private_key_jwt`, use PAR and PKCE
`S256`, and receive DPoP-bound access tokens. It does not support public MCP
clients or Client ID Metadata Documents (CIMD), and
`client_id_metadata_document_supported` is therefore absent from discovery.
[ADR-0012](adr/0012-mcp-clients-remain-confidential.md) records that boundary.

This is not a claim of complete MCP Authorization 2026-07-28 conformance. In
particular, the official MCP TypeScript SDK does not currently orchestrate PAR;
an integration using it needs a confidential-client adapter that performs the
PAR and `private_key_jwt` steps, or a pre-registered client with equivalent
support.

## Register the confidential client

Enable the tenant preset through its `registration_policy` setting:

```json
{
  "profile": "mcp-confidential",
  "scopes": ["openid", "offline_access", "mcp:tools"],
  "resources": ["https://mcp.example.com/mcp"],
  "redirect_uri_hosts": ["client.example.com"]
}
```

The preset requires a tenant-issued initial access token and accepts only
authorization-code/refresh registrations using `private_key_jwt` with inline
keys. A DCR request is therefore shaped like this:

```http
POST /t/acme/register HTTP/1.1
Authorization: Bearer <initial-access-token>
Content-Type: application/json

{
  "client_name": "Acme MCP client",
  "redirect_uris": ["https://client.example.com/oauth/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid offline_access mcp:tools",
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks": { "keys": [{ "kty": "EC", "crv": "P-256", "kid": "mcp-1", "x": "…", "y": "…" }] }
}
```

After registration, an administrator first registers the canonical MCP URI on
the **Resource servers** screen, then opens the client on the **Applications**
screen and selects that audience under **Authorized resources**. These are two
different controls: the registry says which audiences exist for the tenant;
the client allow-list says which of them this client may request.

Automation can perform the second step with the tenant-scoped admin API:

```http
PUT /t/acme/admin/api/v1/clients/c.example/resources HTTP/1.1
Authorization: DPoP <admin-access-token>
DPoP: <proof>
Content-Type: application/json

{"resources":["https://mcp.example.com/mcp"]}
```

The operation is an explicit replacement. An empty array authorizes no
resource, and an unknown or other-tenant audience is refused. The allow-list
is authorization policy, not client-controlled RFC 7591 metadata: DCR POST
and RFC 7592 PUT ignore a `resources` member and preserve the administrator's
stored value.

Read discovery rather than constructing endpoint URLs. MCP clients may probe
the path-inserted RFC 8414 form, the path-inserted OIDC form, or the
path-appended OIDC form; Asterius serves the same document at all three. Push
the authorization request to PAR with PKCE `S256`, a fresh client assertion,
DPoP proof, and `resource=https://mcp.example.com/mcp`. Send the same exact
`resource` on the code exchange with another fresh assertion and proof.

Resource identifiers are compared as strings. If the registered canonical URI
is `https://mcp.example.com/mcp`, neither a trailing slash nor an uppercase host
matches it. A mismatch is `invalid_target`, even if a general URL library would
consider the URLs equivalent.

## Publish protected-resource metadata

The MCP server, not Asterius, publishes RFC 9728 metadata at the location
derived from its canonical resource URI. For example:

```json
{
  "resource": "https://mcp.example.com/mcp",
  "authorization_servers": ["https://id.example.com/t/acme"],
  "scopes_supported": ["mcp:tools"],
  "bearer_methods_supported": ["header"],
  "resource_documentation": "https://mcp.example.com/docs/auth"
}
```

When no usable credential is present, point the client at that document:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", scope="mcp:tools"
```

## Validate every request

For local RFC 9068 validation, the MCP server must:

1. Verify the JWT signature with the issuer's discovered `jwks_uri`, accept
   only the advertised algorithms, and require a known `kid`.
2. Require the exact `iss`, a live `exp`/`nbf`, and an `aud` equal to the exact
   canonical MCP resource URI. Reject merely URL-equivalent spellings.
3. Require every operation's scope in the space-delimited `scope` claim.
4. Require `cnf.jkt`, validate the request's DPoP proof signature and JWK
   thumbprint, then check `typ`, `alg`, `htm`, canonical `htu`, `iat`, unique
   `jti`, and `ath` over the presented access token.
5. Never pass the incoming token to an upstream API. Obtain a separately
   audienced token for that hop.

An MCP server may instead use Asterius introspection. Its confidential
credential must be listed in that resource server's `introspection_clients`.
It must still require `active: true`, exact `aud`, sufficient `scope`, a live
expiry, and the `cnf` binding that matches the request's DPoP proof.

If the token is valid but lacks authority, answer with a step-up challenge:

```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope", scope="mcp:tools", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
```

The client then starts a new authorization flow for the advertised scope and
the same canonical resource. The MCP server must not broaden the old token or
forward it as a substitute.
