# ADR-0012: MCP clients remain confidential

- **Status:** Accepted
- **Date:** 2026-09-18
- **Bead:** ast-m9c.8
- **Deciders:** Quentin RODIC
- **Refines:** [ADR-0002](0002-fapi-2-0-as-the-only-mode.md)

## Context

The MCP authorization specification and the FAPI 2.0 Security Profile describe
different client populations. MCP Authorization 2026-07-28 says authorization
servers must implement appropriate OAuth 2.1 security measures for both public
and confidential clients. FAPI 2.0 SP section 5.3.2.1 item 3 says an
authorization server shall support confidential clients only. ADR-0002 chose
the FAPI rule as a product invariant rather than a mode.

The conflict is concrete for an off-the-shelf desktop or CLI MCP client. It
normally has no safely provisioned client secret or private key, may need a
loopback callback, and does not necessarily implement PAR. Asterius requires
client authentication with `private_key_jwt` or mTLS, PAR, PKCE `S256`, DPoP
and an exactly registered redirect URI. Calling both shapes "MCP compatible"
would hide the part that cannot interoperate.

Client registration widened the gap while this decision was pending. MCP
Authorization 2026-07-28 prefers Client ID Metadata Documents (CIMD), retains
Dynamic Client Registration only for backwards compatibility, and tells a
client to choose between CIMD, pre-registration and DCR. CIMD makes an HTTPS
URL the `client_id`; the authorization server obtains the metadata at that URL.
The current IETF work is `draft-ietf-oauth-client-id-metadata-document-02`, not
an RFC, and introduces another attacker-controlled fetch plus mutable client
metadata. MCP's published page still links revision `-00`.

Two options were considered:

1. Keep the FAPI-only product and support only confidential MCP clients that
   can meet the existing Asterius profile.
2. Add a tenant-level OAuth 2.1 public-client profile: PKCE `S256`, DPoP-bound
   tokens, exact loopback redirects and optional PAR.

## Decision

**Asterius keeps option 1 for v1.** It registers no public client and does not
implement Client ID Metadata Documents. The authorization-server metadata
member `client_id_metadata_document_supported` is absent, rather than `false`,
because Asterius implements none of the CIMD protocol.

The MCP compatibility work in `ast-lh3.8` is limited to **confidential MCP
clients** that are pre-registered or use the backwards-compatible DCR path with
an inline public `jwks`, authenticate with `private_key_jwt`, push every
authorization request through PAR, use PKCE `S256`, and request DPoP-bound
tokens. Its documentation and tests must not claim compatibility with generic
off-the-shelf MCP clients or conformance to the complete MCP authorization
profile.

Option 2 is rejected for v1 because it removes an invariant on which client
authentication, PAR and readiness reporting rely. It is not rejected forever:
adopting it requires a new ADR and a separate tenant mode. That mode must make
`fapi_compliant=false` visible on readiness; it must never silently widen the
current mode. Reconsider it when CIMD is stable as an RFC and an OIDF
conformance profile defines the high-assurance public-client boundary Asterius
would be claiming.

## Consequences

**Easier.** The client model, token endpoint and authorization endpoint retain
one security contract. No URL-shaped unregistered client can bypass the stored
registration, no new outbound fetch is added, and the deployment-wide FAPI
readiness claim remains meaningful.

**Harder.** Most desktop and CLI MCP clients will not work without an adapter
or explicit confidential-client support. The latest MCP flow prefers CIMD and
deprecates DCR, so Asterius supports a narrowing compatibility path rather than
the protocol's default onboarding path. This limitation must be stated beside
every MCP integration example.

**Metadata and tests.** `client_id_metadata_document_supported` remains absent
under every capability combination. A regression test fixes that consequence
at the metadata producer. `ast-s36.2` tracks the evolving CIMD draft;
`ast-lh3.8` owns the confidential-client interoperability path.

**Future public-client mode.** A future implementation must be tenant-scoped,
must fail FAPI-compliant readiness, and must define how public client records,
PAR-optional requests, refresh-token DPoP binding, redirect handling, CIMD
fetching and conformance testing differ from the baseline. None of those paths
is pre-created by this decision.

## Spec clauses

| Clause | What it requires | How this decision satisfies it |
|---|---|---|
| FAPI 2.0 SP section 5.3.2.1 item 3 | Authorization servers support confidential clients only | Asterius continues to reject public clients globally |
| FAPI 2.0 SP section 5.3.2.1 items 4–6 | Access tokens are sender-constrained and clients authenticate with mTLS or `private_key_jwt` | The confidential MCP subset uses the existing FAPI token and authentication paths |
| FAPI 2.0 SP section 5.3.2.2 items 2–5 | Authorization requests use PAR and PKCE `S256` | The confidential MCP subset does not create an MCP-specific bypass |
| MCP Authorization 2026-07-28, Overview items 1–3 | Covers public and confidential clients, recommends CIMD, and retains DCR for backwards compatibility | Asterius deliberately does not claim the full profile; it exposes only a confidential DCR/pre-registration compatibility subset |
| MCP Authorization 2026-07-28, Client Registration | An MCP client obtains an id through CIMD, pre-registration or DCR | Asterius supports pre-registration and policy-gated DCR for confidential clients; metadata does not advertise CIMD |
| `draft-ietf-oauth-client-id-metadata-document-02` section 6 | A supporting authorization server advertises `client_id_metadata_document_supported` | The member is absent because Asterius does not fetch or process CIMD |

Every clause listed here was checked against its published text on 2026-09-18.
