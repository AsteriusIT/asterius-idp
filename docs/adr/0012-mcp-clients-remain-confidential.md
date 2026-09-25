# ADR-0012: Public OAuth clients are an explicit tenant exception

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

**The deployment remains FAPI-first, with an explicit tenant opt-in for public
OAuth clients.** The default profile and readiness claim remain FAPI-only. A
tenant that enables non-FAPI clients may create a public client through the
administrator-managed client registry. Its profile is explicit and distinct
from confidential OIDC. It has no client secret or JWK authentication; it
requires authorization code plus PKCE `S256`, DPoP-bound tokens, and a DPoP key
pin on every authorization code. PAR is supported but optional. Redirect URIs
remain exact HTTPS or native loopback URIs. FAPI tenants continue to reject
this profile. Dynamic registration remains confidential-only in this slice.
The non-FAPI profile and tenant opt-in are explicit in client and tenant
administration; process readiness remains a deployment-level health signal.

Client ID Metadata Documents are still not implemented. The authorization-
server metadata member `client_id_metadata_document_supported` remains absent;
this slice does not fetch or trust URL-shaped client identifiers.

The MCP compatibility work in `ast-lh3.8` is limited to **confidential MCP
clients** that are pre-registered or use the backwards-compatible DCR path with
an inline public `jwks`, authenticate with `private_key_jwt`, push every
authorization request through PAR, use PKCE `S256`, and request DPoP-bound
tokens. Its documentation and tests must not claim compatibility with generic
off-the-shelf MCP clients or conformance to the complete MCP authorization
profile.

The tenant opt-in narrows option 2 to a separate profile and registry path. It
does not relax FAPI clients: their asymmetric authentication, PAR requirement,
sender constraint and conformance checks remain unchanged. Any future
tenant-scoped FAPI readiness indicator must report `fapi_compliant=false` when
this tenant opt-in is enabled. CIMD remains a separate follow-up because it
adds attacker-controlled metadata fetches and mutable client identity.

## Consequences

**Easier.** The FAPI profile retains its existing security contract. Public
clients are stored records with an explicit non-FAPI profile, PKCE S256, DPoP
code pinning and optional PAR; no URL-shaped identifier or outbound fetch is
added.

**Harder.** Public clients do not receive self-service dynamic registration in
this slice, and clients must implement DPoP even when they use direct
authorization instead of PAR. The latest MCP flow prefers CIMD, so Asterius
still does not provide the protocol's default onboarding path. This limitation
must be stated beside every MCP integration example.

**Metadata and tests.** `client_id_metadata_document_supported` remains absent
under every capability combination. A regression test fixes that consequence
at the metadata producer. `ast-s36.2` tracks the evolving CIMD draft;
`ast-lh3.8` owns the confidential-client interoperability path.

**Future CIMD support.** It must remain tenant-scoped and fail FAPI-compliant
readiness. It must define SSRF-safe document fetching, origin/key binding,
metadata lifecycle, redirect validation and conformance testing. This decision
does not pre-create those paths.

## Spec clauses

| Clause | What it requires | How this decision satisfies it |
|---|---|---|
| FAPI 2.0 SP section 5.3.2.1 item 3 | Authorization servers support confidential clients only | Public clients are confined to an explicitly non-FAPI tenant profile; FAPI tenants continue to reject them |
| FAPI 2.0 SP section 5.3.2.1 items 4–6 | Access tokens are sender-constrained and clients authenticate with mTLS or `private_key_jwt` | The confidential MCP subset uses the existing FAPI token and authentication paths |
| FAPI 2.0 SP section 5.3.2.2 items 2–5 | Authorization requests use PAR and PKCE `S256` | The confidential MCP subset does not create an MCP-specific bypass |
| MCP Authorization 2026-07-28, Overview items 1–3 | Covers public and confidential clients, recommends CIMD, and retains DCR for backwards compatibility | Asterius deliberately does not claim the full profile; it exposes only a confidential DCR/pre-registration compatibility subset |
| MCP Authorization 2026-07-28, Client Registration | An MCP client obtains an id through CIMD, pre-registration or DCR | Asterius supports pre-registration and policy-gated DCR for confidential clients; metadata does not advertise CIMD |
| `draft-ietf-oauth-client-id-metadata-document-02` section 6 | A supporting authorization server advertises `client_id_metadata_document_supported` | The member is absent because Asterius does not fetch or process CIMD |

Every clause listed here was checked against its published text on 2026-09-18.
