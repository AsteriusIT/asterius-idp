# ADR-0017: Explicit enterprise approval for ID-JAG issuance

- **Status:** Provisional (IETF draft profile)
- **Date:** 2026-09-25
- **Bead:** ast-s36.19

## Decision

Asterius issues an Identity Assertion JWT Authorization Grant only from an ID
Token that this tenant issued to the authenticated managed agent. The agent
must prove a DPoP key. A tenant operator must configure the exact local agent
client ID, downstream authorization-server issuer, downstream client ID,
subject sector, resource set and scope set. No approval is inferred from the
subject token or from a URL sent in a request. The target subject is derived
from the local user account in the configured downstream SSO sector, avoiding
reuse of the requesting client's pairwise subject. The grant is typed
`oauth-id-jag+jwt`, carries an `act.client_id` and DPoP `cnf.jkt`, and expires
within five minutes and within the source ID Token's lifetime.

The current [ID-JAG draft -04](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04)
leaves `actor_token` validation and `act` processing to future profiles (§4.3.3
and §9.7). It also states that `client_id` continuity does not authenticate an
actor named by `act` (§4.4.1). This issuer refuses `actor_token` and records the
authenticated client in `act`. The offline downstream validator accepts only
keys pinned to an issuer by its caller and requires exact audience, client,
resource, scope, lifetime and DPoP bindings. Its local actor profile requires
the operator to pin the upstream actor client ID independently of the
downstream authenticated client. It accepts exactly `act: {"client_id":
<pinned actor>}`: one delegation hop, no nested `act`, extra actor attributes or
`may_act`. The signature and issuer key pin establish who asserted the actor;
the exact actor pin is a separate trust decision. `client_id` continuity
authenticates only the downstream client. The issuer currently creates this
single-hop shape from its authenticated agent.

This validator is a protective, stateless verification seam, not an enabled
redemption path. A Resource Authorization Server must explicitly trust the
issuer and its signing keys for this client, map the asserted subject under
that issuer, atomically reserve the issuer-scoped `jti`, check local consent
and resource/scope policy, verify the DPoP proof, and audit issuance before it
can issue an access token. A repeat use must not issue a second token in this
local profile. SAML and refresh-token subject assertions, rich authorization
details, multi-hop actor chains, and downstream redemption remain separate
work. The issuer advertises ID-JAG only for a tenant with at least one
configured approval and Token Exchange enabled.

## Consequences

A deployment can authorize a managed agent's cross-app access with a bounded,
audited grant. Its target authorization server still authenticates the mapped
client, validates the signed grant, and makes its own resource/scope decision;
this issuer cannot grant access merely by signing an ID-JAG.
