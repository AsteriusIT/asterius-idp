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
resource, scope, lifetime and DPoP bindings. It refuses `act` and `may_act`
until an actor validation profile is approved. Therefore it deliberately
refuses grants from this issuer; it is a protective verification seam, not an
enabled redemption path. SAML and refresh-token subject assertions, rich
authorization details, actor-chain validation, replay reservation, user
mapping, consent and downstream redemption remain separate work. The issuer
advertises ID-JAG only for a tenant with at least one configured approval and
Token Exchange enabled.

## Consequences

A deployment can authorize a managed agent's cross-app access with a bounded,
audited grant. Its target authorization server still authenticates the mapped
client, validates the signed grant, and makes its own resource/scope decision;
this issuer cannot grant access merely by signing an ID-JAG.
