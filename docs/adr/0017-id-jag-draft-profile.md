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
leaves `actor_token` processing undefined. This profile refuses it and uses the
authenticated client as the actor. SAML and refresh-token subject assertions,
rich authorization details, and downstream redemption are separate work. The
issuer advertises ID-JAG only for a tenant with at least one configured
approval and Token Exchange enabled.

## Consequences

A deployment can authorize a managed agent's cross-app access with a bounded,
audited grant. Its target authorization server still authenticates the mapped
client, validates the signed grant, and makes its own resource/scope decision;
this issuer cannot grant access merely by signing an ID-JAG.
