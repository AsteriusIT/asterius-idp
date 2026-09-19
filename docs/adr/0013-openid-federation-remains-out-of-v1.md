# ADR-0013: Keep OpenID Federation out of v1 without narrowing the client model

- **Status:** Accepted
- **Date:** 2026-09-19
- **Bead:** ast-s36.4
- **Deciders:** Quentin RODIC

## Context

[OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0-final.html)
became an OpenID Final Specification on 2026-02-17. A newer 1.1 Final was
approved on 2026-05-06; this record addresses the 1.0 baseline named by the
product backlog, not an implementation commitment to either version.

Federation introduces Entity Statements, Trust Chains, metadata policy and
automatic or explicit registration. Automatic registration gives a relying
party's HTTPS Entity Identifier a second role as its Client ID and resolves the
party's configuration from that URL. Entity-type keys may be represented by an
HTTPS `jwks_uri` (or `signed_jwks_uri`) instead of only being embedded. These
are useful future seams, but implementing their discovery, policy evaluation,
trust-anchor administration and registration lifecycle is outside v1.

The current model can represent the two shapes that would otherwise force a
schema migration. `ClientId` is an opaque string and `clients.client_id` is
PostgreSQL `text`, so an HTTPS URL fits without a new identifier column.
`JwksSource::Uri` and `clients.jwks_uri` preserve keys by reference alongside
the existing inline form. This does not make current registrations Federation
entities: today Asterius assigns identifiers and validates registrations under
its existing FAPI and OIDC rules.

Two options were considered:

1. Implement Federation discovery and registration in v1.
2. Keep it out of v1 while preserving URL-shaped client identifiers and
   referenced client key sets in the domain and storage boundaries.

## Decision

**Asterius chooses option 2.** v1 does not publish or resolve Entity
Statements, construct or validate Trust Chains, apply Federation metadata
policy, administer Trust Anchors, or advertise automatic or explicit
Federation registration.

The client identifier remains an opaque, unbounded domain string backed by a
database `text` column. Code must not narrow every `ClientId` to the locally
minted `c.` shape: that shape identifies what current registration paths
create, not every identifier the model may eventually hold. The client key
model continues to support an HTTPS `jwks_uri`; it must not be redesigned as
inline-JWKS-only.

These are compatibility invariants, not dormant protocol behavior. A future
Federation implementation still needs an explicit design for Entity Identifier
validation and aliasing, Federation Entity signing keys (which are distinct
from entity-type keys), Trust Chain caching and expiry, metadata policy,
registration renewal, outbound-fetch security and tenant-scoped trust anchors.

## Consequences

**Easier.** A future automatic-registration path can use an HTTPS Entity
Identifier as a `ClientId`, and resolved RP/client metadata can retain keys by
reference, without changing the client table's identifier or key-source shape.

**Harder.** Current callers cannot infer from the type that a `ClientId` was
locally minted. Code that needs that fact must obtain it from the registration
flow or validate the prefix explicitly. Referenced key sets retain the outbound
fetch, cache and SSRF obligations recorded by ADR-0006.

**No v1 surface.** No Federation well-known endpoint, metadata flag, trust
anchor configuration or registration mode is added. Documentation and tests
must not claim OpenID Federation conformance until a later decision owns those
behaviors and their conformance coverage.

## Spec clauses

| Clause | What it requires | How this decision satisfies it |
|---|---|---|
| OpenID Federation 1.0 section 1.2, Entity Identifier | Entity Identifiers defined by the specification are globally unique HTTPS URLs with a host and no query or fragment | The client model can retain the complete URL as an opaque identifier; validation is deliberately deferred to a future Federation boundary |
| OpenID Federation 1.0 section 5.2.1 | Entity-type key material may be obtained through HTTPS `jwks_uri` or `signed_jwks_uri`, or carried as `jwks`; Federation Entity signing keys are a distinct Entity Statement claim | The existing referenced client-key variant remains representable without conflating it with future Federation Entity signing keys |
| OpenID Federation 1.0 section 9 | Entity Configurations are obtained at a well-known path derived from the HTTPS Entity Identifier | The identifier is not normalized into a locally minted shape; v1 intentionally does not perform the fetch |
| OpenID Federation 1.0 section 12.1 | Automatic registration uses the RP Entity Identifier as its Client ID and resolves its Entity Configuration and Trust Chain | The data model can hold that identifier, but v1 neither resolves nor accepts automatic registrations |

Every clause listed here was checked against the published Final text on
2026-09-19. Final status was checked against the OpenID Foundation's
[1.0 approval announcement](https://openid.net/openid-federation-1-0-final-specification-approved/)
and [1.1 approval announcement](https://openid.net/openid-federation-1-1-final-specifications-approved/)
on the same date.
