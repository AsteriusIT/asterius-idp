# Post-v1 enterprise identity roadmap

**Planning snapshot:** 2026-09-19
**Owner:** product
**Tracking bead:** `ast-s36.12`

This is a release-planning aid, not an implementation commitment. None of the
capabilities below is part of v1, and none may be advertised in discovery,
configuration, documentation or readiness output until a product decision
opens a dedicated implementation bead and its security boundary is designed.

## Current order

| Order | Candidate | Current decision | Re-opening trigger |
|---|---|---|---|
| 1 | SCIM 2.0 provisioning | First candidate after v1 | A customer-backed provisioning use case and an explicit decision on inbound service-provider scope, tenant isolation and lifecycle ownership |
| 2 | TOTP | Compatibility/recovery candidate only | A documented population that cannot use WebAuthn, plus recovery and downgrade policies that preserve phishing-resistant authentication where it is required |
| 3 | SAML 2.0 | Nice-to-have, out of scope | A product decision backed by named SAML service-provider integrations and ownership of XML signature, metadata and federation operations |
| 4 | LDAP | Out of scope | A product decision backed by a deployment model that cannot use SCIM, OIDC or an external directory bridge |

The order is deliberately not a promise. Release planning must reconsider the
evidence and record a dated outcome below; lack of new evidence leaves all four
items deferred.

## Compatibility boundaries

### SCIM 2.0

The likely first slice is an **inbound SCIM service provider** for tenant-scoped
`User` and `Group` resources. RFC 7643 defines the JSON resource/schema model,
and RFC 7644 defines the HTTP create, query, replace, patch and delete
operations. RFC 9865 adds optional cursor pagination, while RFC 9967 defines a
SCIM profile for Security Event Tokens. Those updates belong in any future
design review; they do not create v1 endpoints today.

Before implementation, decide at least:

- whether SCIM or an administrator is authoritative for activation, deletion,
  group membership and locally edited attributes;
- stable mapping of tenant, SCIM `id`, client-controlled `externalId`, user and
  group identifiers, including uniqueness and rename behavior;
- authentication and least-privilege authorization for provisioning clients;
- PATCH/filter behavior, bulk limits, pagination, idempotency and concurrency;
- audit events, privacy-safe logs and transactional propagation of lifecycle
  changes to sessions, grants and the existing outbox.

SCIM must enter through application/domain commands rather than writing the
PostgreSQL schema directly. Its wire schema is an interoperability boundary,
not a replacement for Asterius's user and claims model.

### TOTP

RFC 6238 defines a time-based one-time-password algorithm, not the surrounding
enrolment, recovery, throttling or factor policy. A future TOTP feature must
therefore first decide secret generation and encrypted storage, QR/bootstrap
delivery, accepted clock skew, replay prevention, recovery codes, rate limits,
factor reset and audit behavior.

TOTP is a phishable shared-secret factor. It must not silently replace the
user-verified WebAuthn requirement for deployment administrators or weaken any
policy that explicitly requires phishing-resistant authentication. Whether it
is an additional factor, a recovery mechanism or a legacy primary factor is a
product decision, not something inferred from RFC 6238.

### SAML 2.0

SAML is a separate XML protocol family with assertions, bindings, profiles,
metadata, trust and key rollover. Reusing OIDC claim names does not remove the
need for strict XML signature validation, destination/audience checks, replay
protection, metadata lifecycle and an explicit IdP/SP role decision. No SAML
assertion or metadata surface is added to v1, and the OIDC token-exchange code
continues to reject SAML token types.

### LDAP

LDAP is a directory access protocol suite, not a provisioning synonym. A future
decision must say whether Asterius is an LDAP client, exposes an LDAP server, or
relies on a separately operated bridge. It must also own schema mapping,
connection security, bind policy, paging, referrals, synchronization and the
source-of-truth conflict model. Until then, LDAP does not shape the domain or
storage schema.

## Release-planning review

At each release-planning review, update this section and the bead notes with:

1. the review date and product owner;
2. customer evidence and the concrete interoperability role requested;
3. relevant standards changes;
4. the decision: remain deferred, commission a design, or open implementation;
5. any changed order or prerequisite.

| Review date | Outcome |
|---|---|
| 2026-09-19 | SCIM remains the first post-v1 candidate. TOTP remains a constrained compatibility/recovery candidate. SAML and LDAP remain closed unless a product decision re-opens them. No v1 implementation or advertised capability was added. |

## Specification baseline

- RFC 7643, *SCIM: Core Schema*, and RFC 7644, *SCIM: Protocol* (both updated
  by later SCIM RFCs)
- RFC 9865, *Cursor-Based Pagination of SCIM Resources*
- RFC 9967, *SCIM Profile for Security Event Tokens*
- RFC 6238, *TOTP: Time-Based One-Time Password Algorithm*
- OASIS SAML V2.0 specification set and approved errata 05
- RFC 4510 and the LDAP technical specification it identifies
