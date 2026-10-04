# Managed device posture uses an authenticated relay and enrolled TLS credentials

- **Status:** Approved by the user on 2026-10-04; implementation and delivery tracked separately
- **Date:** 2026-10-03
- **Bead:** ast-dd1y.4.4
- **Refines:** [Trusted conditional access](trusted-conditional-access-context.md)

## Context

Asterius already resolves client certificates from an authenticated TLS peer or
an explicitly trusted terminating proxy in `crates/server/src/mtls.rs`. It
performs bounded certificate parsing and tenant-specific chain/client-usage
validation. A header from another peer is not a certificate proof. Existing
OAuth client authentication remains a separate consumer of this machinery.

Posture is another authority: possession of a certificate proves possession of
its key, while a management source must vouch for enrollment and current state.
Neither a browser's operating-system string nor a passkey alone establishes
management status. A synchronized passkey cannot identify one physical device.

## Chosen first profile

Use **managed-device-relay/v1**, an operator-managed enrollment/posture relay,
and **enrolled PKI TLS client credentials** for device proof. The relay is the
single bounded initial source profile. It translates an authoritative management
feed into explicit Asterius enrollment and posture updates; a vendor adapter is
not implicitly trusted or claimed interoperable by this decision.

A tenant administrator registers the exact relay client and enables the source.
Device enforcement is disabled until the operator configures the dedicated
device anchors and trusted ingress and the tenant explicitly enables this profile.
The relay is a confidential, client-credentials-only client, authenticated by
the existing `private_key_jwt` or OAuth mTLS path. Its administrative access
token is sender constrained and carries a dedicated device-source scope.
Ingress additionally matches the authenticated client to the registered source
in the routed tenant. An ordinary browser session, user-delegated token,
workload assertion, public client or unrelated scoped automation token cannot
publish posture. A DPoP proof alone is not source authentication.

Device credentials chain to a **separate, tenant-specific device CA anchor
set**, mounted by the operator. Do not silently reuse the public web roots,
OAuth client CA set or another tenant's anchors. The initial supported ingress
is `behind_proxy`: the configured trusted proxy verifies TLS key possession,
removes any caller-provided certificate header, and forwards the actual leaf
certificate over its protected connection to Asterius. The dedicated adapter
rechecks the device anchor chain, client-auth usage, validity and exact enrolled
leaf SHA-256 fingerprint. Self-signed device certificates are excluded.
Direct TLS ingress can be added only with equivalent verified peer evidence.

The relay or its PKI provisions the private device key/certificate through its
existing management channel. Asterius never creates, returns or stores that
private key. No new device JWT, browser-supplied JWK or custom signature dialect
is introduced. This credential does not register or authenticate an OAuth
client, issue tokens, raise authentication assurance or authorize a user.

## Enrollment and binding

An enrollment binds `(tenant, source, source_generation, device_uuid,
user_uuid, leaf_fingerprint, allowed_client_ids)`. The user and each client must
exist in that tenant. Asterius generates the opaque device UUID; vendor serials,
MAC addresses and guessed browser identifiers are not identity keys.

Enrollment is an explicit privileged source operation, separately audited from
posture ingestion. It asserts the source's approved user/device association;
the user's ordinary authentication must independently establish the same local
user at the access boundary. An incoming posture observation cannot enroll,
change the user, change the certificate or widen the application allow-list.
Certificate renewal requires explicit enrollment-generation replacement and
invalidates proofs bound to the previous fingerprint. A name reused by the
management system inherits no authority.

At authorization, the adapter binds verified device evidence to the exact
tenant/user/client and server-owned interaction. Issuance can use only this
interaction's verified observation, capped at 300 seconds, and must re-read
current source/enrollment/posture state. It cannot borrow another session's
device or the strongest unrelated grant. A required device fact on refresh,
exchange or a PDP request requires matching verified evidence for that boundary;
when an RP cannot supply it, the fact is absent and the request is denied.
Return to interactive authorization instead of treating the previous login's
IP, certificate header or token claim as a new proof.

## Minimal posture and freshness

Posture has only closed, typed attributes: `managed`, `compliant`,
`disk_encrypted` and `risk` (`low`, `medium`, `high`, `unknown`). Absent values
remain unknown. An authenticated update names an existing enrollment generation,
strictly increasing nonnegative sequence, `observed_at` and `expires_at`.
Limit each update to 8 KiB and 32 observations; reject duplicates and unknown
fields. No free-form inventory, executable policy, URLs or remote fetches.

Accept timestamps only within the server-checked 300-second age bound and
five-second forward clock tolerance. Effective expiry is the earliest of the
source expiry, observation plus 300 seconds, certificate expiry and the
transaction's device-proof expiry. A duplicate/lower sequence or wrong generation
is refused atomically. Source key rotation uses normal client authentication
key management; source-generation changes invalidate earlier enrollment proofs.

Read current enrollment/source state at every enforcement boundary, without a
positive authorization cache. A removed device, disabled source, invalid
certificate, stale observation, source outage or store timeout cannot satisfy a
required fact. A relay outage becomes stale within at most 300 seconds. Apply
the mandatory required-facts guard before `not`/`any` and deny-overrides-permit
from the conditional-access contract. No fallback to self-reported values.

## Removal, revocation and privacy

Source administrators can disable a source; a user can remove only their own
enrollment; tenant administrators can revoke tenant-owned enrollments. Deletion
of the underlying user/client removes the corresponding binding. Removal and
disable are audited and immediately prevent new protected decisions. Their
effects do not revoke already-issued offline JWTs before expiry; do not present
this profile as resource-server continuous enforcement.

Posture ingress only updates active enrollments and cannot recreate removed
ones. Retain a minimal removed-generation tombstone for 30 days for operator
diagnosis, then erase it; an absent enrollment still denies and an explicit new
enrollment gets a new server UUID. Keep only the latest posture for active
enrollments. Erase posture values on removal; retain no location, serial, raw
certificate, hardware inventory, private key or browser fingerprint in the
device tables. The audit trail records source/enrollment IDs, revisions and
outcome categories under existing tenant audit authorization and retention.

## Assurance limits and alternatives

The source, device CA and TLS-terminating proxy are explicit trust roots. A
compromised source can assert false posture; a compromised trusted proxy can
assert another enrolled credential. A copied software private key can satisfy
the same credential binding. **This profile proves an approved management
credential and authenticated source state, not hardware attestation or that the
same physical machine performed every request.** Operators requiring hardware
provenance need a separately reviewed attestation profile.

Unsigned browser headers/self-reported compliance were rejected because they
provide no source authority. WebCrypto keys would require a new enrollment/proof
protocol and do not by themselves establish management or hardware provenance.
Passkey-only binding was rejected because account authentication and a managed
device are distinct facts. A direct vendor-specific connector remains possible
after its exact credential lifecycle, user binding and interoperability are
tested; no generic vendor support is claimed here.

## Delivery evidence required by ast-dd1y.4.5

The runtime must prove correct and wrong tenant/user/client/certificate cases,
untrusted proxy spoof refusal, expired certificates, stale/replayed observations,
source/device removal, concurrent update/removal and missing-fact negation refusal.
Add a controlled relay plus real TLS/proxy fixture; do not infer key possession
from merely parsing certificate DER. Publish scope/schema/retention, fuzz the
bounded ingress parser and expose unavailable-state explanations. Human review
of the relevant normative trust text is required before protocol/crypto delivery;
this architecture record itself enables no runtime profile.

## Normative basis

- [RFC 8705 §§2.1, 3, 6.5, 7.4](https://datatracker.ietf.org/doc/html/rfc8705):
  PKI validation, key possession, certificate binding and trusted TLS termination.
  The new device association is an application trust rule, not a claim that
  RFC 8705 defines managed-device enrollment.
- [RFC 9449 §§4.3, 7, 8, 11.11](https://www.rfc-editor.org/rfc/rfc9449.html):
  existing relay token/proof validation; proof of possession is independent of
  client authentication.
- [WebAuthn Level 3 §6.1.3](https://www.w3.org/TR/webauthn-3/#sctn-credential-backup):
  credentials can be backed up; a passkey is not a physical-device identifier.
- [Web Cryptography API §6](https://www.w3.org/TR/2017/REC-WebCryptoAPI-20170126/#security-considerations):
  API key handling alone does not establish a management trust root.

Sources checked on 2026-10-03. Algorithm and FAPI/OIDC profile boundaries remain
the existing repository decisions; this does not admit public OAuth clients or
external certificate identities as OAuth client registrations.

## Protected-hop candidate clarification (pending human review)

Source inspection shows the existing `behind_proxy` listener is plain HTTP.
A trusted CIDR and a public leaf forwarded in a header do not establish the
protected-hop key-possession boundary above. The candidate therefore requires
mandatory proxy client TLS authentication on the edge-to-Asterius hop, against
a separately configured bounded proxy CA bundle, plus an exact operator pin of
the proxy client leaf SHA256 digest. No configuration boolean or caller-supplied
field may create the private authenticated-hop context. Ordinary HTTP never
supplies managed-device facts. The selected device adapter remains behind the
edge for issuer and forwarding semantics; the protected backend listener uses
existing rustls/aws-lc TLS1.2/1.3 suites, with mandatory client authentication.
The edge must validate the backend server chain/name, verify the device client
TLS handshake, strip incoming device fields and forward the actual device leaf.

The current private trust revision combines the dedicated tenant device CA,
proxy CA and sorted proxy pins. Each original interaction proof expires no later
than either the device or proxy leaf expiry, in addition to the existing300s
bound. Root/pin changes invalidate older proof generations. This does not assert
physical hardware attestation and does not alter OAuth client authentication.
The exact transport refinement must be included in human review before delivery;
source implementation and isolated validation do not constitute that review.

[CertificateVerify in RFC8446 §4.4.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.3)
provides TLS private-key possession rather than merely parsing a public leaf.
[ClientAuth usage in RFC5280 §4.2.1.12](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.12)
keeps the dedicated device/proxy certificate purpose explicit. Neither RFC
specifies this repository's enrollment or management protocol.

### Proposed final authority and legacy derivation compatibility

The isolated ast-dd1y.9 candidate replaces modification timestamps with a
private grant authority UUID. The baseline database changes `updated_at` on
ordinary claim, and transaction timestamps can repeat across real permission
amendments; neither is a valid authority revision. Migration0171 preserves the
UUID across claim/expiry bookkeeping and an exact attested stable-public-session
lookup rotation, and changes it when durable permissions, authentication,
principal, actor or parent authority changes. The generation and each child's
immutable captured parent generation remain private database/issuance context.
They are never supplied by a workload token, browser header or public JWT claim.

Final signing checks the exact current claimed lineage under canonical tenant,
client, user and root-to-leaf locks. Every child edge must retain the generation
observed before derivation. Loading an existing child cannot replace its receipt
with the current parent generation. Existing derived grants without historical
receipts fail closed for new issuance and require reauthorization; standalone
legacy grants acquire their own generation during migration. Already-issued
stateless credentials keep their existing expiry and resource-server revocation
contract. This does not claim retrospective offline JWT invalidation.

This compatibility tradeoff is part of the proposed runtime refinements for
human review before delivery. Candidate schema/compiled CI regressions/controlled
runtime evidence must be reviewed separately; source preparation is not an
approval or proof that the final 116-migration binary has passed runtime checks.

## Human review approval — 2026-10-04

The user explicitly stated: "I have reviewed and approve all five contracts."
Approval covers this prepared contract, including its documented compatibility,
trust and freshness limits, at SHA-256 `99f90f64696f75de98ba92a29fd82db11a5f9f2b1144fd983de7cfcd51c2d01c`.
Implementation, runtime evidence and delivery retain their separate verification
requirements. This record does not claim CI or deployment completion.
