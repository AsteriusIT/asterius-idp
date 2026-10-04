# SPIRE JWT-SVID subject exchange

- **Status:** Approved by the user on 2026-10-04; implementation and delivery tracked separately
- **Date:** 2026-10-03
- **Bead:** ast-dd1y.2.5
- **Refines:** [external workload trust](external-workload-trust.md)
- **Deciders:** Human approval not yet recorded for this SPIFFE extension

## Decision prepared for review

Select a bounded **SPIRE-issued JWT-SVID subject** profile on the existing
RFC 8693 exchange endpoint. Keep independently registered confidential-client
authentication with existing `private_key_jwt` or explicitly configured RFC 8705
mTLS. Output remains DPoP constrained. A JWT-SVID is a bearer workload assertion;
it neither authenticates an OAuth client nor enrolls the caller's ephemeral key.
No X.509-SVID client authentication or trusted broker is introduced in this mode.

This selects a SPIRE integration profile, not support for every standards-valid
JWT-SVID. The SPIFFE standard does not require `iss` or `iat`; the inspected
SPIRE credential builder emits `iat` and supports a configured `jwt_issuer`.
Require operators to set that issuer explicitly to an exact HTTPS identifier
and configure JWT-SVID TTL at most 300 seconds. Reject missing or altered issuer,
missing/untyped `iat`, expiry, issuance age over 300 seconds, future issuance over
30 seconds and `exp-iat > 300s`. This makes freshness enforceable from signed
claims rather than assuming the Workload API just returned a recently minted
credential. SPIRE installations without those claims/configuration fail closed.

## Current code boundaries and implementation contract

`ExternalWorkloads` selects existing enabled tenant trusts using a bounded
unverified issuer hint, then verifies signatures and exact claims. The selected
trust must additionally bind one explicit trust domain and exact SPIFFE ID. Its
issuer identifier does not supply a JWKS endpoint or establish domain authority.
No token-provided `iss`, `sub`, URL, certificate or bundle is enrollment evidence.

The current `Provider` enum supports Kubernetes/GitHub only. Generic
`Parsed::parse` restricts JOSE `typ` to `JWT` and string claims to 1024 bytes;
`KeySet::parse` expects OAuth `use=sig`. These are not generic JWT-SVID or SPIFFE
bundle readers. ast-dd1y.2.6 must add an explicit SPIFFE parser/validated bundle
adapter, rather than passing a SPIFFE document through the browser verifier or
silently accepting it as a Kubernetes/GitHub credential. No runtime is enabled
by this decision-only commit.

The SPIFFE profile accepts only `alg`, `kid` and optional `typ` headers; absent
`typ`, `JWT` and `JOSE` are supported. Require nonempty bounded `kid` even though
the JWT-SVID standard permits omission. The first implementation allowlist is
the explicit configured subset of ES256, PS256 and RS256; reject HMAC, `none`,
EdDSA and all other algorithms in this profile. Reuse the existing public-key
signature primitives without widening FAPI authentication or output signing.
No certificate-thumbprint header, embedded key, critical extension or key URL
is accepted here. Duplicate JSON, invalid encoding and unknown headers fail.

Keep compact JWT <= 8192 bytes, decoded claims <= 4096 bytes and nesting <= 8. Support
SPIFFE IDs up to 2048 ASCII bytes with trust-domain length <= 255 bytes; other claim
strings remain bounded at 1024 bytes. Parse and validate the SPIFFE URI grammar
before any selection hint is used, without URL-normalization aliases. Pin the
complete canonical identity and compare the path byte-for-byte. No prefix/path
wildcards, query, fragment, userinfo, port, percent encoding, empty/relative path
segments or trailing slash. Domain and scheme are represented in their required
lowercase canonical form. A path resembling Kubernetes namespace/ServiceAccount
names supplies no extra authorization: it is an opaque operator-owned SPIFFE ID.

Each tenant trust maps its domain+ID to one stable `workload:` principal, an
explicit confidential-client allowlist and exact scopes/resources/actions.
Neither an ID rename nor a trust-domain collision inherits another mapping.
Require the single audience `urn:asterius:workload:<tenant>:<trust-id>`, separate
from the requested resource. Additional audiences fail. Local-issuer JWTs stay
on their current verifier; unrecognized/ambiguous SPIFFE mappings fail closed.

## Trusted bundles and rotation

The initial adapter accepts **operator-installed public SPIFFE bundles** bound
to one explicit tenant trust/domain tuple. Export them from the independently
authenticated SPIRE control plane; do not infer authenticity from a matching
domain name. The same bundle keys cannot authorize other domains just because
their names look related. Automatic federation enrollment, recursive bundle
chaining and token-directed retrieval are outside the first implementation.

Validate a bounded 64 KiB bundle with at most 16 total key entries. Keep only keys
with `use=jwt-svid`; unknown SVID uses cannot authorize JWTs. Validate required
`kid`, allowed algorithm/key type, RSA 2048–8192 bits, public-only material and
duplicate IDs. An empty bundle or zero usable JWT keys means effective trust
revocation, not an error that restores the previous usable snapshot. SPIFFE
`spiffe_sequence`, when present, is a nonnegative 64-bit integer and must strictly
increase when a previously recorded sequence changes; reject rollback and
same-sequence changed key material. Once a sequence is recorded, subsequent
updates cannot omit it to bypass ordering. Without an initial sequence, no
upstream ordering guarantee is claimed; durable trust revision still serializes
operator writes. Administrative reads return public key
fingerprints/domain/version, not raw SVIDs or private credentials.

The crypto adapter may project previously validated JWT-SVID keys into its
internal verification representation. Such projection must never treat a raw
OAuth `use=sig` entry as SPIFFE authority or add X.509 trust anchors. `kid` lookup
remains bounded to the selected domain's current bundle.

Bundle installation/removal, disabled state and policy edits advance the existing
durable trust revision and append actor/tenant/domain/trust metadata audit. Mint
locks and rechecks that authoritative revision/enabled state before consuming
the assertion and writing the child grant. Rotation installs old+new public JWT
authorities during intentional overlap, verifies new SVID issuance, then removes
the retired authority. The next serialized mint cannot use a removed key.
No stale-key grace is added. An explicit empty/removed bundle stops issuance.

This first mode deliberately makes the operator responsible for bundle delivery.
If a SPIRE key is removed but the operator does not update Asterius, delivery lag
has no automatic bound: the old installed authority remains trusted until update
or disable. Do not claim 60-second remote-key revocation for static bundles. A
future authenticated local Workload API watcher or pinned federation endpoint
requires a separate implementation and lifecycle policy; this decision chooses
neither an unimplemented stream nor an SSRF exception for private SPIRE endpoints.

## Replay, output and revocation bounds

Reuse durable SHA-256 assertion consumption keyed by tenant/trust until expiry,
atomically with grant, source provenance and success audit. No optional upstream
`jti` or process-local cache substitutes for this mark. Output carries the mapped
workload `sub`, visible independently authenticated client `act`, grant ID and
DPoP confirmation; no actor token, impersonation, refresh or ID token. Scope,
resource and registered RFC 9396 action ceilings use the existing workload
intersection. Success provenance/audit identifies provider `spiffe`, source
domain, exact SPIFFE ID, trust revision and child grant without logging the JWT.

Child expiry is at most `min(now+300s, SVID.exp, tenant/client/resource ceiling)`.
Since the accepted SVID lifetime itself is <= 300 seconds, removing a SPIRE workload
registration cannot revoke a previously issued SVID immediately, but neither the
assertion nor its child remains authoritative past that SVID's original expiry,
with only the approved 30-second future clock error. The bound is 300 seconds from
issuance, not an extra 300 seconds added after SVID expiry. A compromised signing
authority is a separate threat: it can mint until installed trust is removed or
disabled, subject to the explicit delivery-lag limitation above. Online API grant
revocation can shorten child authority; offline JWT verifiers cannot promise it.

SPIRE's Workload API authenticates local workloads according to its own agent
attestation/registration policy. It does not authenticate an Asterius OAuth
client. Clients must request the exact exchange audience, reload newly issued
SVIDs, and request a new assertion after consumption or a failed post-commit
signature. Older SPIRE versions may return identical JWTs for immediate requests
within one clock second; the client must detect repeats and request again with
bounded pacing, without disabling server replay protection.

## Alternatives and X.509 boundary

| Mode | Decision and rationale |
| --- | --- |
| SPIRE JWT-SVID subject + independent client | Selected: bounded assertion adapter and existing exchange/grant policy; client provisioning remains explicit |
| X.509-SVID-backed broker | Deferred: broker attestation, delegated proof/key possession, its independent OAuth credential and lifecycle introduce a new trust boundary |
| Explicit X.509-SVID OAuth mTLS mapping | Deferred: requires domain-specific bundle/chain and leaf-SVID validation, exact registered URI SAN, proof of possession and per-client lifecycle |

`ClientAuthenticator::check_certificate` currently verifies configured tenant PKI
roots plus registered RFC 8705 subject, or exact registered leaf certificates for
self-signed authentication. A valid SPIFFE certificate is not automatically a
registered OAuth client certificate. The domain authority, exact SPIFFE URI SAN,
SVID leaf constraints, certificate path/time and TLS possession must all be
enforced before any explicitly registered mTLS mapping could authenticate a
client. Accepting every certificate chaining to an added SPIRE CA would let that
CA mint unregistered OAuth clients and collapse tenant/domain isolation.

## Required interoperability evidence and review

Before ast-dd1y.2.6 closes, a disposable pinned SPIRE server/agent must attest a
controlled workload, issue a native JWT-SVID with the configured issuer/TTL,
export its real domain bundle, and exchange it through Asterius with independent
client auth and DPoP into a permitted API. Exercise wrong domain, ID, issuer,
audience, expiry, stale issuance, unregistered client, replay, scope/action/resource
widening, empty bundle/disable, same-domain key rotation and retired-key refusal.
Include duplicate/unknown-use/sequence rollback bundle tests and bounded parser
fuzzing. Record actual SPIRE version, its claim shape and the tested offline
freshness/delivery limits; a synthetic JWS alone is not SPIRE interoperability.

The implementing agent opened primary sources on 2026-10-03 and prepared this
concrete contract. Human review must explicitly approve the SPIFFE/SPIRE-specific
parser, issuer/iat/TTL subset, bundle-use/domain/sequence semantics, independent
bootstrap and static delivery/offline revocation bounds. The earlier external
workload ADR did not approve this new SPIFFE provider. ast-dd1y.2.5 stays open and
ast-dd1y.2.6 remains blocked until that review is recorded. No reviewer or approval
is fabricated by this document.

## Primary sources

- [SPIFFE ID standard](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md): namespace syntax, limits and identity/trust-domain separation.
- [JWT-SVID standard](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md): constrained JOSE headers, audience/expiry, bearer risk and JWT-specific key use.
- [Trust domain and bundle standard](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md): explicit domain/bundle binding, key uses, empty revocation and sequence semantics.
- [Workload API standard](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md): local workload identity acquisition, delivery and update lifecycle.
- [SPIRE credential builder](https://github.com/spiffe/spire/blob/main/pkg/server/credtemplate/builder.go): actual `iat`, optional configured `JWTIssuer`, TTL and optional `jti` behavior; implementation fact, not a SPIFFE normative requirement.
- [SPIRE JWT signer](https://github.com/spiffe/spire/blob/main/pkg/server/ca/ca.go): actual key ID/type/signature issuance boundary.
- [RFC 8705 §§2–3](https://www.rfc-editor.org/info/rfc8705/): registered client-certificate authentication and token binding as separate decisions.

## Human review approval — 2026-10-04

The user explicitly stated: "I have reviewed and approve all five contracts."
Approval covers this prepared contract, including its documented compatibility,
trust and freshness limits, at SHA-256 `8da739717636174c74ed9d9d38fc442422df7143a9637c96fdacbb6acfd1e700`.
Implementation, runtime evidence and delivery retain their separate verification
requirements. This record does not claim CI or deployment completion.
