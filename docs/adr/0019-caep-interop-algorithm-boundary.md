# ADR-0019: Keep CAEP Draft 01 outside the supported SSF receiver profile

- **Status:** Accepted
- **Date:** 2026-09-26
- **Bead:** ast-s36.26.4.8
- **Deciders:** Asterius implementation team

## Context

[CAEP Interoperability Profile 1.0 draft 01, §2.6](https://openid.github.io/sharedsignals/openid-caep-interoperability-profile-1_0.html)
requires every event to use RS256 with an RSA key of at least 2048 bits. Its
§2.4.4 also requires a receiver to assume that all subjects are included in a
stream without Add Subject calls. [ADR-0003](0003-signing-algorithm-set.md)
deliberately excludes RS256 from issuance and verification. The
[FAPI 2.0 Security Profile §5.4.1](https://openid.net/specs/fapi-security-profile-2_0-final.html)
limits JWT creation and processing to PS256, ES256, or EdDSA. The receiver
currently accepts EdDSA and ES256 from explicitly trusted peers, and its
receiver-managed stream setup does not assume implicit inclusion of all subjects.

The CAEP Interoperability Profile is a working draft. Calling this receiver
conformant to that draft would be false even if its stream management were
otherwise complete. Enabling RS256 in the shared JOSE verifier would also
change the algorithm boundary for unrelated FAPI-facing JWTs.

## Decision

Retain ADR-0003's closed signing and verification algorithm set. The product
targets SSF 1.0 Final receiver operations with configured peers and the CAEP
event types it actually handles. It does **not** claim CAEP Interoperability
Profile draft 01 conformance or advertise that draft as a supported profile.
RS256 SETs remain rejected. The transmitter continues issuing only algorithms
permitted by ADR-0003; the receiver accepts only its explicitly implemented
subset from pinned peer keys. Stream subject enrollment remains explicit and
fail closed until a coherent policy is implemented.

This decision can be revisited if the interoperability draft changes its
algorithm requirement or if the product explicitly chooses an isolated
receiver-only RS256 verifier. That change requires a new ADR, a separate
algorithm allow-list and key-use boundary, strict RSA key-size enforcement,
and FAPI impact analysis before implementation. It must never be added through
the generic JWT verifier or silently enabled for all peers.

## Consequences

SSF Final integration with configured EdDSA or ES256 peers can proceed on its
own merits. CAEP Draft 01 interoperability and certification remain unsupported;
documentation and metadata must say so. The original decision required stream
verification, deletion, credential lifecycle and independent evidence before a
narrower SSF interoperability claim. The dated implementation update below
records those gates without changing the algorithm decision.

Rejected alternative: enabling RS256 generally for draft compatibility. That
would contradict ADR-0003 and the FAPI 2.0 Security Profile algorithm set.


## Implementation update, 8 October 2026

The supported receiver policy retains EdDSA/ES256 and the operator-managed bearer
boundary. ALL subjects are permitted only with explicit tenant opt-in and explicit
local mappings; NONE peers still require external enrollment. Correlated signed
verification, authenticated multi-stream readback and exact remote deletion are
implemented. Operator credentials are read afresh per operation, must be rotated
before expiry and are not automatically acquired or refreshed.

[Independent SSFgo evidence](../integrations/evidence/ssfgo-asterius-lifecycle-2026-10-08.json)
records guarded ES256 poll setup and verification, actual mapped seeded-session
revocation, lost-ACK redelivery with one inbox row, bearer refusal/recovery,
untrusted issuer refusal and unaffected delivery on a second stream after deletion.
The peer advertises polling only and push is refused accordingly. This supports a
bounded SSF1 Final integration claim; it does not certify CAEP Draft01 or establish
native push interoperability. The September decision and its RS256 refusal stand.

A second owned native SSFgo transmitter subsequently advertised RFC8935 push
and delivered its own ES256 event using its native worker/default guarded
HTTPS client. The real receiver revoked the mapped session with exactly one
inbox row; owned stream and fixture identities were removed. Sanitized evidence
is [`ssfgo-native-push-2026-10-08.json`](../integrations/evidence/ssfgo-native-push-2026-10-08.json).
This resolves the separate native push evidence gap for the chosen SSF1 Final
profile without changing the RS256 or Draft01 boundary.
