---
layout: bead.njk
permalink: "beads/ast-a05-6.html"
id: "ast-a05.6"
title: "DPoP (RFC 9449): proof validation, jkt binding, nonce, `dpop_jkt` in PAR, metadata"
status: "Open"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Proof validation middleware for token, PAR (dpop_jkt correlation), UserInfo, introspection (optional), grant-management, SSF-management and AuthZEN endpoints. Replay store in PostgreSQL keyed by (tenant, jkt, jti) with TTL = iat window.

Spec: RFC 9449 §4.1 (`DPoP` header), §4.2 (proof JWT: typ dpop+jwt, alg asymmetric ≠ none, jwk public key; claims jti, htm, htu, iat, nonce, ath), §4.3 (checking: exactly one header; parse; typ; alg; signature with jwk; jti replay; htm/htu match; iat window; nonce), §5 (token request: `token_type: DPoP`; error `invalid_dpop_proof`), §6.1 (`cnf.jkt` = JWK thumbprint RFC 7638), §8 (AS-provided nonce: `use_dpop_nonce` 400 + `DPoP-Nonce` header), §10.1 (`dpop_jkt` authorization request parameter), §10.2 (in PAR), §11 (`dpop_signing_alg_values_supported`), §12 (`dpop_bound_access_tokens`), §13 (security: htu normalisation, replay); FAPI 2.0 SP §5.3.2.1 items 4–5 (sender-constrained via DPoP), 10 (nonce MAY), 12 (must support code binding to DPoP key), 13 (skew).

Depends on: E02_04, E08_01, E02_06

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
