---
layout: bead.njk
permalink: "beads/ast-mxc-4.html"
id: "ast-mxc.4"
title: "JWT verification service (typ, crit, skew window, duplicate-kid selection)"
status: "Closed"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "3h ago"
---

One verifier used for client assertions, DPoP proofs, request objects, id_token_hint, CIBA signed requests, logout tokens received in tests. Callers pass an expected `typ`, allowed algs, expected `iss`/`aud`, and a key resolver.

Spec: RFC 8725 §3.1–3.3 (alg verification, key/alg binding), §3.5 (crit), §3.8–3.9 (validate all claims, use UTC), §3.11 (explicit typ); FAPI 2.0 SP §5.3.2.1 item 13 ('shall accept JWTs with an iat or nbf timestamp between 0 and 10 seconds in the future but shall reject JWTs with an iat or nbf timestamp greater than 60 seconds in the future'); §5.4.3 (duplicate kid selection algorithm).

Depends on: E02_01

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
