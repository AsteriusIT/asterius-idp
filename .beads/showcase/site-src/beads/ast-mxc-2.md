---
layout: bead.njk
permalink: "beads/ast-mxc-2.html"
id: "ast-mxc.2"
title: "JWKS endpoint (`jwks_uri`)"
status: "Closed"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "1h ago"
---

`GET /t/{tenant}/jwks` returning public members of active + retiring signing keys, with `kid`, `kty`, `crv`/`alg`, `use: sig`. Cache headers tuned to rotation cadence.

Spec: OIDC Discovery §3 (`jwks_uri`: keys used to sign ID Tokens; `use` parameter); OIDC Core §10.1.1 (key rotation via JWKS); FAPI 2.0 SP §5.4.2 (serve only over TLS; should not use `x5u`/`jku`; should not serve multiple keys with the same `kid`).

Depends on: E02_01, E02_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
