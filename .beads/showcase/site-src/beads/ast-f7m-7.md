---
layout: bead.njk
permalink: "beads/ast-f7m-7.html"
id: "ast-f7m.7"
title: "Console: signing keys (list, rotate, retire, JWKS preview)"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Key inventory per purpose/alg with states; rotate now; set rotation schedule; JWKS preview; never shows private material.

Spec: OIDC Core §10.1.1; FAPI 2.0 SP §6.7.

Depends on: E14_03, E02_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
