---
layout: bead.njk
permalink: "beads/ast-uwv-6.html"
id: "ast-uwv.6"
title: "User-facing grants dashboard (list & revoke standing consents)"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Account page listing active grants per client/agent with scopes, RAR summaries, resources, last use, delegation chains issued from the grant; one-click revoke with the same semantics as E07_05.

Spec: Grant Management ID1 §3 (dashboards use case); OIDC Core §3.1.2.4; FAPI 2.0 SP §7 (privacy).

Depends on: E07_02, E06_08

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
