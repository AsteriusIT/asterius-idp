---
layout: bead.njk
permalink: "beads/ast-lh3-10.html"
id: "ast-lh3.10"
title: "Pre-issuance policy port (AuthZEN-backed decisions before minting agent tokens)"
status: "Open"
type: "Feature"
priority: "Low"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

`IssuancePolicy` port consulted for agent clients: subject = agent (+ owner), action = `obtain_token`/`exchange_token`, resource = {audience, scope, authorization_details}, context = {grant, chain depth}. Default adapter = internal PDP (E13); decisions cached briefly; deny → `access_denied` with audit.

Spec: Authorization API 1.0 §6 (evaluation request shape); RFC 6749 §5.2 (`access_denied`, `invalid_scope`).

Depends on: E13_01, E11_01

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
