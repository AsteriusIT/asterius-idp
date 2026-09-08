---
layout: bead.njk
permalink: "beads/ast-o0t-3.html"
id: "ast-o0t.3"
title: "Capability registry → metadata (single source of truth, route/metadata parity test)"
status: "Closed"
type: "Task"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "2h ago"
---

`Capabilities` (E01_02 flags + tenant settings + alg allow-list) is the only input to metadata generation and to router construction, so an endpoint cannot be advertised without existing or exist without being advertised.

Spec: OIDC Discovery §3; RFC 8414 §2 (metadata MUST reflect actual behaviour).

Depends on: E01_02

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
