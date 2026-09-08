---
layout: bead.njk
permalink: "beads/ast-f7m-8.html"
id: "ast-f7m.8"
title: "Console: SSF streams, delivery status & audit/agent-trail explorer"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Stream list with status/reason, queue depth, dead letters (retry/drop), trigger verification; audit explorer with filters and delegation-chain visualisation; export.

Spec: SSF 1.0 §8 (stream state); E11_09 query API.

Depends on: E14_03, E12_03, E11_09

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
