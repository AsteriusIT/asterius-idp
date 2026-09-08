---
layout: bead.njk
permalink: "beads/ast-p2l-8.html"
id: "ast-p2l.8"
title: "Performance baseline & DB index review"
status: "Open"
type: "Task"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Load scripts (k6/oha) for token endpoint (private_key_jwt + DPoP), PAR+authorize+token flow, introspection, SSF delivery; EXPLAIN review of hot queries; connection-pool sizing guidance.

Spec: FAPI 2.0 SP §6.1 (short access tokens increase AS load — size lifetimes with data).

Depends on: E08_02, E12_06

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
