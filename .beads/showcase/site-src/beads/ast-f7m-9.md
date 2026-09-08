---
layout: bead.njk
permalink: "beads/ast-f7m-9.html"
id: "ast-f7m.9"
title: "Console: AuthZEN policy editor with test bench"
status: "Open"
type: "Feature"
priority: "Low"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Edit tenant rules (E13_04) with schema validation and a 'try a request' panel that calls the evaluation endpoint.

Spec: Authorization API 1.0 §6 (evaluation request shape for the test bench).

Depends on: E14_03, E13_04

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
