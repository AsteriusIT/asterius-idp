---
layout: bead.njk
permalink: "beads/ast-pj0-2.html"
id: "ast-pj0.2"
title: "Access Evaluations (boxcar) endpoint with `evaluations_semantic` options"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Same engine, N decisions per request with short-circuit semantics.

Spec: Authorization API 1.0 §7.1 (`evaluations` array; top-level subject/action/resource/context as defaults; each item overrides; required entities must come from item or default), §7.1.1 (default values), §7.1.2.1 (`options.evaluations_semantic`: execute_all (default) | deny_on_first_deny | permit_on_first_permit), §7.2 (response `evaluations` array in request order; per-item errors as decision:false with context.error), §10.1 (default path /access/v1/evaluations).

Depends on: E13_01

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
