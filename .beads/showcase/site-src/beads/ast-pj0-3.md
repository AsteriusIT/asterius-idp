---
layout: bead.njk
permalink: "beads/ast-pj0-3.html"
id: "ast-pj0.3"
title: "PDP metadata (`/.well-known/authzen-configuration`)"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Per-tenant PDP identifier = tenant issuer + `/authzen` (or the issuer itself — decide in implementation, keep identical in `aud`).

Spec: Authorization API 1.0 §9.1.1 (endpoint parameters: policy_decision_point REQUIRED (https, no query/fragment), access_evaluation_endpoint REQUIRED, access_evaluations_endpoint, search_* OPTIONAL), §9.1.2 (`capabilities` URNs), §9.1.3 (`signed_metadata` OPTIONAL), §9.2 (well-known URI inserted between host and path; multi-tenant example), §9.2.2 (200, application/json; omit empty parameters; ignore unknown), §9.2.3 (validation: policy_decision_point identical to the identifier used).

Depends on: E13_01, E04_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
