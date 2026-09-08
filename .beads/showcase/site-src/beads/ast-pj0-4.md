---
layout: bead.njk
permalink: "beads/ast-pj0-4.html"
id: "ast-pj0.4"
title: "PolicyEngine port + built-in declarative engine over IdP data"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

`PolicyEngine::evaluate(tenant, Subject, Action, Resource, Context) -> Decision`. Built-in engine: tenant rules as data (JSON/YAML, schema-validated) over attributes the IdP owns — user attributes/groups/roles, client/agent profile, active grants (scopes, RAR, resources), session acr — plus PEP-supplied properties. Deterministic, total, explainable.

Spec: Authorization API 1.0 §5 (information model), §5.5.1 (decision context: reasons, obligations, step-up hints e.g. `acr_values`); NIST SP 800-162 (ABAC — informational).

Depends on: E06_06, E07_02, E13_05

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
