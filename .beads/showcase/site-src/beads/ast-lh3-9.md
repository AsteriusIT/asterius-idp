---
layout: bead.njk
permalink: "beads/ast-lh3-9.html"
id: "ast-lh3.9"
title: "Per-agent audit trail & query API (delegation chains end-to-end)"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Extend E01_11 events with `agent_id`, `agent_owner`, `act_chain`, `grant_id`, `authorization_details` summary, `resource`, `approval_id` (CIBA/device). Query API with filters and NDJSON export; console explorer (E14_08).

Spec: RFC 8693 §4.1 (act chain semantics); FAPI 2.0 SP §6.7 item 4 (credential linking); product requirement.

Depends on: E01_11, E11_02

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
