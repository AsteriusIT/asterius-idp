---
layout: bead.njk
permalink: "beads/ast-uwv-4.html"
id: "ast-uwv.4"
title: "Grant Management authorization-request parameters (`grant_id`, `grant_management_action`) [flag: grant_management]"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Parameters accepted in PAR and CIBA requests; semantics applied at consent/grant persistence time.

Spec: Grant Management for OAuth 2.0 ID1 (2023-07-10, draft-03) §5.1 (confidential clients only), §5.2 (`grant_id`; `grant_management_action` = create | merge | replace; merge/replace 'shall invalidate existing refresh tokens'), §5.3 (no change to authorization response), §5.4 (errors: `invalid_grant_id`; `invalid_request` when grant_id with create, action missing with grant_id, unsupported action, or action required but absent), §7.1 (`grant_management_action_required`). Status: Implementer's Draft — isolated behind a flag and a thin port so spec churn is cheap.

Depends on: E07_02, E05_01

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
