---
layout: bead.njk
permalink: "beads/ast-2vk-8.html"
id: "ast-2vk.8"
title: "Self-registration (`prompt=create`) & account self-service pages"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

SSR registration with email verification (single-use ≥128-bit token, 15 min), then passkey enrolment. Account pages: passkeys (add/rename/remove), password (set/change), sessions (list/revoke), grants (list/revoke → E07_06).

Spec: OpenID Connect Prompt Create 1.0 §3 (`prompt=create`), §4 (`prompt_values_supported`); OIDC Core §5.1 (email_verified semantics).

Depends on: E06_03, E06_05

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
