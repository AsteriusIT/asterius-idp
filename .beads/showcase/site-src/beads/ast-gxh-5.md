---
layout: bead.njk
permalink: "beads/ast-gxh-5.html"
id: "ast-gxh.5"
title: "response_mode=form_post (server-rendered auto-submit, works without JavaScript)"
status: "Open"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Template renders a hidden form with `code`, `state`, `iss`; a nonce-CSP script auto-submits; `<noscript>` shows a Continue button. Only `query` and `form_post` are accepted for `response_type=code`.

Spec: OAuth 2.0 Form Post Response Mode §2 (HTML form POST to redirect_uri with `application/x-www-form-urlencoded` body containing all response parameters; MUST NOT be cached); OAuth 2.0 Multiple Response Type Encoding Practices §2.1 (`response_mode`); FAPI 2.0 SP §5.2.3 (browser endpoints).

Depends on: E05_04, E15_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
