---
layout: bead.njk
permalink: "beads/ast-f7m-6.html"
id: "ast-f7m.6"
title: "Console: users, credentials, sessions & grants"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

User search/create/disable, claims editing with verification flags, credential management (remove passkey, force password reset), session list with revoke (triggers E10_03), grants list with revoke (E07_05 semantics).

Spec: OIDC Core §5.1 (claims editing); Back-Channel Logout §2.5; CAEP 1.0 §3.1.

Depends on: E14_03, E10_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
