---
layout: bead.njk
permalink: "beads/ast-uwv-1.html"
id: "ast-uwv.1"
title: "Consent screen (client identity, scopes, claims, RAR, resources; no JS)"
status: "Open"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

SSR consent page listing client name/URI (text only; logo only if uploaded to the IdP), scopes with tenant descriptions, requested claims, RAR items rendered by type template, target resources, offline access, and Approve/Deny. Deny is a first-class outcome.

Spec: OIDC Core §3.1.2.4 (obtain end-user consent/authorization); FAPI 2.0 SP §5.3.2.2 item 13 (provide all information for an informed decision: client identity and scope), §7 (privacy: client misidentification, insufficient understanding, inadequate choice); RFC 9396 §2 (render authorization details).

Depends on: E06_01, E06_02

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
