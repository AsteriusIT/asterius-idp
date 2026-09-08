---
layout: bead.njk
permalink: "beads/ast-2vk-1.html"
id: "ast-2vk.1"
title: "Interaction engine & SSR page framework (CSRF, CSP nonce, no-JS)"
status: "Open"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

An `Interaction` (id ≥128 bits, bound to the PAR request and to a `__Host-asterius_ix` cookie) drives a state machine login → step-up → consent → response. askama templates with autoescape; per-response CSP nonce; synchroniser CSRF token per form; every page usable without JavaScript.

Spec: OIDC Core §3.1.2.3 (authorization server authenticates end-user; MUST NOT interact if prompt=none), §3.1.2.4; FAPI 2.0 SP §5.2.3 (browser endpoints), §6.5 (browser-swapping: keep authorization response confidential); RFC 9700 §4 (clickjacking and open-redirector countermeasures — exact section number from memory, verify).

Depends on: E01_04, E01_10, E15_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
