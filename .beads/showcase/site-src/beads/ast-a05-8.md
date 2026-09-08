---
layout: bead.njk
permalink: "beads/ast-a05-8.html"
id: "ast-a05.8"
title: "client_credentials grant (service & agent tokens, sender-constrained, audience-bound)"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Used by resource servers, admin automation, SSF receivers, AuthZEN PEPs and AI agents acting on their own behalf.

Spec: RFC 6749 §4.4 (client credentials grant; §4.4.3 refresh token SHOULD NOT be included); RFC 8707 §2.2; RFC 9449 §5; FAPI 2.0 SP §5.3.2.1 items 4, 14; RFC 9068 §2.2 (`sub` = client_id for client-only tokens).

Depends on: E08_01, E08_06, E05_07

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
