---
layout: bead.njk
permalink: "beads/ast-gxh-9.html"
id: "ast-gxh.9"
title: "Signed request objects (JAR) inside PAR [optional]"
status: "Open"
type: "Feature"
priority: "Low"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Optional non-repudiation hook (prerequisite for FAPI 2.0 Message Signing later — Implementer's Draft, tracked in E17). Off by default.

Spec: RFC 9126 §3 (`request` parameter in PAR; `request_uri` by reference MUST NOT be used in PAR); RFC 9101 §4 (request object claims; `typ` oauth-authz-req+jwt), §6.1 (all parameters in the JWT; parameters outside are ignored except client auth), §6.3 (validation); OIDC Core §6.1 (`request` parameter), §6.3 (validation: iss=client_id, aud=issuer).

Depends on: E05_01, E02_04

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
