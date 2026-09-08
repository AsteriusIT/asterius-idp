---
layout: bead.njk
permalink: "beads/ast-gxh-6.html"
id: "ast-gxh.6"
title: "Rich Authorization Requests (`authorization_details`, RFC 9396)"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Per-tenant registry of RAR types with JSON Schema and consent template; parsing with depth/size limits; client allow-list; persisted on the grant; propagated to access tokens, introspection and the Grant Management resource.

Spec: RFC 9396 §2 (JSON array of objects; `type` REQUIRED), §2.1 (authorization details types), §2.2 (common fields locations, actions, datatypes, identifier, privileges), §3 (authorization request), §6 (token response MAY include enriched `authorization_details`), §7 (token error `invalid_authorization_details` — section number from memory, verify), §8.1 (`authorization_details` claim in JWT access tokens), §9.1 (`authorization_details_types_supported`), §9.2 (client `authorization_details_types`). FAPI 2.0 SP §5.3.2.2 Note 5 (RAR recommended when scope is not expressive enough).

Depends on: E05_01, E07_02

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
