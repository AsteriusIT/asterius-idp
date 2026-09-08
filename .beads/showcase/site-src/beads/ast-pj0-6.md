---
layout: bead.njk
permalink: "beads/ast-pj0-6.html"
id: "ast-pj0.6"
title: "Search APIs (subject/resource/action) with pagination [optional]"
status: "Open"
type: "Feature"
priority: "Low"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Only for the built-in engine (finite entity sets: users, grants, resources).

Spec: Authorization API 1.0 §8 (search: omit the id of the entity being searched; results SHOULD evaluate to permit), §8.2 (pagination: `page.token`/`limit`; response `page.next_token` REQUIRED when paginated, empty string at end; identical parameters between pages), §8.3 (response: `results` REQUIRED, `page`, `context`), §8.4–8.6 (subject/resource/action search requests; default paths /access/v1/search/{subject,resource,action}).

Depends on: E13_04

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
