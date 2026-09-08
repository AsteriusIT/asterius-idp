---
layout: bead.njk
permalink: "beads/ast-gxh-7.html"
id: "ast-gxh.7"
title: "Resource indicators (`resource`, RFC 8707) driving `aud`"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Registered resource servers per tenant (identifier URI, allowed scopes, default token lifetime). `resource` values must be registered; otherwise `invalid_target`. Access tokens are always audience-bound: if a client sends no `resource`, its registered default audiences apply, and a client with none cannot get an access token.

Spec: RFC 8707 §2 (absolute URI, no fragment, SHOULD be most specific; multiple allowed), §2.1 (authorization request), §2.2 (token request; MUST be a subset of the authorized set; `invalid_target` error), §3 (security: audience restriction); RFC 9068 §3 (`aud` from resource); MCP Authorization 2025-11-25 'Resource Parameter Implementation' (clients MUST send `resource` in both requests; canonical MCP server URI).

Depends on: E05_01

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
