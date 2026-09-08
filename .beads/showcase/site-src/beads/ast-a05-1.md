---
layout: bead.njk
permalink: "beads/ast-a05-1.html"
id: "ast-a05.1"
title: "Token endpoint framework & client-authentication dispatch"
status: "Open"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

One handler that authenticates the client (E03_02/E03_03), validates the DPoP proof when present (E08_06), parses `grant_type` and dispatches to grant handlers enabled by feature flags and the client's `grant_types`.

Spec: RFC 6749 §3.2 (token endpoint: POST, TLS, client auth), §3.2.1, §4.1.3, §5.1 (success: `Cache-Control: no-store`, `Pragma: no-cache`), §5.2 (errors invalid_request, invalid_client (401 + WWW-Authenticate when header auth attempted), invalid_grant, unauthorized_client, unsupported_grant_type, invalid_scope); OIDC Core §3.1.3 (token endpoint), §3.1.3.4 (token error response); RFC 6750 §3.

Depends on: E03_02, E01_04

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
