---
layout: bead.njk
permalink: "beads/ast-lh3-8.html"
id: "ast-lh3.8"
title: "MCP authorization compatibility profile (confidential MCP clients & MCP resource servers)"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Make a FAPI-compliant Asterius tenant usable by MCP clients that are confidential (DCR with `jwks` → private_key_jwt, PAR, PKCE S256, DPoP) and document the resource-server side.

Spec: MCP Authorization (2025-11-25): AS MUST provide RFC 8414 or OIDC Discovery (clients try path-inserted RFC 8414, path-inserted OIDC, path-appended OIDC); OIDC discovery MUST include `code_challenge_methods_supported`; AS MUST validate exact redirect URIs; clients MUST send `resource` (RFC 8707) in authorization and token requests; AS SHOULD issue short-lived ATs; MCP servers MUST implement RFC 9728 with `authorization_servers` and validate `aud`; DCR MAY; CIMD SHOULD (IETF draft → track per E03_08).

Depends on: E04_01, E04_02, E05_07, E03_04, E03_08

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
