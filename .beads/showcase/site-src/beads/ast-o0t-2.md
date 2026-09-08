---
layout: bead.njk
permalink: "beads/ast-o0t-2.html"
id: "ast-o0t.2"
title: "OAuth 2.0 Authorization Server Metadata (`/.well-known/oauth-authorization-server`)"
status: "Closed"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "1h ago"
---

Same document as E04_01, served at the RFC 8414 location (path-inserted form) so MCP clients' first probe succeeds.

Spec: RFC 8414 §2 (metadata), §3.1 (well-known path insertion between host and path), §3.2 (response), §3.3 (validation: issuer identical), §5 (compatibility with OIDC Discovery).

Depends on: E04_01

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
