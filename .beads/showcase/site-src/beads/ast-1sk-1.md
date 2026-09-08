---
layout: bead.njk
permalink: "beads/ast-1sk-1.html"
id: "ast-1sk.1"
title: "Token introspection endpoint (RFC 7662) for registered resource servers"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Callers authenticate with private_key_jwt/mTLS and must be registered as a resource server (or the client that owns the token). JWT access tokens are verified locally and checked against the jti denylist and grant status.

Spec: RFC 7662 §2.1 (POST `token`, `token_type_hint`; caller MUST be authorized), §2.2 (response: `active` REQUIRED; scope, client_id, username, token_type, exp, iat, nbf, sub, aud, iss, jti), §2.3 (errors; unauthorized → 401), §4 (security: only authorized protected resources; token scanning), §2.2 note (`active:false` for any token the caller may not learn about); RFC 9449 §6.2 (`cnf` in introspection); RFC 8693 §4 (act/scope/client_id in introspection).

Depends on: E08_03, E03_02

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
