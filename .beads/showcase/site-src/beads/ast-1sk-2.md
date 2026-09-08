---
layout: bead.njk
permalink: "beads/ast-1sk-2.html"
id: "ast-1sk.2"
title: "Token revocation endpoint (RFC 7009) with grant-aware semantics"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Revoke a refresh token (and, by tenant policy, all access tokens of its grant) or a single access token (jti denylist until exp). The grant itself stays intact unless policy says otherwise (allows re-connect without consent).

Spec: RFC 7009 §2.1 (POST `token`, `token_type_hint`; client authentication; the AS MUST NOT return an error if the token is invalid), §2.2 (200 on success; 'the client MUST NOT be able to revoke a token issued to another client' → treat as invalid), §2.2.1 (`unsupported_token_type`); RFC 6749 §10.4; Grant Management ID1 §6.5 Note (token revocation need not revoke the underlying grant).

Depends on: E08_05, E03_02

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
