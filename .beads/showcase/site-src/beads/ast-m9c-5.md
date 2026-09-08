---
layout: bead.njk
permalink: "beads/ast-m9c-5.html"
id: "ast-m9c.5"
title: "Client configuration endpoint (GET/PUT/DELETE registration_client_uri)"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Bearer `registration_access_token` protected management of one client. PUT validates the full document with E03_01; DELETE cascades to grants/tokens/streams.

Spec: RFC 7592 §2.1 (read; unknown client/invalid token → 401 and token SHOULD be revoked), §2.2 (update: full replacement, client_id immutable), §2.3 (delete → 204), §3 (responses); OIDC Registration §4.1 (endpoint URL), §4.2–4.3 (read request/response), §4.4 (error: 401 invalid/unknown, 403 no permission, MUST NOT return 404).

Depends on: E03_04

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
