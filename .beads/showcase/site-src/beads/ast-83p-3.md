---
layout: bead.njk
permalink: "beads/ast-83p-3.html"
id: "ast-83p.3"
title: "PostgreSQL schema baseline & sqlx migrations"
status: "Closed"
type: "Task"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "5h ago"
---

Initial migration set: tenants, clients, client_keys, users, credentials, sessions, auth_requests (PAR + interaction state), authorization_codes, grants, refresh_tokens, access_token_jti (denylist), signing_keys, audit_events, outbox, rate_limits. Every tenant-scoped table carries `tenant_id` and composite indexes. Opaque credentials (codes, refresh tokens, registration tokens, device codes, auth_req_id) are stored as SHA-256 digests only.

Spec: FAPI 2.0 SP §5.4.1 item 4 (≥128-bit credentials, stored hashed); RFC 6749 §10.3 (access/refresh tokens and codes must be kept confidential in storage).

Depends on: E01_01

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
