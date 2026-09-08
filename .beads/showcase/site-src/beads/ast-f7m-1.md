---
layout: bead.njk
permalink: "beads/ast-f7m-1.html"
id: "ast-f7m.1"
title: "Admin API foundation (`/admin/api/v1`): auth modes, RBAC, audit, OpenAPI"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Two auth modes: (1) console — same-origin IdP session cookie + CSRF header + admin role; (2) automation — DPoP-bound access token with `admin.*` scopes from an admin client. RBAC roles: tenant-admin, security-auditor (read-only), user-support (users/sessions only). Every mutation audited with actor.

Spec: RFC 6749 §4.4 (client_credentials for automation); RFC 9449 §7 (DPoP at the API); OWASP ASVS V4 (access control), V13 (API).

Depends on: E06_02, E08_08, E01_11

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
