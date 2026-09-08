---
layout: bead.njk
permalink: "beads/ast-m9c-4.html"
id: "ast-m9c.4"
title: "Dynamic Client Registration endpoint (POST /register)"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Tenant-scoped registration endpoint. Default: bearer initial access token required (issued by admin API with a policy and quota); tenant may enable open registration only together with a DCR policy (E03_06).

Spec: RFC 7591 §3.1 (request), §3.2.1 (201 response: client_id, client_id_issued_at, echoed metadata), §3.2.2 (errors invalid_redirect_uri, invalid_client_metadata, invalid_software_statement, unapproved_software_statement); OIDC Registration §3.1–3.3 (registration_access_token, registration_client_uri, client_secret_expires_at=0 semantics); RFC 7591 §5 (security: initial access token, rate limiting).

Depends on: E03_01, E03_07

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
