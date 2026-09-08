---
layout: bead.njk
permalink: "beads/ast-gxh-2.html"
id: "ast-gxh.2"
title: "Authorization endpoint: PAR-only request handling & interaction hand-off"
status: "Open"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

`GET|POST /t/{tenant}/authorize?client_id&request_uri` loads the pushed request, re-checks binding, creates an interaction (E06_01) and redirects (303) to the login/consent pages. Pure-OAuth requests (no `openid` scope) are allowed and yield no ID token.

Spec: OIDC Core §3.1.2.1 (authentication request parameters; GET or POST; scope openid), §3.1.2.2 (request validation: 'MUST validate all OAuth 2.0 parameters'; 'MUST verify that a scope parameter is present and contains the openid scope value' for OIDC; ignore unrecognised parameters), §3.1.2.6 (error response); RFC 6749 §4.1.1, §4.1.2.1 (if redirect URI/client_id invalid: 'MUST NOT automatically redirect'); RFC 9126 §4 (client_id + request_uri at authorization endpoint); FAPI 2.0 SP §5.3.2.2 item 1 (`response_type` = `code`), item 3 (reject non-PAR), item 14 (nonce up to 64 chars).

Depends on: E05_01, E06_01

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
