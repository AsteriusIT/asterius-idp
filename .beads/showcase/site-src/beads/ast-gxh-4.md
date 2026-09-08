---
layout: bead.njk
permalink: "beads/ast-gxh-4.html"
id: "ast-gxh.4"
title: "Authorization response: code issuance (≤60 s, single-use, replay revocation) with `iss`"
status: "Open"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

After consent, mint an authorization code bound to client_id, redirect_uri, scope, nonce, PKCE challenge, `dpop_jkt`, resources, authorization_details, session id, auth_time, acr; persist hash; redirect via query or form_post.

Spec: OIDC Core §3.1.2.5 (successful authentication response: code, state), §3.1.2.6 (error response); RFC 6749 §4.1.2 (code lifetime SHOULD be short, MUST NOT be used more than once; on reuse 'SHOULD revoke all tokens previously issued based on that authorization code'), §4.1.2.1; RFC 9207 §2 (`iss` parameter MUST be included in successful and error responses when supported); FAPI 2.0 SP §5.3.2.2 item 7 (`iss` per RFC 9207), item 9 (reject previously used code), items 10–11 (no 307; 303), Note 1.

Depends on: E05_02, E06_02, E07_01

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
