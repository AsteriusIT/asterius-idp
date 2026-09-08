---
layout: bead.njk
permalink: "beads/ast-o4u-1.html"
id: "ast-o4u.1"
title: "RP-Initiated Logout (`end_session_endpoint`)"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

GET/POST endpoint; terminates the OP session, triggers back-channel logout (E10_02) for participating clients, then redirects or shows a logged-out page.

Spec: OpenID Connect RP-Initiated Logout 1.0 (Final, 2022-09) §2 (parameters id_token_hint, logout_hint, client_id, post_logout_redirect_uri, ui_locales, state; OP asks the End-User whether to log out when the request cannot be verified), §2.1 (`end_session_endpoint` metadata), §3 (redirection: 'MUST NOT perform post-logout redirection' without id_token_hint unless other means confirm legitimacy, and only when `post_logout_redirect_uri` exactly matches a registered value; redirection happens after RPs are notified), §3.1 (client metadata `post_logout_redirect_uris`), §4 (validation and error handling: id_token_hint signature/iss/aud; expired ID Tokens accepted as hints).

Depends on: E06_02, E08_04

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
