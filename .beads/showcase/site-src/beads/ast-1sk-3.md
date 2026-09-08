---
layout: bead.njk
permalink: "beads/ast-1sk-3.html"
id: "ast-1sk.3"
title: "UserInfo endpoint (DPoP-bound access tokens, JSON or signed JWT)"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

The IdP's own resource server; reuses the RS verification helper (E08_03).

Spec: OIDC Core §5.3.1 (GET/POST with access token; `openid` scope), §5.3.2 (response: `sub` REQUIRED and MUST match; JSON `application/json` or signed/encrypted JWT `application/jwt` per `userinfo_signed_response_alg`, with `iss`/`aud` in JWT form), §5.3.3 (errors per RFC 6750: `invalid_token` 401, `insufficient_scope` 403), §5.3.4, §5.4 (scope → claims), §5.5 (claims parameter), §5.2 (language tags); RFC 6750 §3 (`WWW-Authenticate: Bearer` … error attributes); RFC 9449 §7.1 (`Authorization: DPoP` + proof with `ath`), §7.2 (RS nonce optional); FAPI 2.0 SP §5.3.4 (RS: accept tokens in header only; never in query; verify validity, revocation, sender-constraint).

Depends on: E08_03, E08_06, E09_04

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
