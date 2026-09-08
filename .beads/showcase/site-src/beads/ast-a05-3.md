---
layout: bead.njk
permalink: "beads/ast-a05-3.html"
id: "ast-a05.3"
title: "JWT access token profile (RFC 9068, `at+jwt`, always audience- and sender-bound)"
status: "Open"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Signed (EdDSA default) self-contained access tokens; opaque reference tokens are out of scope (KISS). Lifetime default 300 s, tenant/resource cap 900 s.

Spec: RFC 9068 §2.1 (header `typ: at+jwt`), §2.2 (claims iss, exp, aud, sub, client_id, iat, jti REQUIRED), §2.2.1 (auth_time, acr, amr), §2.2.3 (scope, groups/roles/entitlements), §4 (validation rules for RS — informs tests), §5 (security: aud restriction, no sensitive data); RFC 9449 §6.1 (`cnf.jkt`); RFC 8705 §3 (`cnf.x5t#S256`); RFC 8693 §4.1 (`act`); RFC 9396 §8.1 (`authorization_details`); FAPI 2.0 SP §5.3.2.1 item 4 (only sender-constrained access tokens), item 14 (least privilege), §6.1 (short-lived access tokens), §5.4.1.

Depends on: E02_01, E07_02

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
