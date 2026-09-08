---
layout: bead.njk
permalink: "beads/ast-o4u-2.html"
id: "ast-o4u.2"
title: "Back-Channel Logout (Logout Token `logout+jwt`, delivery via outbox)"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

On session termination, for each participating client with `backchannel_logout_uri`, enqueue a Logout Token signed with the client's ID-token alg and POST it with retries.

Spec: OpenID Connect Back-Channel Logout 1.0 incorporating errata set 1 (Final, 2023-12) §2.1 (OP metadata `backchannel_logout_supported`, `backchannel_logout_session_supported`), §2.2 (client metadata `backchannel_logout_uri`, `backchannel_logout_session_required`), §2.3 (remembering logged-in RPs), §2.4 (Logout Token: `iss`, `sub` and/or `sid`, `aud`, `iat`, `exp`, `jti`, `events` = {"http://schemas.openid.net/event/backchannel-logout": {}}; `typ` `logout+jwt`; MUST NOT contain `nonce`), §2.5 (request: POST `logout_token` form param; retransmit only on potentially recoverable errors, with delay), §2.6 (RP validation steps 1–11 — drive tests), §2.7 (RP actions), §2.8 (response: 200/204 success, 400 on invalid token), §4.1 (cross-JWT confusion → explicit typ).

Depends on: E06_02, E02_01, E12_09

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
