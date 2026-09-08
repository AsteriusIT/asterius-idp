---
layout: bead.njk
permalink: "beads/ast-a05-5.html"
id: "ast-a05.5"
title: "Refresh tokens: opaque, grant-bound, no rotation (FAPI 2.0), revocable"
status: "Open"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Opaque ≥256-bit refresh tokens stored as SHA-256 digests with grant, client, scopes, absolute and idle expiry. No rotation by default; a time-boxed rotation mode exists only for migrations (FAPI Note 1) and offers the old token for retry within a grace window.

Spec: RFC 6749 §1.5, §6 (refresh request: grant_type=refresh_token, refresh_token, scope ⊆ original), §10.4; OIDC Core §12.1–12.3 (refresh: ID Token MAY be returned; `sub` MUST match; new nonce not required); FAPI 2.0 SP §5.3.2.1 item 9 ('shall not use refresh token rotation except in extraordinary circumstances'), Note 1, §6.1 (long-lived grants → short ATs + RTs); RFC 9449 §5 (refresh tokens for public clients bound to DPoP key; confidential clients: new AT bound to the proof key presented); RFC 9700 §4.14 (refresh token protection: sender-constrained or rotation — we use client authentication + optional key binding).

Depends on: E08_02, E07_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
