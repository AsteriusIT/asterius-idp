---
layout: bead.njk
permalink: "beads/ast-2vk-2.html"
id: "ast-2vk.2"
title: "Server-side session management (`sid`, lifetimes, participating clients)"
status: "Open"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Sessions in PostgreSQL keyed by an opaque id (≥128 bits, hashed at rest) carried by `__Host-asterius_session`. Tracks user, auth_time, acr/amr, idle/absolute expiry, participating clients (for back-channel logout) and device summary.

Spec: OIDC Core §3.1.2.3; OpenID Connect Back-Channel Logout §2.1 (`backchannel_logout_session_supported`), §2.4 (`sid` claim in ID Token and Logout Token — section numbers as in the Final spec); OWASP ASVS V3 (session lifetime, rotation).

Depends on: E01_03, E06_01

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
