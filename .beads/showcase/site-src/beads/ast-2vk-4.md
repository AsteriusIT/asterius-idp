---
layout: bead.njk
permalink: "beads/ast-2vk-4.html"
id: "ast-2vk.4"
title: "Passkey authentication (discoverable credentials, conditional UI as enhancement)"
status: "Open"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Username-less flow first (discoverable credential), username-first fallback. Conditional UI (autofill) is progressive enhancement only.

Spec: WebAuthn L3 §7.2 (verifying an authentication assertion: challenge, origin, rpIdHash, UP/UV flags, sign count); RFC 8176 (`amr` values: `hwk`, `swk`, `user`, `pin`); OIDC Core §2 (acr, amr, auth_time).

Depends on: E06_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
