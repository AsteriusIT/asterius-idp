---
layout: bead.njk
permalink: "beads/ast-2vk-9.html"
id: "ast-2vk.9"
title: "Login abuse protection (rate limits, generic errors, no enumeration)"
status: "Open"
type: "Task"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Sliding-window limits per IP, per account and per tenant for login, passkey challenges, password reset, registration and email verification; generic error messages; audit of failures.

Spec: NIST SP 800-63B §5.2.2 (rate limiting online guessing); OWASP ASVS V2.2; RFC 6749 §10.x (brute force on codes/tokens — informational).

Depends on: E06_04, E06_05

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
