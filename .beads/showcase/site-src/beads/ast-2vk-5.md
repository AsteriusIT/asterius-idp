---
layout: bead.njk
permalink: "beads/ast-2vk-5.html"
id: "ast-2vk.5"
title: "Password authentication with Argon2id (secondary credential)"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Passwords are a secondary factor/legacy path; passkeys remain primary in UX. Argon2id with configurable parameters (floor enforced), transparent rehash, timing-equalised failure path, per-account/IP throttling.

Spec: RFC 9106 (Argon2id parameters); OWASP Password Storage Cheat Sheet (Argon2id m=19 MiB, t=2, p=1 minimum); NIST SP 800-63B §5.1.1 (min 8 chars, allow ≥64, no composition rules, breach list check, Unicode NFKC).

Depends on: E06_02, E06_06

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
