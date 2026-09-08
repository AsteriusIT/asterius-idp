---
layout: bead.njk
permalink: "beads/ast-2vk-10.html"
id: "ast-2vk.10"
title: "Account recovery (email reset token, passkey re-enrolment)"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Email-based recovery producing a single-use ≥128-bit token (15 min, hashed at rest); on use, forces new credential set-up and invalidates other sessions; emits CAEP `credential-change`.

Spec: NIST SP 800-63B §6.1.2.3 (recovery); OWASP Forgot Password Cheat Sheet.

Depends on: E06_06

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
