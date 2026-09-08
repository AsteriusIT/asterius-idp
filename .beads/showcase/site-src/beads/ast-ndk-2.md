---
layout: bead.njk
permalink: "beads/ast-ndk-2.html"
id: "ast-ndk.2"
title: "Constrained template set (login, register, consent, error, device, approvals, logout, account, reset)"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

askama compile-time templates with a shared layout; tenant customization limited to tokens (E15_01) and message bundles (E15_05). Snapshot-tested.

Spec: OIDC Core §3.1.2.3–3.1.2.4; RFC 8628 §3.3; CIBA §8; product rule (templates fixed, tenants change tokens and strings only); WCAG 2.2 AA.

Depends on: E06_01

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
