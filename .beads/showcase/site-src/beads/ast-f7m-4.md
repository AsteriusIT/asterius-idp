---
layout: bead.njk
permalink: "beads/ast-f7m-4.html"
id: "ast-f7m.4"
title: "Console: tenant settings (feature flags, lifetimes, session & ACR policy, rate limits, theming)"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Forms for issuer info (read-only), feature flags, token/code/session lifetimes (with FAPI caps enforced server-side), ACR policy editor, rate limits, theming tokens (E15_01) with live preview.

Spec: OIDC Discovery §3 (settings that surface in metadata); product config model (E01_02).

Depends on: E14_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
