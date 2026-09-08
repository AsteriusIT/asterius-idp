---
layout: bead.njk
permalink: "beads/ast-f7m-3.html"
id: "ast-f7m.3"
title: "Console scaffold (React + TypeScript + Vite) served by the binary under strict CSP"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Vite build embedded in the binary (`include_dir`/rust-embed) under `/admin/`, hashed immutable assets, index rendered server-side to inject the CSP nonce; no inline scripts/styles; no external fonts/CDNs; role-aware navigation; Playwright e2e smoke.

Spec: CSP Level 3 (`strict-dynamic`, nonces/hashes); FAPI 2.0 SP §5.2.3.

Depends on: E14_01, E14_02, E15_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
