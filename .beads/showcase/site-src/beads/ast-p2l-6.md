---
layout: bead.njk
permalink: "beads/ast-p2l-6.html"
id: "ast-p2l.6"
title: "Threat model completion & external security review readiness"
status: "Open"
type: "Task"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Complete `docs/threat-model.md` with agent-specific threats: prompt-injected agent requesting broader scope, delegation-chain abuse, replay of agent DPoP proofs, approval fatigue in CIBA/device flows, MCP confused deputy. Each threat links to controls and beads. Add SECURITY.md and a coordinated-disclosure policy.

Spec: FAPI 2.0 Attacker Model (A1–A5); FAPI 2.0 SP §6 (DPoP proof replay, stolen token injection/'Cuckoo's token', authorization request leak → CSRF, browser swapping, client impersonating resource owner, key compromise); MCP Authorization security considerations (confused deputy, token passthrough, localhost redirect risks).

Depends on: E01_09, E11_02, E11_06, E12_08

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
