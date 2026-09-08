---
layout: bead.njk
permalink: "beads/ast-83p-9.html"
id: "ast-83p.9"
title: "Threat model & ADR log baseline (FAPI 2.0 Attacker Model mapping)"
status: "Closed"
type: "Task"
priority: "Critical"
assignee: "Quentin RODIC"
origin: "agent"
updated: "5h ago"
---

`docs/threat-model.md` listing each attacker capability, the security goal it threatens (authorization, session integrity, token confidentiality) and the control + bead that mitigates it. `docs/adr/` with template and ADR-0001 modular monolith, ADR-0002 FAPI 2.0 as the only mode, ADR-0003 signing algorithm set (see E01_12).

Spec: FAPI 2.0 Attacker Model §3–§4 (attackers A1–A5: web attacker, network attacker, read/inject authorization request/response, read/inject token request/response); FAPI 2.0 SP §6 (security considerations).

Depends on: E01_01

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
