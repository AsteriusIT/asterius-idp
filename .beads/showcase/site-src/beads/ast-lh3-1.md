---
layout: bead.njk
permalink: "beads/ast-lh3-1.html"
id: "ast-lh3.1"
title: "Agent client profile & policy (owner, key, allowed grants/audiences/RAR types, delegation limits)"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

`client_kind = agent` with owner (user or org), mandatory `private_key_jwt` + `jwks`, allowed grant types ⊆ {client_credentials, token-exchange, device_code, ciba}, allowed audiences and scopes, allowed RAR types, `max_delegation_depth`, token TTL caps, and human-approval requirements per scope/RAR type. A DCR policy preset (E03_06) creates agents with these constraints.

Spec: RFC 7591 §2 (client metadata + extension fields); FAPI 2.0 SP §6.6 (client impersonating resource owner: client_id must not look like a subject identifier); RFC 8693 §5 (security considerations for delegation).

Depends on: E03_01, E03_06

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
