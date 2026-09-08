---
layout: bead.njk
permalink: "beads/ast-f7m-5.html"
id: "ast-f7m.5"
title: "Console: clients, agents & DCR policy"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Client list/search, create/edit with the same validator as DCR (E03_01), JWKS upload / jwks_uri, redirect URIs, grant types, RAR types, resources; agent profile editor; initial-access-token issuance with policy and quota; DCR policy editor with dry-run against a sample registration.

Spec: RFC 7591 §2; RFC 7592; E03_06 policy model; E11_01 agent profile.

Depends on: E14_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
