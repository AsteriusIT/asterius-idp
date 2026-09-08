---
layout: bead.njk
permalink: "beads/ast-m9c-6.html"
id: "ast-m9c.6"
title: "Software statements & per-tenant DCR policy engine (agent onboarding profile)"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Declarative policy per tenant evaluated on every registration/update: allowed auth methods, grant types, scopes, audience/resource allowlist, redirect-URI host allowlist, require `jwks`/`jwks_uri`, require software statement from configured issuers (JWKS), max clients per initial access token, auto-expire unused clients, and a preset `agent` profile (E11_01).

Spec: RFC 7591 §2.3 (software statement JWT: signed by trusted issuer, values override plain metadata), §3.1.1 (registration with software statement), §5 (security: software statement trust, open registration risks).

Depends on: E03_04, E02_04

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
