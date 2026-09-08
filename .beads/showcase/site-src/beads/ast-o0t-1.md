---
layout: bead.njk
permalink: "beads/ast-o0t-1.html"
id: "ast-o0t.1"
title: "OpenID Provider Configuration endpoint (`/.well-known/openid-configuration`)"
status: "Closed"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "1h ago"
---

Rendered from the capability registry (E04_03) per tenant; served at the path-appended form and the path-inserted form.

Spec: OIDC Discovery §3 (OpenID Provider Metadata: REQUIRED issuer, authorization_endpoint, token_endpoint, jwks_uri, response_types_supported, subject_types_supported, id_token_signing_alg_values_supported; others), §4.1 (request), §4.2 (response: application/json, 200), §4.3 (validation: issuer MUST be identical to the URL used); FAPI 2.0 SP §5.3.2.1 item 1 (distribute metadata via OIDD/RFC 8414); RFC 9126 §5; RFC 9207 §3; RFC 9449 §11; RFC 9396 §9.1; MCP Authorization 2025-11-25 ('Authorization servers providing OpenID Connect Discovery 1.0 MUST include code_challenge_methods_supported').

Depends on: E04_03, E02_02, E01_10

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
