---
layout: bead.njk
permalink: "beads/ast-mxc-5.html"
id: "ast-mxc.5"
title: "Client key resolution & caching (`jwks` / `jwks_uri`, SSRF guard)"
status: "Closed"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "1m ago"
---

Resolver used by private_key_jwt, DPoP (no — DPoP uses embedded jwk), request objects, CIBA signed requests. Fetches `jwks_uri` over TLS with strict limits and caches per client.

Spec: RFC 7591 §2 (`jwks_uri` and `jwks` MUST NOT both be present); OIDC Registration §2; OIDC Core §10.1.1 (fetch JWKS again on unknown kid); FAPI 2.0 SP §5.4.2 (JWKS over TLS; recommend jwks_uri or jwks + RFC 7591/7592).

Depends on: E02_04

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
