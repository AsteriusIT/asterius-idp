---
layout: bead.njk
permalink: "beads/ast-gxh-3.html"
id: "ast-gxh.3"
title: "PKCE S256 enforcement (no plain, no missing)"
status: "Open"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Validation at PAR (challenge present, method S256, well-formed) and at the token endpoint (verifier present, S256 match, constant-time).

Spec: RFC 7636 §4.1 (verifier 43–128 unreserved chars), §4.2 (S256 = BASE64URL(SHA256(ASCII(verifier)))), §4.3 (client sends challenge), §4.4 (server associates challenge with code), §4.5 (client sends verifier), §4.6 (server verifies), §7.2 (entropy); FAPI 2.0 SP §5.3.2.2 item 5 ('shall require PKCE with S256'); RFC 9700 §4.8 (PKCE downgrade attack: reject token requests without verifier when challenge was present, and never accept codes issued without PKCE).

Depends on: E02_06

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
