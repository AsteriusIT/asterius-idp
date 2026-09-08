---
layout: bead.njk
permalink: "beads/ast-m9c-7.html"
id: "ast-m9c.7"
title: "Redirect URI validation: exact match, https-only, loopback exception"
status: "Closed"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "1h ago"
---

One function used at registration, PAR and token endpoint. FAPI 2.0 permits unregistered redirect URIs via PAR; this product deliberately keeps exact matching against the registered set (defense in depth; documented in ADR).

Spec: RFC 6749 §3.1.2.2–3.1.2.3 (registered redirect URI; comparison); RFC 9700 §4.1 (exact string matching, no pattern matching); RFC 8252 §7.3 (loopback interface redirection, any port); FAPI 2.0 SP §5.3.2.2 item 8 ('shall not allow redirect URIs that use the http scheme except for native clients that use loopback interface redirection').

Depends on: E03_01

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
