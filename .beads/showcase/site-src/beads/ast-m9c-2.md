---
layout: bead.njk
permalink: "beads/ast-m9c-2.html"
id: "ast-m9c.2"
title: "Client authentication: private_key_jwt"
status: "Open"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "4h ago"
---

Shared authenticator used by token, PAR, introspection, revocation, device-authorization and backchannel-authentication endpoints. Keys resolved via E02_05.

Spec: OIDC Core §9 (private_key_jwt: iss=sub=client_id, aud, jti, exp; MAY contain iat); RFC 7523 §3 (JWT format and processing; jti MAY be used to reject replay); RFC 7521 §4.2 (client_assertion_type urn:ietf:params:oauth:client-assertion-type:jwt-bearer); FAPI 2.0 SP §5.3.2.1 item 6 (authenticate with mTLS or private_key_jwt), item 8 ('shall only accept its issuer identifier value … as a string in the aud claim'); CIBA §7.1 (backchannel endpoint MUST also accept token endpoint URL / backchannel endpoint URL as aud).

Depends on: E03_01, E02_04, E02_05

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
