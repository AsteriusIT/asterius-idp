---
layout: bead.njk
permalink: "beads/ast-a05-7.html"
id: "ast-a05.7"
title: "Certificate-bound access tokens (RFC 8705 §3) [flag: mtls]"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

When the client is registered with `tls_client_certificate_bound_access_tokens: true` and presents a certificate at the token endpoint, bind the access token to it instead of DPoP.

Spec: RFC 8705 §3 (mutual-TLS certificate-bound access tokens), §3.1 (`cnf` `x5t#S256`), §3.2 (introspection), §3.3 (AS metadata `tls_client_certificate_bound_access_tokens`), §3.4 (client metadata `tls_client_certificate_bound_access_tokens`), §5 (`mtls_endpoint_aliases`); FAPI 2.0 SP §5.3.2.1 item 5.

Depends on: E03_03, E08_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
