---
layout: bead.njk
permalink: "beads/ast-m9c-3.html"
id: "ast-m9c.3"
title: "Client authentication: mTLS (`tls_client_auth`, `self_signed_tls_client_auth`) [flag: mtls]"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Certificate arrives either from rustls (terminate mode) or from a proxy header (`behind_proxy` + trusted CIDR only). Exactly one of the subject/SAN metadata fields is registered and matched exactly.

Spec: RFC 8705 §2.1 (PKI method: subject DN / SAN matching), §2.1.2 (client metadata tls_client_auth_subject_dn, *_san_dns/uri/ip/email), §2.2 (self-signed: match against registered JWKS `x5c`), §5 (`mtls_endpoint_aliases`); FAPI 2.0 SP §5.2.2 (MTLS ecosystems), §5.3.2.1 item 6.

Depends on: E03_01, E01_04

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
