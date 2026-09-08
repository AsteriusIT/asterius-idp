---
layout: bead.njk
permalink: "beads/ast-m9c-1.html"
id: "ast-m9c.1"
title: "Client model & metadata validation (confidential clients only)"
status: "Closed"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "2h ago"
---

`Client` aggregate + validating parser used by DCR, admin API and seed scripts. Defaults are the FAPI values; anything weaker is rejected, not defaulted.

Spec: RFC 7591 §2 (client metadata), §2.1 (grant_types ↔ response_types consistency); OIDC Registration §2 (application_type, subject_type, sector_identifier_uri, id_token_signed_response_alg, token_endpoint_auth_method …); RFC 9126 §6 (`require_pushed_authorization_requests`); RFC 9449 §12 (`dpop_bound_access_tokens`); RFC 9396 §9.2 (`authorization_details_types`); CIBA §4 (backchannel_* client metadata); FAPI 2.0 SP §5.2.2.1.1 (`use_mtls_endpoint_aliases`), §5.3.2.1 item 3 ('shall only support confidential clients').

Depends on: E01_03, E01_10

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
