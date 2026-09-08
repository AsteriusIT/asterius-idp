---
layout: bead.njk
permalink: "beads/ast-gxh-1.html"
id: "ast-gxh.1"
title: "Pushed Authorization Request endpoint (RFC 9126)"
status: "Open"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Validates the whole authorization request at push time with the same rules as E05_02, stores it keyed by a ≥128-bit reference bound to the client, and returns the `request_uri`.

Spec: RFC 9126 §2.1 (request: client auth, all authorization parameters, `request_uri` MUST NOT be present), §2.2 (201 with `request_uri` urn:ietf:params:oauth:request_uri:… and `expires_in`), §2.3 (errors incl. `invalid_request`, `invalid_client` 401), §2.4 (redirect URI management), §7.1 (request_uri guessing), §7.3 (replay); FAPI 2.0 SP §5.3.2.2 items 2–4 (support client-authenticated PAR; reject requests without PAR; reject PAR without client auth), 6 (`redirect_uri` required in PAR), 12 (`expires_in` < 600 s), Note 3 (enforce one-time use at authorization, not page load).

Depends on: E03_02, E03_07, E05_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
