---
layout: bead.njk
permalink: "beads/ast-0ju-6.html"
id: "ast-0ju.6"
title: "Push delivery (RFC 8935) via outbox worker"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Outbox worker (E12_09) delivers each SET individually, in order per subject, with exponential backoff and a dead-letter state visible in the console.

Spec: RFC 8935 §2.1 (POST SET with `Content-Type: application/secevent+jwt`, `Accept: application/json`), §2.2 (success 202; SETs MUST be transmitted one at a time), §2.3 (failure: 400 with JSON `err`/`description`; `invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`, `authentication_failed`, `access_denied`), §2.4 (retries for 5xx/timeouts; do not retry on 4xx except 429/503); SSF 1.0 §6.1.1 (push: `endpoint_url` receiver-supplied; `authorization_header` MUST be sent with every request when provided).

Depends on: E12_02, E12_09, E12_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
