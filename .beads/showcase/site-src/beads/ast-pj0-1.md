---
layout: bead.njk
permalink: "beads/ast-pj0-1.html"
id: "ast-pj0.1"
title: "Access Evaluation endpoint (`POST /access/v1/evaluation`)"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

PEPs authenticate with a DPoP-bound access token (scope `authzen.evaluate`, `aud` = PDP identifier). Decisions come from the `PolicyEngine` port (E13_04). Fail closed.

Spec: Authorization API 1.0 §5 (information model: Subject {type, id REQUIRED, properties}, Resource {type, id, properties}, Action {name REQUIRED, properties}, Context, Decision {decision boolean REQUIRED, context}), §6.1 (request: subject, action, resource REQUIRED; context OPTIONAL), §6.2 (response = Decision), §10.1 (HTTPS JSON binding: POST, `Content-Type: application/json`, 200 + JSON; default path /access/v1/evaluation), §10.1.1 (JSON serialisation: missing required → 400; ignore unknown fields; no ordering assumptions), §10.1.2 (errors 400/401/403/500 — a deny is 200 {decision:false}), §10.1.3 (`X-Request-ID` echoed when present), §11.1–11.2 (TLS; authenticate the PEP), §11.5 (I-JSON, omit nulls), §11.7 (DoS: payload limits, rate limiting).

Depends on: E13_04, E08_08

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
