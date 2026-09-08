---
layout: bead.njk
permalink: "beads/ast-83p-5.html"
id: "ast-83p.5"
title: "Observability: tracing, redaction, metrics, health endpoints"
status: "Closed"
type: "Task"
priority: "High"
assignee: "Quentin RODIC"
origin: "agent"
updated: "3h ago"
---

tracing with per-request span (request id, tenant, client_id, sub hashed), structured JSON logs, a redaction layer for anything that looks like a token/code/assertion/password, Prometheus metrics, `/healthz` and `/readyz` (DB ping).

Spec: RFC 9700 §4.2/§4.3 (credential leakage via logs/referrers — informational).

Depends on: E01_04

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
