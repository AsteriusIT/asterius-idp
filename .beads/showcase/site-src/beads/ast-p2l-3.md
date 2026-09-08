---
layout: bead.njk
permalink: "beads/ast-p2l-3.html"
id: "ast-p2l.3"
title: "Rate limiting & abuse controls across endpoints"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

In-process token buckets (per instance; documented) keyed by (tenant, endpoint, client|ip|user) with 429 + `Retry-After`; polling grants get `slow_down`; login/registration/reset get silent throttling (E06_09).

Spec: RFC 8628 §5.1–5.2 (brute force on user/device codes); CIBA §11 (over-polling → invalid_request); RFC 9126 §7.1 (request_uri guessing); RFC 7591 §5 (registration abuse); RFC 6749 §10.x; Authorization API 1.0 §11.7 (DoS).

Depends on: E01_04

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
