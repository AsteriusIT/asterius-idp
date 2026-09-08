---
layout: bead.njk
permalink: "beads/ast-83p-4.html"
id: "ast-83p.4"
title: "HTTP server bootstrap & transport hardening (TLS, HSTS, 303, no CORS on /authorize)"
status: "Closed"
type: "Task"
priority: "Critical"
assignee: "Quentin RODIC"
origin: "agent"
updated: "4h ago"
---

axum + rustls bootstrap with two modes: terminate TLS (rustls, TLS 1.2/1.3, BCP195 suites only) or `behind_proxy` (trust `X-Forwarded-*`/`Forwarded` only from configured CIDRs). Shared middleware: request id, body size limits, timeouts, HSTS on browser-facing routes, redirect helper that only ever emits 303.

Spec: FAPI 2.0 SP §5.2.1 (TLS ≥1.2, BCP195, RFC 9525 cert check), §5.2.2 (server-to-server cipher suites), §5.2.3 (HSTS/TLS stripping, cipher suites, no CORS on authorization endpoint); §5.3.2.2 items 10–11 (never HTTP 307; use 303).

Depends on: E01_02

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
