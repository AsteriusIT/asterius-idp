---
layout: bead.njk
permalink: "beads/ast-ndk-3.html"
id: "ast-ndk.3"
title: "Strict CSP (nonce + strict-dynamic) & security headers on every HTML response"
status: "Open"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Middleware sets per-response nonce and headers: `Content-Security-Policy: default-src 'none'; script-src 'nonce-{n}' 'strict-dynamic'; style-src 'nonce-{n}'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self' {redirect-origin-when-form_post}; frame-ancestors 'none'; base-uri 'none'; object-src 'none'`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Cross-Origin-Opener-Policy: same-origin`, `Permissions-Policy: publickey-credentials-get=(self), publickey-credentials-create=(self)`, `Cache-Control: no-store` on interaction pages.

Spec: FAPI 2.0 SP §5.2.3 (browser endpoints: HSTS, no CORS on authorization endpoint); RFC 9700 §4 (clickjacking, referrer leakage); CSP Level 3; RFC 6797 (HSTS).

Depends on: E01_04

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
