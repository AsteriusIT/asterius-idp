---
layout: bead.njk
permalink: "beads/ast-lh3-3.html"
id: "ast-lh3.3"
title: "Device Authorization Grant (RFC 8628) for confidential agents/devices"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

For CLI agents/headless devices. Approval happens in the approvals inbox (E11_06) after passkey authentication.

Spec: RFC 8628 §3.1 (device authorization request: client_id/auth, scope), §3.2 (response: device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval), §3.3 (user interaction; §3.3.1 non-textual), §3.4 (token request grant_type urn:ietf:params:oauth:grant-type:device_code), §3.5 (errors authorization_pending, slow_down (+5 s), access_denied, expired_token), §4 (`device_authorization_endpoint`), §5.1 (user code brute forcing: entropy + rate limiting), §5.2 (device code brute forcing), §5.3 (remote phishing: show client identity, warn), §5.4 (session spying), §6.1 (user code recommendations: case-insensitive, unambiguous alphabet, e.g. 8 chars ≈ 34.5 bits with base-20 alphabet); FAPI 2.0 SP §5.3.2.1 item 3 (confidential clients only → client authentication required at the device authorization endpoint; documented deviation from typical public-client usage).

Depends on: E08_01, E08_06, E06_01, E07_01

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
