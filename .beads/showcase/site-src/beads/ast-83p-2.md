---
layout: bead.njk
permalink: "beads/ast-83p-2.html"
id: "ast-83p.2"
title: "Configuration, feature flags & issuer identity validation"
status: "Closed"
type: "Task"
priority: "Critical"
assignee: "Quentin RODIC"
origin: "agent"
updated: "5h ago"
---

Typed configuration (file + env overrides) and a feature-flag registry (`mtls`, `compat.rs256`, `grant_management`, `ciba`, `device_flow`, `token_exchange`, `ssf`, `authzen`, `dpop_nonce`). Secrets are typed `Secret<T>` and never Debug-printed.

Spec: RFC 8414 §2 (issuer: https URL, no query/fragment); OIDC Discovery §3 (issuer); FAPI 2.0 SP §5.3.2.1 item 1.

Depends on: E01_01

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
