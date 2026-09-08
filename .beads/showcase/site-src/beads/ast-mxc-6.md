---
layout: bead.njk
permalink: "beads/ast-mxc-6.html"
id: "ast-mxc.6"
title: "CSPRNG token generation & secret-handling utilities (constant-time compare, zeroize)"
status: "Closed"
type: "Task"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "2h ago"
---

`OpaqueToken::generate(bits)` (default 256) base64url without padding; `Secret<T>` with `zeroize`; `ct_eq` wrapper (subtle) used for every secret comparison; hashing helper `sha256_hex` for at-rest storage.

Spec: FAPI 2.0 SP §5.4.1 item 4 (credentials not handled by end users ≥128 bits of entropy); RFC 6749 §10.10 (credential guessing); RFC 8628 §6.1 (user-code entropy — used later).

Depends on: E01_01

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
