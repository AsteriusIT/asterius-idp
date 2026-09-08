---
layout: bead.njk
permalink: "beads/ast-2vk-3.html"
id: "ast-2vk.3"
title: "Passkey registration (WebAuthn L3 via webauthn-rs)"
status: "Open"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

RP ID = tenant host (configurable subdomain policy). Discoverable credentials requested, user verification required by default, attestation `none` unless tenant enables enterprise attestation with an AAGUID allowlist.

Spec: W3C WebAuthn Level 3 §7.1 (registering a new credential: challenge, origin, RP ID, UV, attestation); FIDO Alliance passkey guidance (discoverable credentials).

Depends on: E06_02, E06_06

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
