---
layout: bead.njk
permalink: "beads/ast-mxc-1.html"
id: "ast-mxc.1"
title: "KeyStore/Signer port + josekit adapter with algorithm allow-list"
status: "Closed"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "3h ago"
---

Trait `Signer { fn sign(&self, header: Header, claims: &[u8]) -> Result<Jws> }` and `KeyStore` (active key per (tenant, purpose, alg), lookup by kid). josekit adapter with aws-lc-rs/ring backends. Every issued JWT sets `kid`, `alg` and an explicit `typ`.

Spec: FAPI 2.0 SP §5.4.1 items 1–3 (RFC 8725 adherence; PS256/ES256/EdDSA(Ed25519) only; no `none`; RSA ≥2048; EC ≥224 bits); RFC 8725 §3.1 (verify alg), §3.2 (restrict algs), §3.11 (explicit typ); RFC 7515/7517/7518.

Depends on: E01_01, E01_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
