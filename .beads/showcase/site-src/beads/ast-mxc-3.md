---
layout: bead.njk
permalink: "beads/ast-mxc-3.html"
id: "ast-mxc.3"
title: "Key lifecycle & automated rotation (encrypted at rest, KMS port)"
status: "Closed"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "1h ago"
---

States `pending → active → retiring → retired`. Per-tenant rotation schedule; private keys encrypted with a KEK obtained from a `Kek` port (local file / env for dev, cloud KMS adapters later). Separate keys per purpose (id_token/access_token signing, SET signing may share; encryption keys separate).

Spec: OIDC Core §10.1.1 (rotation of asymmetric signing keys: publish new key, then sign with it; keep old for verification); FAPI 2.0 SP §6.7 (key compromise: automated regular rotation, single-purpose keys).

Depends on: E02_01

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
