---
layout: bead.njk
permalink: "beads/ast-a05-4.html"
id: "ast-a05.4"
title: "ID Token issuance (claims, nonce, auth_time, acr/amr, sid, at_hash, pairwise sub)"
status: "Open"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Built after grant/claims resolution (E09_04). Signed with the client's `id_token_signed_response_alg` (default EdDSA). Explicit `typ: JWT` header.

Spec: OIDC Core §2 (ID Token claims: iss, sub, aud, exp, iat REQUIRED; auth_time, nonce, acr, amr, azp), §3.1.3.6 (ID Token from token endpoint; at_hash OPTIONAL in code flow), §3.1.3.7 (validation rules the client applies — drive our tests), §5.4/§5.5 (claims in the ID Token via scopes/`claims`), §10.1 (signing; `alg` per `id_token_signed_response_alg`; `none` forbidden here), §15.1 (mandatory to implement), §8.1 (pairwise sub); Back-Channel Logout §2.3 (remembering logged-in RPs) and §2.4 (`sid` in ID Token and Logout Token).

Depends on: E02_01, E09_04

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
