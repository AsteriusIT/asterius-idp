---
layout: bead.njk
permalink: "beads/ast-2vk-6.html"
id: "ast-2vk.6"
title: "User & issuer-agnostic claims model (public/pairwise subjects)"
status: "Open"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

`users` (stable `sub`, status, tenant), `identifiers` (email/phone with `verified`), `claims` JSONB where every claim carries `value`, `source` (local|admin|import|<issuer>) and `verified_at` so future aggregated/verified claims fit without a schema change. Pairwise `sub` = base64url(SHA-256(sector || local_sub || tenant_salt)).

Spec: OIDC Core §5.1 (standard claims), §5.7 (claim stability and uniqueness: sub locally unique, never reassigned), §8 (subject identifier types public/pairwise), §8.1 (pairwise algorithm: sector identifier from `sector_identifier_uri` host or redirect_uri host; MUST NOT be reversible; salt), §5.6.2 (aggregated/distributed claims — schema readiness only); OIDC Registration §5 (sector_identifier_uri validation).

Depends on: E01_03, E01_10

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
