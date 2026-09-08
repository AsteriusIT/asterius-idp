---
layout: bead.njk
permalink: "beads/ast-uwv-2.html"
id: "ast-uwv.2"
title: "Grant model & persistence (every token links to a revocable grant)"
status: "Open"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

`grants` row: tenant, client, user (null for client_credentials), scopes, claims, authorization_details, resources, status (pending|active|revoked|expired), created_at, last_updated_at, expires_at, updated_by. Codes, refresh tokens, access-token jti and device/CIBA requests reference `grant_id`.

Spec: Grant Management for OAuth 2.0 ID1 (draft-03) §5.6 'Lifecycle of the grant' (active once tokens claimed; delete unclaimed after timeout; AS may modify); FAPI 2.0 SP §6.7 item 4 (record relationships between credentials issued for the same authorization so they can be revoked together).

Depends on: E01_03, E03_01, E06_06

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
