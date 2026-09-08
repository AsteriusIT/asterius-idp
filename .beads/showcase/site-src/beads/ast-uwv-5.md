---
layout: bead.njk
permalink: "beads/ast-uwv-5.html"
id: "ast-uwv.5"
title: "Grant Management API (GET/DELETE /grants/{grant_id}) + token-response `grant_id` + metadata"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Access with a DPoP-bound client_credentials access token carrying the query/revoke scope and `aud` = grant management resource; only the owning client can address a grant.

Spec: Grant Management ID1 §5.5 (token response `grant_id` MUST be returned when a valid action was requested), §6.1 (scopes `grant_management_query`, `grant_management_revoke`), §6.2 (https endpoint; `grant_management_endpoint`), §6.3 (resource URL = endpoint + '/' + grant_id), §6.4 (query response: scopes[{scope,resource}], claims, authorization_details, created_at, last_updated_at, expires_at, updated_by; no tokens exposed), §6.5 (DELETE → 204; 'MUST revoke the grant and all refresh tokens'; should revoke access tokens), §6.6 (404 unknown, 403 unauthorized, 401 `invalid_token`), §7.1 (`grant_management_actions_supported`, `grant_management_endpoint`, `grant_management_action_required`).

Depends on: E07_04, E08_08, E08_06

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
