---
layout: bead.njk
permalink: "beads/ast-lh3-2.html"
id: "ast-lh3.2"
title: "Token Exchange (RFC 8693) with delegation chains (`act`), narrowing-only"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Agents obtain a token to act *for* a user (delegation, `act` chain) or, when policy explicitly allows, *as* a user (impersonation, no `act`). Subject tokens: our access tokens or ID tokens; actor token optional (defaults to the authenticated client). Every exchange narrows: scope ⊆ subject scope ∩ actor allowed; aud ⊆ allowed; TTL ≤ subject remaining.

Spec: RFC 8693 §2.1 (request: grant_type urn:ietf:params:oauth:grant-type:token-exchange, resource, audience, scope, requested_token_type, subject_token, subject_token_type REQUIRED, actor_token, actor_token_type), §2.2.1 (response: access_token, issued_token_type REQUIRED, token_type, expires_in, scope, refresh_token), §2.2.2 (error: invalid_request/invalid_grant; invalid_target for unacceptable resource/audience), §3 (token type identifiers), §4.1 (`act` claim; nested chains; most recent actor outermost), §4.4 (`may_act`), §5 (security: delegation vs impersonation policy), §6 (privacy).

Depends on: E08_01, E08_06, E08_03, E11_01

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
