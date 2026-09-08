---
layout: bead.njk
permalink: "beads/ast-lh3-5.html"
id: "ast-lh3.5"
title: "CIBA token delivery: poll & ping (`urn:openid:params:grant-type:ciba`)"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Poll: token endpoint grant handler. Ping: outbox job posts the callback after the user decides, then the client polls once.

Spec: CIBA Core §10 (single registered delivery mode), §10.1 (token request: grant_type ciba, auth_req_id; 'MUST check whether the auth_req_id was issued to this Client'; polling not more frequent than `interval`; long polling optional; 503 + Retry-After under load), §10.1.1 (successful response per OIDC Core §3.1.3.3; auth_req_id no longer valid after redemption), §10.2 (ping callback: POST JSON {auth_req_id} with `Authorization: Bearer <client_notification_token>`; client SHOULD answer 204; OP MUST NOT follow redirects), §11 (errors authorization_pending, slow_down (+5 s), expired_token, access_denied; invalid_grant when auth_req_id invalid/other client; invalid_request when polling too fast; unauthorized_client for push clients).

Depends on: E11_04, E08_01, E08_06, E12_09

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
