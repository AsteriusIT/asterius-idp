---
layout: bead.njk
permalink: "beads/ast-lh3-4.html"
id: "ast-lh3.4"
title: "CIBA backchannel authentication endpoint (poll/ping only)"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

`POST /t/{tenant}/bc-authorize`. Creates a pending authentication request that surfaces in the user's approvals inbox / notification channel.

Spec: OpenID Connect CIBA Core 1.0 (Final, 2021-09-01) §7 (endpoint MUST use TLS), §7.1 (authentication request: client auth per registered method — for JWT client assertions the OP 'MUST accept its Issuer Identifier, Token Endpoint URL, or Backchannel Authentication Endpoint URL' as aud; parameters scope (MUST contain openid), client_notification_token (REQUIRED for ping/push; ≤1024 chars; ≥128 bits), acr_values, login_hint_token, id_token_hint, login_hint, binding_message, user_code, requested_expiry; exactly one hint REQUIRED), §7.1.1 (signed authentication request: all params in JWT; aud = issuer, iss = client_id, exp, iat, nbf, jti; no params outside), §7.1.2 (user code), §7.2 (validation steps 1–6; ignore unrecognised parameters), §7.3 (ack: auth_req_id ≥128 bits, charset A-Za-z0-9.-_; expires_in; interval for poll/ping), §13 (errors: invalid_request, invalid_scope, expired_login_hint_token, unknown_user_id, unauthorized_client, missing_user_code, invalid_user_code, invalid_binding_message; 401 invalid_client; 403 access_denied); FAPI-CIBA profile (Final) — push mode not permitted.

Depends on: E11_07, E03_02, E06_06

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
