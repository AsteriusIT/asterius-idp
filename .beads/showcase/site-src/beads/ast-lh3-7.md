---
layout: bead.njk
permalink: "beads/ast-lh3-7.html"
id: "ast-lh3.7"
title: "CIBA & device-flow metadata and client-registration validation"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Wire the capability registry and the client validator for both flows.

Spec: CIBA Core §4 (OP metadata: backchannel_token_delivery_modes_supported REQUIRED, backchannel_authentication_endpoint REQUIRED, backchannel_authentication_request_signing_alg_values_supported, backchannel_user_code_parameter_supported; grant type in grant_types_supported; client metadata: backchannel_token_delivery_mode REQUIRED, backchannel_client_notification_endpoint REQUIRED (https) for ping/push, backchannel_authentication_request_signing_alg, backchannel_user_code_parameter; pairwise + poll/ping requires jwks_uri/sector_identifier_uri); RFC 8628 §4 (`device_authorization_endpoint`).

Depends on: E03_01, E04_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
