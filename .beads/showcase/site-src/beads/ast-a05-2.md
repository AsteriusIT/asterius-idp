---
layout: bead.njk
permalink: "beads/ast-a05-2.html"
id: "ast-a05.2"
title: "authorization_code grant (PKCE, redirect_uri, DPoP-key binding, replay)"
status: "Open"
type: "Feature"
priority: "Critical"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Redeem a code for tokens. All bindings recorded at issuance (E05_04) are checked here.

Spec: RFC 6749 §4.1.3 (grant_type=authorization_code, code, redirect_uri REQUIRED if included in the authorization request, client_id), §4.1.4; OIDC Core §3.1.3.1 (token request), §3.1.3.2 (validation: authenticate client, code issued to this client, code not used, redirect_uri identical), §3.1.3.3 (successful response: access_token, token_type, refresh_token, expires_in, id_token); RFC 7636 §4.6; RFC 9449 §10 ('Authorization Code Binding to DPoP Key': `dpop_jkt` must match the proof key at the token endpoint); RFC 8707 §2.2; FAPI 2.0 SP §5.3.2.1 item 12, §5.3.2.2 item 9.

Depends on: E08_01, E05_04, E05_03, E08_03, E08_04, E08_06

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
