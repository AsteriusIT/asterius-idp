---
layout: bead.njk
permalink: "beads/ast-p2l-1.html"
id: "ast-p2l.1"
title: "FAPI 2.0 Security Profile conformance suite green in CI (release gate)"
status: "Open"
type: "Task"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Run the full plan nightly and on release branches; publish report; track waivers explicitly (none expected).

Spec: FAPI 2.0 Security Profile (Final); OIDF conformance plan `fapi2-security-profile-final` variants: client_auth_type=private_key_jwt, sender_constrain=dpop, fapi_profile=plain_fapi, openid=openid_connect (+ mtls variant when flag on).

Depends on: E01_08, E08_09, E05_05, E09_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
