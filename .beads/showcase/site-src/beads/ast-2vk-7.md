---
layout: bead.njk
permalink: "beads/ast-2vk-7.html"
id: "ast-2vk.7"
title: "ACR/AMR policy, `acr_values` processing & step-up authentication"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Tenant policy: ordered ACR levels with the credential combinations that satisfy them (e.g., `urn:asterius:acr:passkey-uv` → passkey with UV; `phrh` mapping optional). Voluntary `acr_values` picks the highest achievable; essential picks exactly one of the requested or fails. Step-up reuses the session and re-authenticates with a stronger credential.

Spec: OIDC Core §2 (acr/amr/auth_time semantics), §3.1.2.1 (acr_values: voluntary), §5.5.1.1 (essential acr via `claims`: 'MUST return an acr Claim' matching one of the requested values or fail), §3.1.2.3; Unmet Authentication Requirements 1.0 §2 (`unmet_authentication_requirements` when the OP cannot meet the requested acr); EAP ACR Values 1.0 (`phr`, `phrh` — Final, informational for naming).

Depends on: E06_04, E06_05

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
