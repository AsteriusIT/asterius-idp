---
layout: bead.njk
permalink: "beads/ast-1sk-4.html"
id: "ast-1sk.4"
title: "Claims resolution service (scopes → claims, `claims` parameter, placement, i18n)"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Pure function from (grant, user claims store, request `claims`, `claims_locales`) to (id_token claims, userinfo claims). Tenant-configurable scope→claim mapping with OIDC defaults.

Spec: OIDC Core §5.1 (standard claims), §5.2 (claims languages and scripts: `#` language tag suffix; `claims_locales`), §5.4 (scope values profile/email/address/phone/offline_access), §5.5 (`claims` request parameter: `userinfo` and `id_token` members; `essential`, `value`, `values`; 'MUST NOT return claims the user did not consent to'; unknown claims ignored), §5.5.1 (individual claims requests), §5.5.1.1 (acr), §5.6.1 (normal claims); Discovery §3 (`claims_supported`, `claims_parameter_supported`, `claims_locales_supported`).

Depends on: E06_06

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
