---
layout: bead.njk
permalink: "beads/ast-ndk-5.html"
id: "ast-ndk.5"
title: "i18n message bundles & `ui_locales` handling"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Fluent (or ICU) bundles en + fr, tenant string overrides validated against the bundle keys (no markup), locale negotiation from `ui_locales` → Accept-Language → tenant default.

Spec: OIDC Core §3.1.2.1 (`ui_locales`: preferred languages in order; OP MUST NOT error if unsupported), §5.2 (`claims_locales`); Discovery §3 (`ui_locales_supported`).

Depends on: E15_02

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
