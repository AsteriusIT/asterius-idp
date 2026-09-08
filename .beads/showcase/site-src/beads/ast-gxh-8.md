---
layout: bead.njk
permalink: "beads/ast-gxh-8.html"
id: "ast-gxh.8"
title: "prompt / max_age / id_token_hint / login_hint / acr_values handling and unmet-requirements error"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Deterministic decision table from (session state, prompt, max_age, hints, acr policy) to {silent, login, consent, register, error}.

Spec: OIDC Core §3.1.2.1 (prompt none|login|consent|select_account and combination rules; max_age; id_token_hint 'MUST be validated' / 'SHOULD' sub match; login_hint; acr_values), §3.1.2.3 (re-authentication rules), §3.1.2.6 (login_required, consent_required, interaction_required, account_selection_required), §5.5.1.1 (essential acr); OpenID Connect Prompt Create 1.0 §3–§4 (prompt=create; `prompt_values_supported`); OpenID Connect Core Unmet Authentication Requirements 1.0 §2 (`unmet_authentication_requirements`).

Depends on: E05_02, E06_07

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
