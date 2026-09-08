---
layout: bead.njk
permalink: "beads/ast-uwv-3.html"
id: "ast-uwv.3"
title: "Consent memory & offline_access / refresh-token consent rules"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Skip the consent screen when the user previously granted a superset for this client (and prompt≠consent); always show it when new scopes/claims/details/resources are requested or when `offline_access` is requested for the first time.

Spec: OIDC Core §11 (Offline Access: `offline_access` scope; 'MUST ignore the offline_access request unless the Client is using a response_type value that would result in an Authorization Code being returned'; OP 'MUST obtain explicit consent' — prompt=consent expected unless other conditions), §3.1.2.4.

Depends on: E07_01, E07_02

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
