---
layout: bead.njk
permalink: "beads/ast-lh3-6.html"
id: "ast-lh3.6"
title: "Approvals inbox: human-in-the-loop approval UX for CIBA, device flow and agent step-ups"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

SSR page `/account/approvals` listing pending requests (CIBA, device, agent scope elevation) with client/agent identity, binding_message or user_code, scopes/RAR/resources, expiry countdown (no JS required), Approve/Deny. Notification port (email/push adapters) informs the user.

Spec: CIBA Core §8 (OP identifies the user, authenticates on the authentication device, 'MUST obtain an authorization decision as described in Section 3.1.2.4 of OpenID Core'), §7.1 (binding_message displayed on both devices), §14 (security: login_hint_token signed); RFC 8628 §3.3, §5.3 (show client identity, warn).

Depends on: E11_04, E11_03, E06_04

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
