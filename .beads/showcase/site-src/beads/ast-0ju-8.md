---
layout: bead.njk
permalink: "beads/ast-0ju-8.html"
id: "ast-0ju.8"
title: "CAEP/RISC event emitters (session-revoked, credential-change, assurance-level-change, account-disabled/enabled)"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Domain events (logout, admin/user session revoke, passkey add/remove/rename, password set/change/reset, step-up, account disable/enable — grant revocation has no CAEP event type and stays audit-only) map to SETs, filtered by stream subjects/events_requested, and enqueued.

Spec: CAEP 1.0 (Final) §2 (optional event claims common to all events: `event_timestamp` (seconds since epoch), `initiating_entity` admin|user|policy|system, `reason_admin`, `reason_user` — localized objects), §3.1 (session-revoked: no event-specific claims; complex subject {user, session, device, tenant} applies to matching sessions), §3.3 (credential-change: `credential_type` (password|pin|x509|fido2-platform|fido2-roaming|fido-u2f|verifiable-credential|phone-voice|phone-sms|app), `change_type` create|revoke|update|delete, `friendly_name`, `x509_issuer`, `x509_serial`, `fido2_aaguid`), §3.4 (assurance-level-change: `namespace`, `current_level`, `previous_level`, `change_direction` increase|decrease); RISC 1.0 (Final) account-disabled (`reason` hijacking|bulk-account), account-enabled; SSF 1.0 §3.1.1 (existing CAEP/RISC events MAY carry `subject` inside the event but `sub_id` MUST be present). Section numbers per the Final markdown structure — re-check against the published HTML while implementing.

Depends on: E12_02, E12_06, E12_07, E06_02

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
