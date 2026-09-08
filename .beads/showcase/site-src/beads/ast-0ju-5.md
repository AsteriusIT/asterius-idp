---
layout: bead.njk
permalink: "beads/ast-0ju-5.html"
id: "ast-0ju.5"
title: "Verification event & Stream Updated event"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Both events bypass `events_requested` filtering (spec allows) and go through the normal outbox delivery.

Spec: SSF 1.0 §8.1.4 (verification: event type https://schemas.openid.net/secevent/ssf/event-type/verification; `state` echoed; `sub_id` MUST be opaque = stream_id), §8.1.4.2 (POST verification endpoint {stream_id, state} → 204; 429 under `min_verification_interval`; asynchronous transmission allowed), §8.1.5 (stream-updated: type …/stream-updated with `status`, `reason`; MUST be sent before pausing/disabling and upon re-enabling; `sub_id` opaque stream_id).

Depends on: E12_04, E12_02

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
