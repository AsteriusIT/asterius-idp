---
layout: bead.njk
permalink: "beads/ast-0ju-4.html"
id: "ast-0ju.4"
title: "Stream Status & Subjects endpoints (add/remove, matching rules)"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Status transitions and subject membership per stream; `default_subjects: NONE` means only added subjects receive events (E12_01).

Spec: SSF 1.0 §8.1.2 (status enabled|paused|disabled; paused MUST NOT transmit and SHOULD hold, ordering per subject; disabled drops), §8.1.2.1 (GET status → {stream_id, status, reason}), §8.1.2.2 (POST status → 200 or 202 when undecided), §8.1.3 (subjects), §8.1.3.1 (subject matching: simple = identical; complex = each member undefined on either side or identical), §8.1.3.2 (add subject: POST {stream_id, subject, verified} → 200; MAY silently ignore; 404/403/429), §8.1.3.3 (remove subject → 204), §9.1 (subject probing: prefer 200/204 even when unknown), §9.3 (tolerate events after removal).

Depends on: E12_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
