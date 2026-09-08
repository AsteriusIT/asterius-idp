---
layout: bead.njk
permalink: "beads/ast-0ju-9.html"
id: "ast-0ju.9"
title: "Transactional outbox & delivery worker (no Redis)"
status: "Open"
type: "Task"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

`outbox` table written in the same transaction as the domain change; worker claims rows with `SELECT … FOR UPDATE SKIP LOCKED`, delivers (SSF push, back-channel logout, CIBA ping, notifications), records attempts, applies backoff and dead-lettering. Per-key ordering (stream+subject, client+session).

Spec: Product architecture decision (single binary, one PostgreSQL, no Redis until measured need).

Depends on: E01_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
