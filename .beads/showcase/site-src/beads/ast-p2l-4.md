---
layout: bead.njk
permalink: "beads/ast-p2l-4.html"
id: "ast-p2l.4"
title: "Secrets & data hygiene: retention jobs, log redaction proof, PII minimisation, backups doc"
status: "Open"
type: "Task"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Scheduled cleanup of codes, PAR requests, interactions, expired sessions, jti denylist, outbox, replay caches; audit PII hashing; log redaction regression test; backup/restore runbook covering KEK handling.

Spec: RFC 9700 §4.2–4.3 (credential leakage); FAPI 2.0 SP §7 (privacy: data minimisation, data leak from AS); GDPR data minimisation (informational).

Depends on: E01_05

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
