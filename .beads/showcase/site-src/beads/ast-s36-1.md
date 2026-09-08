---
layout: bead.njk
permalink: "beads/ast-s36-1.html"
id: "ast-s36.1"
title: "Track: FAPI 2.0 Message Signing (JAR + JARM + HTTP message signatures)"
status: "Open"
type: "Task"
priority: "Backlog"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Non-repudiation profile on top of FAPI 2.0 SP. E05_09 (JAR in PAR) is the only prerequisite worth keeping optional in v1. Re-evaluate when Message Signing reaches Final.

Spec: FAPI 2.0 Message Signing draft-02 (Implementer's Draft; 'not an OIDF International Standard'); JARM (Final, errata set 1) §2 (JWT response document: iss, aud, exp ≤10 min, plus response params), §4 (response modes query.jwt/fragment.jwt/form_post.jwt/jwt).
