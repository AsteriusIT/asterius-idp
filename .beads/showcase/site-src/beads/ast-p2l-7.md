---
layout: bead.njk
permalink: "beads/ast-p2l-7.html"
id: "ast-p2l.7"
title: "Release packaging & deployment docs (single binary, container, compose, Helm minimal)"
status: "Open"
type: "Task"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Reproducible release builds (musl/static where feasible), distroless image, migrations-on-start with advisory lock, example compose (PG + Asterius + conformance), minimal Helm chart, config reference generated from the config schema, TLS/HSTS/reverse-proxy guide, upgrade & rotation runbooks.

Spec: Product decision: single binary + one PostgreSQL; FAPI 2.0 SP §5.2 (TLS deployment guidance).

Depends on: E01_03, E01_04

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
