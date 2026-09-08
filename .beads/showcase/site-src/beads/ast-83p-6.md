---
layout: bead.njk
permalink: "beads/ast-83p-6.html"
id: "ast-83p.6"
title: "CI pipeline (fmt, clippy, tests, sqlx check, cargo-deny/audit, fuzz smoke)"
status: "Closed"
type: "Chore"
priority: "Critical"
assignee: "Quentin RODIC"
origin: "agent"
updated: "5h ago"
---

GitHub Actions: fmt, clippy -D warnings, unit+integration tests against PostgreSQL service, `cargo sqlx prepare --check`, cargo-deny, cargo-audit, 60 s fuzz smoke per target, nightly conformance job (E01_08).

Spec: Project DoD (conformance test, fuzz target, threat-model note, no new unsafe).

Depends on: E01_01
