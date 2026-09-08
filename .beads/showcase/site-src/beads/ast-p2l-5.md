---
layout: bead.njk
permalink: "beads/ast-p2l-5.html"
id: "ast-p2l.5"
title: "Fuzz-coverage gate, nightly fuzzing, cargo-geiger/deny/audit gates"
status: "Open"
type: "Chore"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Finalize the coverage gate (E01_07) across all parser modules added by the protocol epics; nightly 10-minute runs per target with corpus persistence; `cargo geiger` zero unsafe in workspace crates; `cargo deny`/`cargo audit` gates.

Spec: Project DoD (fuzz target for every parser; no new unsafe).

Depends on: E01_07
