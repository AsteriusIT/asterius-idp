---
layout: bead.njk
permalink: "beads/ast-83p-7.html"
id: "ast-83p.7"
title: "Fuzz & property-test harness with parser-coverage gate"
status: "Closed"
type: "Chore"
priority: "Critical"
assignee: "Quentin RODIC"
origin: "agent"
updated: "3h ago"
---

cargo-fuzz workspace + proptest conventions. A script maps every module under `parsers/` or `validators/` (or tagged `#[fuzzable]`) to a fuzz target and fails CI when one is missing. First targets: `application/x-www-form-urlencoded` parser, JWT compact-serialisation parser, JSON metadata parser.

Spec: Project DoD: fuzz target for every parser/validator.

Depends on: E01_06
