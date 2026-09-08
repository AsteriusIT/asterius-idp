---
layout: bead.njk
permalink: "beads/ast-83p-1.html"
id: "ast-83p.1"
title: "Cargo workspace & modular-monolith crate layout (ports & adapters)"
status: "Closed"
type: "Chore"
priority: "Critical"
assignee: "Quentin RODIC"
origin: "agent"
updated: "5h ago"
---

Single binary `asterius` with crates: `domain` (entities, ports), `oidc` (protocol logic, no I/O), `jose` (KeyStore/Signer port + josekit adapter), `store-pg` (sqlx adapters), `web` (askama SSR pages), `admin-api`, `server` (axum wiring). Protocol crates must not depend on sqlx/axum.

Spec: Project ADR 0001 (modular monolith); FAPI 2.0 SP §5.1.1 (build on complete, correct implementations).
