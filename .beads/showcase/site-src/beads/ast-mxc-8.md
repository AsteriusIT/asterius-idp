---
layout: bead.njk
permalink: "beads/ast-mxc-8.html"
id: "ast-mxc.8"
title: "client_keys table cannot express a negative cache entry"
status: "Open"
type: "Task"
priority: "Low"
assignee: "Unassigned"
origin: "agent"
updated: "2m ago"
---

The client_keys table is keyed by (tenant_id, client_id, kid). A *failed* jwks_uri fetch has no kid, so there is no row that can represent 'we tried this URI at T and it failed'. The negative cache from ast-mxc.5 is therefore in-memory and per-replica: N replicas will each hammer an unreachable third-party jwks_uri once per backoff window instead of once between them, and a restart clears the memory of the failure entirely.

Not urgent — the in-memory cache is correct, just not shared — but it becomes real when the deployment is multi-replica, which the modular monolith of ADR-0001 explicitly expects to be.

Options: (a) add a client_key_fetches table keyed by (tenant_id, client_id, jwks_uri) holding last_attempt_at / last_error / next_attempt_at; (b) leave it per-replica and document the multiplier in the operator docs; (c) treat it as covered by whatever shared cache ast-f7m picks up.

Decide before the first multi-replica deployment, not after a client complains about our traffic.
