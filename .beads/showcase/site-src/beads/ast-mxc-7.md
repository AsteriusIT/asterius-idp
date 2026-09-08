---
layout: bead.njk
permalink: "beads/ast-mxc-7.html"
id: "ast-mxc.7"
title: "Wire PgKeyRepository into the server (keys are still in-memory at runtime)"
status: "Closed"
type: "Task"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "28m ago"
---

ast-mxc.3 built PgKeyRepository with encryption at rest, rotation states and a KEK port, and it implements the domain KeyStore port. The binary still constructs asterius_jose::LocalKeyStore, so at runtime every tenant's signing key is generated at startup and lost on restart: tokens signed before a restart stop verifying, the JWKS changes on every boot, and none of the encryption-at-rest or rotation work is reachable.

Two shape mismatches to resolve: PgKeyRepository::new(pool, tenant, kek, audit) is per-tenant, while ProtocolState holds a single Arc<dyn KeyStore> whose methods already take a TenantId; and the KEK has to come from configuration (a Kek port implementation chosen at boot, LocalKek for dev).

Also add TenantScope::keys() so the crate's 'every repository hangs off TenantScope' documentation stays true.
