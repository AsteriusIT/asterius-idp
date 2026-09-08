---
layout: bead.njk
permalink: "beads/ast-p2l-2.html"
id: "ast-p2l.2"
title: "Decision: OIDC Core certification profile vs PAR-only baseline (conformance_mode)"
status: "Open"
type: "Decision"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Options: (a) certify FAPI 2.0 only (+ logout profiles where compatible); (b) add a tenant-scoped `conformance_mode` that accepts non-PAR requests solely for certification runs, clearly non-FAPI; (c) skip OIDC certification. Recommendation: (a) now, (b) only if a customer requires the OP marks; never enable (b) on a FAPI tenant.

Spec: OIDF OpenID Provider certification plans (Basic OP, Config OP, Dynamic OP, Form Post, Logout profiles) send non-PAR authorization requests; FAPI 2.0 SP §5.3.2.2 item 3 requires rejecting them.

Depends on: E16_01
