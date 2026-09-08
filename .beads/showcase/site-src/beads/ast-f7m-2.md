---
layout: bead.njk
permalink: "beads/ast-f7m-2.html"
id: "ast-f7m.2"
title: "Decision: admin console as a first-party same-origin app (not an OAuth public client)"
status: "Open"
type: "Decision"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Options: (a) console authenticates with the IdP's own session cookie (same origin), calls `/admin/api` with CSRF protection; (b) console as OIDC public client with DPoP — violates baseline; (c) separate BFF service — new component. Recommendation (a): no tokens in the browser, CSP strict, no third-party origins; the console is just another server-rendered-entry SPA of the IdP.

Spec: FAPI 2.0 SP §5.3.2.1 item 3 (confidential clients only) — a browser SPA cannot be a FAPI 2.0 client; RFC 9700 §4 (browser-based app risks).

Depends on: E01_09
