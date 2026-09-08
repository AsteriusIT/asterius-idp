---
layout: bead.njk
permalink: "beads/ast-o4u-4.html"
id: "ast-o4u.4"
title: "Decision: no Session Management (check_session_iframe) and no Front-Channel Logout in v1"
status: "Open"
type: "Decision"
priority: "Low"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Both mechanisms require iframes/JavaScript and third-party cookies that browsers now block, and conflict with the strict CSP / no-JS baseline. Back-channel logout + CAEP session-revoked cover the need. Recommendation: not planned; `frontchannel_logout_supported` absent; ADR documents how to add later if a customer needs it.

Spec: OpenID Connect Session Management 1.0 (iframe + postMessage; depends on third-party cookies); OpenID Connect Front-Channel Logout 1.0 (iframes rendered in the OP page).

Depends on: E01_09
