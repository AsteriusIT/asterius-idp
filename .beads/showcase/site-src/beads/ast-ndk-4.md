---
layout: bead.njk
permalink: "beads/ast-ndk-4.html"
id: "ast-ndk.4"
title: "Progressive-enhancement test suite (JS disabled and enabled)"
status: "Open"
type: "Chore"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Playwright suites: (1) JS disabled — password login → consent → form_post continue button → RP receives code; device verification; logout; account pages. (2) JS enabled — passkeys via virtual authenticator, form_post auto-submit, conditional UI.

Spec: Product rule: pages must work without JavaScript and support response_mode=form_post.

Depends on: E15_02, E05_05, E11_03
