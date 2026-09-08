---
layout: bead.njk
permalink: "beads/ast-83p-8.html"
id: "ast-83p.8"
title: "OIDF conformance-suite harness (local + nightly)"
status: "Open"
type: "Chore"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

docker-compose that runs the OpenID conformance suite against a local instance with a seeded tenant + two test clients (private_key_jwt + DPoP); CI job runs the FAPI2 SP plan and archives the report. Plans for OIDC Core are gated by decision E16_02.

Spec: FAPI 2.0 SP §6.6 (use certified/complete implementations); OIDF conformance suite plan `fapi2-security-profile-final` (client auth private_key_jwt, sender-constraining DPoP).

Depends on: E01_04
