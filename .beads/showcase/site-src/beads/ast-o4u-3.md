---
layout: bead.njk
permalink: "beads/ast-o4u-3.html"
id: "ast-o4u.3"
title: "Session revocation by admin/user with propagation (back-channel logout + CAEP)"
status: "Open"
type: "Feature"
priority: "High"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Admin API / console and account page can revoke one, many or all sessions of a user; propagation reuses E10_02 and E12_08.

Spec: Back-Channel Logout §2.5; CAEP 1.0 §3.1 (session-revoked); product requirement (continuous access).

Depends on: E10_02, E14_01

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
