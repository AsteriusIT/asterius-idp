---
layout: bead.njk
permalink: "beads/ast-0ju-7.html"
id: "ast-0ju.7"
title: "Poll delivery (RFC 8936) endpoint with acknowledgement"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Per-stream poll endpoint protected with the receiver's DPoP-bound access token.

Spec: RFC 8936 §2.1–2.2 (poll request JSON: `maxEvents`, `returnImmediately`, `ack` [jti…], `setErrs`), §2.3 (response: `sets` {jti: SET}, `moreAvailable`), §2.4 (acknowledgement removes SETs; unacknowledged SETs are redelivered; error reporting via `setErrs`; long polling when `returnImmediately` is false — subsection numbers from memory, verify); SSF 1.0 §6.1.2 (poll `endpoint_url` transmitter-supplied, unique per stream per receiver); §7.1.1 (authorization_schemes SHOULD protect the polling endpoint).

Depends on: E12_02, E12_09, E12_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
