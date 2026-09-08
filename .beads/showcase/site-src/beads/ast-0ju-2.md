---
layout: bead.njk
permalink: "beads/ast-0ju-2.html"
id: "ast-0ju.2"
title: "SET issuance profile (SSF §4): explicit typing, subjects, single event, txn"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

`SetBuilder` enforcing the profile and signing with the tenant key (EdDSA/ES256).

Spec: SSF 1.0 §3.1 (top-level `sub_id` MUST describe the primary subject; existing CAEP/RISC events MAY also use `subject` inside the event, but `sub_id` MUST still be present), §3.2–3.3 (simple and complex subjects: user, device, session, application, tenant, org_unit, group), §3.4–3.5 (RFC 9493 formats + jwt_id, saml_assertion_id, ip-addresses), §4.1.1 (`typ: secevent+jwt` MUST), §4.1.2 (`sub` claim MUST NOT be present), §4.1.6 (`iss` MUST match stream `iss`), §4.1.7 (`exp` MUST NOT be used), §4.1.8 (`aud`), §4.1.9 (`txn` SHOULD; unique per underlying event), §4.2.1 (`events` SHOULD contain only one event); RFC 8417 §2.

Depends on: E02_01

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
