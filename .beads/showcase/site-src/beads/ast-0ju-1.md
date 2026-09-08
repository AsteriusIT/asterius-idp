---
layout: bead.njk
permalink: "beads/ast-0ju-1.html"
id: "ast-0ju.1"
title: "SSF Transmitter Configuration Metadata (`/.well-known/ssf-configuration`)"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Per-tenant transmitter identity = tenant issuer; JWKS shared with the OP (SET signing keys may be the same purpose or a dedicated one — decide in E02_03).

Spec: SSF 1.0 §7.1 (metadata: spec_version, issuer REQUIRED (https, no query/fragment, identical to SET `iss`), jwks_uri (REQUIRED when signing; https), delivery_methods_supported, configuration_endpoint, status_endpoint, add_subject_endpoint, remove_subject_endpoint, verification_endpoint (all https), critical_subject_members, authorization_schemes [{spec_urn}], default_subjects ALL|NONE), §7.2 (well-known path inserted between host and path; application/json), §7.2.3 (200 + JSON), §7.2.4 (validation: issuer identical).

Depends on: E01_10, E02_02, E04_03

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
