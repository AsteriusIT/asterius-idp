---
layout: bead.njk
permalink: "beads/ast-0ju-3.html"
id: "ast-0ju.3"
title: "Stream Configuration endpoint (create/read/update/replace/delete)"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Receivers are registered clients holding a DPoP-bound client_credentials token with scope `ssf.manage` and `aud` = SSF management resource. One stream per receiver per audience by default (409 otherwise) — tenant option for multiple.

Spec: SSF 1.0 §8 (management API MUST use standard HTTP auth; authorization MUST associate a receiver with stream ids/aud), §8.1.1 (stream configuration: stream_id, iss, aud (immutable), events_supported, events_requested, events_delivered (⊆ supported ∩ requested; receiver relies on it), delivery {method, endpoint_url, authorization_header}, min_verification_interval, description, inactivity_timeout), §8.1.1.1 (POST → 201; 409 when multiple streams unsupported; default delivery poll with transmitter-supplied endpoint_url; 400 unsupported method), §8.1.1.2 (GET with/without stream_id → object or list; `Cache-Control: no-store`), §8.1.1.3 (PATCH: stream_id required; only receiver-supplied properties change; transmitter-supplied must match), §8.1.1.4 (PUT: full receiver-supplied set; missing = delete), §8.1.1.5 (DELETE → 204); error tables (400/401/403/404).

Depends on: E12_01, E08_08

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
