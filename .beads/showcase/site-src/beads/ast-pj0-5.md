---
layout: bead.njk
permalink: "beads/ast-pj0-5.html"
id: "ast-pj0.5"
title: "Decision: policy language for the built-in PDP (declarative rules vs Cedar vs external OPA)"
status: "Open"
type: "Decision"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Options: (a) small declarative rule model (JSON/YAML) tailored to IdP data — simplest, explainable, no new language; (b) embed Cedar (`cedar-policy` crate) behind the port — expressive, well-analysed, adds a policy language to learn; (c) delegate to external OPA — new runtime dependency, contradicts single-binary. Recommendation: (a) for v1 with the port shaped so (b) is a drop-in adapter; revisit when customers need cross-resource policies.

Spec: Authorization API 1.0 §2 ('policy language, architecture, and state management aspects of a PDP are beyond the scope').

Depends on: E01_09
