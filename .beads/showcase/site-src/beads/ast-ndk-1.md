---
layout: bead.njk
permalink: "beads/ast-ndk-1.html"
id: "ast-ndk.1"
title: "Design-token model & tenant theming (no tenant HTML/CSS/JS)"
status: "Open"
type: "Feature"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Token schema: palette (with contrast validation), font stack from the self-hosted set, radius/spacing scale, logo (PNG/JPEG/WebP ≤ 200 KiB, re-encoded server-side; SVG rejected), favicon, product name, support links (https only). Rendered as CSS custom properties in a nonce'd `<style>` block.

Spec: Product rule: customization without a JS foothold; CSP `style-src` nonce; OWASP file upload cheat sheet (logo).

Depends on: E15_02

Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.
