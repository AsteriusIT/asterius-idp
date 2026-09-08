---
layout: bead.njk
permalink: "beads/ast-m9c-8.html"
id: "ast-m9c.8"
title: "Decision: MCP public clients & Client ID Metadata Documents (CIMD)"
status: "Open"
type: "Decision"
priority: "Medium"
assignee: "Unassigned"
origin: "agent"
updated: "14h ago"
---

Two fixed product decisions conflict for off-the-shelf MCP clients (public, no PAR, localhost redirect). Options: (a) FAPI-only — MCP compatibility limited to confidential MCP clients registered via DCR with `jwks` + private_key_jwt, PAR and DPoP (E11_08); (b) a tenant-level 'OAuth 2.1 public-client profile' (PKCE S256 + DPoP-bound tokens + exact loopback redirect, PAR optional) that weakens the baseline. Recommendation: (a) for v1; revisit when CIMD is an RFC and OIDF conformance has a public-client FAPI-adjacent profile.

Spec: MCP Authorization (2025-11-25): AS MUST implement OAuth 2.1 'for both confidential and public clients'; AS SHOULD support Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document-00 — IETF working draft: track, don't implement); AS MAY support RFC 7591; FAPI 2.0 SP §5.3.2.1 item 3 (confidential clients only).

Depends on: E01_09
