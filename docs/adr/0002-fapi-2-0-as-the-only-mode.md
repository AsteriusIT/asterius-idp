# ADR-0002: FAPI 2.0 is the baseline, not a mode

- **Status:** Accepted (clause table corrected 2026-09-08; see *Corrections*)
- **Date:** 2026-09-08
- **Bead:** ast-83p.9
- **Deciders:** Quentin RODIC

## Context

Every mainstream identity provider ships OAuth 2.0's full historical surface —
implicit flow, resource-owner password credentials, public clients, bearer
tokens, wildcard redirect URIs — and offers FAPI as an opt-in profile applied
per client. That design has a predictable outcome: the secure configuration is
the one nobody selects, the insecure defaults stay reachable forever because
some tenant depends on them, and the security properties of a deployment cannot
be stated without auditing every client record.

The FAPI 2.0 Attacker Model is only meaningful as a whole. Goals G1–G3 are
claimed against *arbitrary combinations* of attackers A1–A5 (Attacker Model
§7.1); a single client left on bearer tokens or on the implicit flow does not
weaken that client alone — it puts an unconstrained credential into the same
sessions, the same audit trail and the same revocation surface as everything
else.

## Decision

FAPI 2.0 Security Profile behaviour is the **only** mode Asterius implements.
There is no per-client "FAPI mode" switch, because there is nothing to switch
away from. Concretely and without exception:

- No implicit flow, no hybrid flow, no ROPC, no public clients.
- Authorization requests are accepted **only** via PAR (RFC 9126); the
  authorization endpoint takes `client_id` + `request_uri` and nothing else.
- PKCE with `S256` is mandatory; `plain` and absent are errors.
- Access tokens are **always** sender-constrained (DPoP, or certificate binding
  under the `mtls` flag) and always audience-bound. Asterius never issues a
  usable bearer token.
- Client authentication is `private_key_jwt` or mTLS. No `client_secret_basic`,
  no `client_secret_post`.
- Redirect URIs match by exact string comparison, https only.
- Authorization codes live ≤ 60 s, are single-use, and a replay revokes the
  grant.
- Refresh tokens are not rotated (SP §5.3.2.1); they are sender-constrained and
  revocable instead.
- Every JWT carries an explicit `typ` and is signed with an allow-listed
  algorithm (see ADR-0003).

Deviations exist only as **named feature flags that are off by default** and
that are visible in metadata and on `/readyz`. A flag that weakens the baseline
(`compat.rs256`) reports `fapi_compliant=false` and is excluded from conformance
builds.

Rejected: *"FAPI as a per-client profile"* — the ecosystem's default, rejected
for the reasons above. Also rejected: *"FAPI plus a legacy tenant mode"* — same
problem with a larger blast radius, since a tenant-wide legacy mode also lowers
the session and revocation guarantees for that tenant's users.

## Consequences

**Easier.** The security properties of any deployment are a property of the
product, not of its configuration, so the threat model has one column instead of
one per client. Conformance is a release gate (`ast-p2l.1`) rather than a
per-tenant audit. There is no code path for the weak alternative, so there is no
downgrade to defend against.

**Harder.** Asterius cannot be dropped in front of an existing estate of OAuth
clients: a client using `client_secret_basic` and bearer tokens must be changed
before it can migrate. Some SDKs still lack DPoP and PAR. This is a deliberate
market position, not an oversight — but it means the migration guide
(`ast-p2l.7`) matters more than it would elsewhere, and `ast-p2l.2` must settle
whether a plain OIDC Core certification profile is worth a second conformance
run.

**To maintain.** The capability registry (`ast-o0t.3`) is the single source of
truth for what is enabled, and a parity test asserts that advertised metadata
and mounted routes agree — a flag that is off must not appear in metadata, and
a route that exists must be advertised.

## Spec clauses

| Clause | What it requires | How this decision satisfies it |
|---|---|---|
| FAPI 2.0 Attacker Model §7.1 | Goals hold for arbitrary combinations of A1, A1a, A2, A3a, A4, A5 | No client can opt out of the controls the goals depend on |
| FAPI 2.0 SP §5.3.2.1 | General AS requirements: confidential clients only (3), sender-constrained tokens (4), client authentication by mTLS or `private_key_jwt` (6), issuer identifier as a string in `aud` (8), no refresh-token rotation (9), authorization-code lifetime (11), JWT timestamp tolerance (13) | Implemented unconditionally rather than per client |
| FAPI 2.0 SP §5.3.2.2 | Authorization endpoint flows: `response_type=code` (1), PAR required (2, 3, 4), PKCE with `S256` (5), `redirect_uri` in the pushed request (6), `iss` in the authorization response (7), never HTTP 307 (10), `request_uri` under 600 s (12) | Implemented unconditionally rather than per client |
| FAPI 2.0 SP §5.4.1 | PS256/ES256/EdDSA only; never `none`; ≥128-bit credentials | Algorithm allow-list is global; see ADR-0003 |
| RFC 9126 §2 | PAR pushes the request server-side and returns a `request_uri` | The only accepted way to start an authorization request |

## Corrections

**2026-09-08.** The clause table attributed PAR, PKCE `S256` and exact redirect
matching to SP §5.3.2.1. Two of those are §5.3.2.2 — *Authorization endpoint
flows* — and the third is not a FAPI clause at all: exact redirect matching
comes from RFC 6749 §3.1.2.3 and RFC 9700 §4.1.3, which is what ADR-0005 cites.
The row is now two rows, itemised.

The decision this record makes is unchanged; only the citations were wrong. A
clause table exists to be checked against the specification during conformance
work, and one that points at the wrong section fails at the only job it has.
