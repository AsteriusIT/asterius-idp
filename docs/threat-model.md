# Threat model

**Status:** baseline. Every story that adds a protocol surface updates this file
as part of its definition of done; `ast-p2l.6` closes it out before external
review.

**Sources.** [FAPI 2.0 Attacker Model][am] (Final) §5 security goals, §6 model,
§7 attacker definitions; [FAPI 2.0 Security Profile][sp] (Final) §5.2 network
layer, §5.3 profile, §5.4 cryptography and secrets, §6 security considerations.

[am]: https://openid.net/specs/fapi-attacker-model-2_0-final.html
[sp]: https://openid.net/specs/fapi-security-profile-2_0-final.html

> **Verification status.** The attacker labels and clause references below were
> transcribed from the Final specifications. Per the project rule in
> [CONTRIBUTING.md](../CONTRIBUTING.md), a human must re-read the cited clause
> before the corresponding control is considered done — a citation in this table
> is a claim to be checked, not evidence.

## 1. Security goals

The three goals Asterius must hold for *arbitrary combinations* of the attackers
in §2, potentially collaborating (Attacker Model §7.1):

| ID | Goal | Attacker Model |
|---|---|---|
| **G1** | **Authorization.** No attacker can access protected resources other than their own. | §5.2 |
| **G2** | **Authentication.** No attacker can log in at a client under another user's identity. | §5.3 |
| **G3** | **Session integrity.** No attacker can force a user to be logged in as the attacker, or to use the attacker's resources. | §5.4 |

Asterius adds one goal that FAPI does not cover, because the product targets
agents as first-class principals:

| ID | Goal | Rationale |
|---|---|---|
| **G4** | **Delegation integrity.** An agent cannot obtain authority it was not delegated, cannot widen authority across a token exchange, and every token traces to a named human or service principal and a revocable grant. | Agent threats, §4 |

## 2. Attacker capabilities

Taken from Attacker Model §7. Note that **A3b was removed** from the Final
specification (§7.5 note) and **A4 is documented as not relevant to FAPI 2.0**,
because FAPI 2.0 clients learn the token endpoint from authenticated metadata
and authenticate to it with `private_key_jwt` or mTLS.

| ID | §  | Capability |
|---|---|---|
| **A1** | 7.2 | *Web attacker.* Sends and receives messages, participates in flows as a normal user, tampers with its own messages using arbitrary tools, sends links to honest users. Cannot intercept others' traffic or break cryptography. |
| **A1a** | 7.3 | *Web attacker acting as an authorization server.* A1, plus operates an AS in the ecosystem and may replay messages received from honest ASes. |
| **A2** | 7.4 | *Network attacker.* Controls the whole network: intercepts, blocks and tampers with messages. Still cannot break cryptography. |
| **A3a** | 7.5 | *Reads the authorization request* in the front channel, on its way from the browser to the authorization server. |
| **A4** | 7.6 | *Reads and tampers with token requests and responses* by making a client use a token endpoint that is not the honest AS's. Marked not relevant in FAPI 2.0. |
| **A5** | 7.7 | *Reads resource requests* — e.g. a TLS-intercepting proxy log at the resource server. |

**Trusted computing base** (Attacker Model §6): TLS as deployed, the browser,
the operating system CSPRNG, the PostgreSQL instance and its disk, the identity
management of the human user, and the correctness of the JOSE library. Anything
in this list going wrong is out of scope for this document and belongs in the
operations runbook.

## 3. Control mapping

Read a row as: *this attacker capability threatens this goal; this control is
what stops it; this bead builds the control and its test.*

| Attacker | Goal | Attack it enables | Control | Bead |
|---|---|---|---|---|
| A1 | G1, G3 | Registers a client whose `redirect_uri` is a prefix/substring of an honest one, or a public client with no secret at all | Exact-string redirect-URI matching, https-only, no wildcards; confidential clients only, no public clients, no implicit, no ROPC | `ast-m9c.7`, `ast-m9c.1` |
| A1 | G3 | CSRF on the authorization endpoint or on login/consent forms | PAR-only requests (a request the attacker cannot forge without client authentication); per-form CSRF token bound to the interaction; `SameSite` session cookie | `ast-gxh.1`, `ast-gxh.2`, `ast-2vk.1` |
| A1 | G1, G2 | Registers a tenant, or exploits an operator typo, so that two tenants answer to one issuer and `iss` becomes ambiguous | Issuer identifiers are validated (https, no query, fragment or userinfo) and canonicalised once at startup; duplicate ids and duplicate *canonical* issuers refuse the boot | `ast-83p.2` |
| A1 | G1 | Mix-up: honest client is tricked into sending a code to the wrong AS | `iss` in the authorization response (RFC 9207); audience-bound tokens; per-tenant issuer identity | `ast-gxh.4`, `ast-83p.10` |
| A1 | G2 | Uses a leaked or replayed ID Token at a client | `nonce` binding, explicit `typ`, `aud` = client, short lifetime, `at_hash` | `ast-a05.4`, `ast-mxc.4` |
| A1 | G1 | Registers an agent client and asks for authority beyond its policy | Per-tenant DCR policy engine; agent client profile pinning allowed grants, audiences and RAR types | `ast-m9c.6`, `ast-lh3.1` |
| A1 | G1, G3 | Floods login, consent, device or CIBA endpoints (credential stuffing, approval fatigue) | Rate limiting and abuse controls per endpoint and per principal; generic login errors with no account enumeration | `ast-p2l.3`, `ast-2vk.9` |
| A1a | G1, G2 | Operates a rogue AS and replays honest messages; serves malicious metadata or JWKS | Client keys resolved only from the tenant's own registered `jwks`/`jwks_uri` with an SSRF guard; `iss`/`aud` checked on every JWT; no `jku`/`x5u` headers honoured (SP §5.4.2) | `ast-mxc.5`, `ast-mxc.4` |
| A1a | G1 | Replays a client assertion captured from an honest AS against Asterius | `private_key_jwt` audience is this tenant's issuer; single-use `jti` replay cache with the assertion's own lifetime | `ast-m9c.2`, `ast-mxc.4` |
| A2 | G1, G2, G3 | Reads or rewrites any message in flight; strips TLS | TLS 1.2/1.3 only, BCP 195 suites, HSTS with `preload` on every browser-facing response, RFC 9525 certificate checks, HTTP→HTTPS never downgraded (SP §5.2.1–5.2.3) | `ast-83p.4` |
| A2 | G3 | Uses a 307 redirect to make the browser replay a credential-bearing POST to the attacker's URL | Redirect helper that can only emit 303 (SP §5.3.2.2 items 10–11), enforced by a grep test over the tree | `ast-83p.4` |
| A2 | G1 | Steals a bearer access token off the wire or from a log and replays it | Sender-constrained tokens only: DPoP proof-of-possession (`cnf.jkt`), or certificate binding under the `mtls` flag. A stolen token is useless without the private key | `ast-a05.6`, `ast-a05.7` |
| A3a | G1, G3 | Reads the authorization request and learns `state`, `scope`, the PKCE challenge, or a leaked secret | PAR: the front-channel request carries only `client_id` and `request_uri`, so there is nothing in it to read. PKCE S256 means the challenge is not the verifier | `ast-gxh.1`, `ast-gxh.3` |
| A3a | G1 | Injects a stolen authorization code into an honest client's callback (code injection) | PKCE S256 mandatory and rejected when absent or `plain`; code bound to the PAR request, the client and the DPoP key; single use with revocation of the whole grant on replay; ≤ 60 s lifetime (SP §5.4.1) | `ast-gxh.3`, `ast-gxh.4`, `ast-a05.2` |
| A4 | G1 | Substitutes the token endpoint and reads or rewrites the token exchange | Token endpoint is published in signed, TLS-served tenant metadata; clients authenticate with `private_key_jwt`/mTLS, so a substituted endpoint cannot mint a valid token; tokens are audience-bound | `ast-o0t.1`, `ast-m9c.2`, `ast-a05.3` |
| A5 | G1 | Reads resource requests at the RS (TLS-intercepting proxy) and replays the access token | DPoP binding makes a captured token unusable; the resource indicator (`resource`) narrows `aud` so a token for RS-A is rejected by RS-B | `ast-a05.6`, `ast-gxh.7`, `ast-a05.3` |
| A5 | G1 | Uses a long-lived token after the user's access should have ended | Short access-token lifetimes; every token linked to a revocable grant; revocation and CAEP `session-revoked` propagate within seconds | `ast-uwv.2`, `ast-1sk.2`, `ast-0ju.8` |
| A1, A2 | G1 | Reads a secret out of a log line, a panic message or a `Debug` dump of the configuration | `Secret<T>` prints `[REDACTED]` from both `Debug` and `Display`, has no `Deref` or `Serialize`, and zeroes on drop; exposing it requires a greppable `expose()` call | `ast-83p.2`, `ast-mxc.6` |
| A1, A2 | G1 | Reads credentials out of the database after a backup or replica leak | Opaque credentials (codes, refresh tokens, device codes, `auth_req_id`, registration tokens) stored only as SHA-256 digests; passwords as Argon2id; private keys encrypted at rest | `ast-83p.3`, `ast-mxc.3` |
| A1, A2 | G1 | Guesses a credential | ≥ 128 bits of entropy from the OS CSPRNG for every non-human-handled credential (SP §5.4.1); constant-time comparison | `ast-mxc.6` |
| A1 | G1 | Downgrades signing to `none` or to an algorithm with a known weakness | Algorithm allow-list at both signing and verification: EdDSA, ES256, PS256. `none` is never accepted; RS256 only under the non-FAPI `compat.rs256` flag | `ast-mxc.1`, ADR-0003 |

### 4. Agent-specific threats (G4)

FAPI's attacker model has no notion of a principal acting for another principal.
These rows are ours.

| ID | Threat | Control | Bead |
|---|---|---|---|
| **T-A1** | **Delegation-chain widening.** An agent exchanges a narrow token for a broader one, or forges an `act` chain to impersonate the human. | Token exchange is narrowing-only: the issued token's scopes, audiences and `authorization_details` must be a subset of the subject token's; `act` is appended by the AS, never accepted from the client; chain depth is bounded by client policy. | `ast-lh3.2`, `ast-lh3.1` |
| **T-A2** | **Confused-deputy MCP server.** An MCP server holding a user's token is induced by a malicious tool description to call a resource on the attacker's behalf. | Resource indicators make every token audience-specific, so an MCP server cannot reuse a token outside its own audience; MCP clients are confidential; a pre-issuance policy decision gates each mint. | `ast-gxh.7`, `ast-lh3.8`, `ast-lh3.10` |
| **T-A3** | **Approval fatigue.** An agent issues repeated CIBA/device approvals until the human accepts one out of habit. | Rate-limited approval requests per agent and per user; the approvals inbox shows what changed against the last approval; standing consents are explicit, listed and revocable through Grant Management. | `ast-lh3.6`, `ast-p2l.3`, `ast-uwv.5` |
| **T-A4** | **Agent key compromise with no blast-radius limit.** | Every agent is a confidential client with its own key; grants are per-agent and individually revocable; the per-agent audit trail reconstructs everything a compromised agent did, including the delegation chains it used. | `ast-lh3.1`, `ast-lh3.9`, `ast-83p.11` |
| **T-A5** | **Silent divergence after human access ends.** A human is off-boarded but their agents keep working. | CAEP `session-revoked` / `credential-change` / `assurance-level-change` events over SSF; grant revocation cascades to every token minted from it. | `ast-0ju.8`, `ast-o4u.3` |

## 5. Known residual risks

| Risk | Why we accept it (for now) | Tracked by |
|---|---|---|
| No refresh-token rotation. | FAPI 2.0 SP §5.3.2.1 forbids relying on rotation as a security measure; refresh tokens are sender-constrained and grant-bound instead, so theft without the key is not usable. | — |
| Grant Management is an Implementer's Draft. | Behind a feature flag, off by default; metadata advertises it only when enabled. | `ast-uwv.4` |
| `compat.rs256` produces a non-FAPI deployment. | Explicit, off by default, logs at startup and sets `fapi_compliant=false` on `/readyz`; excluded from conformance builds. | ADR-0003, `ast-83p.12` |
| FAPI 2.0 Message Signing (JAR/JARM/HTTP signatures) not implemented. | Out of v1 scope; the attacker model above does not require it for G1–G3 at this profile level. | `ast-s36.1` |
| No formal analysis of the agent extensions. | G4 is ours, not FAPI's, so it has no published formal model. Mitigated by narrowing-only exchange and audit. | `ast-p2l.6` |

## 6. Keeping this file honest

A story is not done until this file reflects it. Concretely, the definition of
done for any protocol story is:

1. a spec-derived or conformance-suite test passes;
2. a fuzz target exists for every new parser or validator;
3. the relevant row here is added or updated, with the bead id;
4. no new `unsafe` (enforced: `#![forbid(unsafe_code)]` in every crate);
5. a human has read the cited spec clause.
