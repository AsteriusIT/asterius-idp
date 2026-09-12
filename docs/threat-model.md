# Threat model

**Status:** review-ready (`ast-p2l.6`). Every story that adds a protocol surface
updates this file as part of its definition of done. Three sections exist for
somebody reading this from outside the project: [§4.1](#41-agent-threats-in-detail-ast-p2l6)
and [§4.2](#42-fapi-20-sp-6-security-considerations-one-row-each) give the
agent threats and the FAPI 2.0 SP §6 considerations in long form — control,
file, test, bead, residual — [§7](#7-decisions-pending-security-review) lists
the decisions nobody has taken yet, and [§8](#8-preparing-for-an-external-review)
is the artefact list for an audit. How to report a vulnerability in this
software is [`SECURITY.md`](../SECURITY.md).

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
| A1 | G1, G3 | Registers a client whose `redirect_uri` is a prefix/substring of an honest one, or a public client with no secret at all | Exact-string redirect-URI matching, https-only, no wildcards; confidential clients only, no public clients, no implicit, no ROPC. RFC 9700 §4.1.3 is implemented as written: comparison is RFC 3986 §6.2.1 simple string comparison, and no prefix, pattern or case-insensitive form exists to be exploited (ADR-0005) | `ast-m9c.7`, `ast-m9c.1` |
| A1 | G1, G3 | Pushes an **unregistered** `redirect_uri` through PAR. RFC 9126 §2.4 and RFC 9700 §4.1.3 both permit an AS to trust it because the client authenticated — and ADR-0002 makes Asterius qualify for that relaxation on every request, so one stolen `private_key_jwt` key would become a complete authorization-code exfiltration channel | The relaxation is declined: the registered set is consulted on every request (ADR-0005). A stolen client key still has to deliver the code to the honest client's registered callback. One comparison function serves registration, PAR and the token endpoint, so the three cannot develop different opinions about one URI | `ast-m9c.7`, `ast-gxh.1`, `ast-a05.2` |
| A1 | G1 | Presents a URI that is *equivalent* to a registered one under a normalisation the server applies but a browser does not — a resolved `..` segment, a decoded `%2F`, the Unicode spelling of a punycode host, a folded case, an explicit `:443` | Nothing is parsed, decoded or case-folded at comparison time: the stored bytes are compared to the presented bytes. The registered side is refused unless it is already the form a URL parser produces, so the two can never drift; the loopback branch splits canonical strings lexically rather than re-parsing them, because re-parsing on the comparison path is where a resolved `..` would do the damage | `ast-m9c.7`, `ast-m9c.1` |
| A1 | G1 | Widens the RFC 8252 §7.3 loopback exception past the port: another path on the same loopback host, another address inside 127/8, `localhost`, an out-of-range or zero-padded port, or an authority that reads as one (`http://127.0.0.1:51004@evil.example/cb`) | Only the port varies, per RFC 8252 §8.4 — "an exact match is required except for the port URI component". Host, path and query stay byte-exact; the presented URI must itself be one this server would have accepted at registration; and the exception is reachable only for `application_type=native`, since `localhost` resolves through DNS (RFC 8252 §8.3) | `ast-m9c.7` |
| A1 | G1 | Registers several spellings of one callback — 32 port variants of a loopback URI, say — so that the set an operator reviewed and the set the authorization endpoint uses are different sets | Registration compares a new entry with the same function the authorization endpoint uses, so a second spelling of one callback is a duplicate and is refused rather than stored | `ast-m9c.7` |
| A1 | G1, G2 | Registers a client that authenticates with a shared secret, or with nothing, and so needs only a stolen `client_id` to impersonate | `TokenEndpointAuthMethod` is a closed enum of `private_key_jwt`, `tls_client_auth` and `self_signed_tls_client_auth`; `client_secret_*` and `none` are not values that exist, and RFC 7591 §2's `client_secret_basic` default is replaced by `private_key_jwt` rather than honoured (FAPI 2.0 SP §5.3.2.1 item 3). The schema's `token_endpoint_auth_method` check is the same rule again, for a row inserted by hand | `ast-m9c.1` |
| A1, A5 | G1 | Registers `dpop_bound_access_tokens: false` and is issued bearer tokens, which are then replayable from a proxy log | `TokenBinding` has no unbound variant: DPoP is the default, and `false` is admissible only where `tls_client_certificate_bound_access_tokens` is true (RFC 9449 §5.2, RFC 8705 §3.4). "This client gets bearer tokens" is not a state the type can hold | `ast-m9c.1` |
| A1, A3a | G1, G3 | Registers `require_pushed_authorization_requests: false` and pushes the authorization request through the front channel instead | Refused at registration with `invalid_client_metadata`. RFC 9126 §6 defaults the field to false; accepting that and requiring PAR anyway would leave the client's own record contradicting the server | `ast-m9c.1`, `ast-gxh.1` |
| A1 | G1, G2 | Registers `id_token_signed_response_alg: none` or `RS256` and has its own ID Tokens signed with an algorithm outside the profile | Both are refused at registration rather than at first use, because `SigningAlgorithm` has no such variants (FAPI 2.0 SP §5.4.1, ADR-0003). The same allow-list covers `request_object_signing_alg` and the CIBA signing algorithm | `ast-m9c.1`, `ast-mxc.1` |
| A1 | G1, G3 | Registers a redirect URI whose registered string and effective destination differ — `https:///cb`, which WHATWG parsing resolves to the host `cb`, or a form that a browser normalises before requesting | A redirect URI must already be in normalised form or it is refused; nothing is ever rewritten, since rewriting would change what the client must send back and matching is byte-exact (RFC 9700 §4.1.3). Fragments, userinfo, non-https schemes, private-use schemes and duplicates are refused with `invalid_redirect_uri`. A property test asserts over generated URIs that what is accepted comes back byte-identical and that anything a URL parser would rewrite is refused | `ast-m9c.1`, `ast-m9c.7` |
| A1 | G1 | Registers a client for a grant behind a feature flag the deployment has switched off, reaching a code path the operator disabled | The grant is refused at registration, and a stored client that needs a flag which has since been turned off fails to load rather than loading as if it could authenticate | `ast-m9c.1`, `ast-o0t.3` |
| A1 | G2, G3 | Registers a client name carrying a right-to-left override, so the consent screen reads as another organisation's while the markup is innocuous | Control characters and the bidirectional formatting characters are refused in `client_name`; escaping in the template does not help against reordering that happens after escaping | `ast-m9c.1`, `ast-2vk.1` |
| A1, A2 | G1 | Reads part of a registration document back out of the `error_description` the registration endpoint returns, or out of the audit record of the failure | No rejection interpolates a value from the document — only field names, indexes and counts; a `serde_json` failure contributes its category and position, never its message. A property test asserts it for every rejected field | `ast-m9c.1`, `ast-83p.11` |
| A1 | G1, G2 | Edits a `clients` row directly during an incident, weakening a client that the registration endpoint would have refused | A row is turned back into a registration document and put through the same validator on the way out, so the adapter has no second, laxer definition of an acceptable client | `ast-m9c.1`, `ast-83p.3` |
| A1 | G1 | Registers clients at `POST /register` without any credential, filling `clients` with rows, inline JWKS blobs and (once `jwks_uri` fetching lands) one outbound fetch per registration at an address the attacker chose | The endpoint is closed unless an operator opens it, and opening it defaults to requiring a bearer initial access token (RFC 7591 §3). RFC 7591 §3's "SHOULD allow registration requests with no authorization" is declined by default and available as `mode = "open"`, which an operator has to type. The gate runs before the body is parsed, so a refused caller makes this process do no work beyond a header comparison | `ast-m9c.4`, `ast-p2l.3` |
| A1 | G1, G2 | Enumerates a deployment's clients, or picks a `client_id` that a resource server or an audit reader mistakes for an end-user `sub`, so that a token issued to a client is read as one issued for a person (OAuth Security BCP §4.15, FAPI 2.0 SP §6.7) | A `client_id` is 128 bits from the CSPRNG and cannot be influenced by the request at all — any `client_id` in the registration document is ignored. It carries a `c.` prefix, and `.` is in neither the `base64url` alphabet a pairwise `sub` uses nor the hex-and-hyphen shape of the UUID a public `sub` uses, so the two sets are disjoint by construction | `ast-m9c.4`, `ast-2vk.6` |
| A1, A5 | G1, G2 | Presents a **software statement** signed by a party this tenant never trusted, or by a key that party does not publish, and registers a client with metadata the registrant could not have asked for. RFC 7591 §2.3 gives a statement precedence over the plain JSON, so an accepted one *is* the registration | The trusted issuer list is per tenant, closed and configured — there is no discovery, no "any valid signature", and no way for a statement to nominate its own key set. An `iss` outside the list is `unapproved_software_statement` and costs no fetch. The `iss` in the unverified payload only selects which configured JWKS to fetch; verification then pins `iss` again under the signature, against keys fetched through ADR-0006's single outbound path. Precedence decides which values are used, never whether they are checked: the merged document goes through `ClientRegistration::from_json` and the tenant's policy exactly as a plain one does | `ast-m9c.6` |
| A1 | G1, G3 | Registers, at a tenant that meant to onboard agents, a client with a callback on a host the tenant does not own, a grant it does not use, or a scope nobody granted it — every one of which the profile itself permits | The registration policy is per-tenant **data**: allow-lists for auth methods, grant types, scopes, resources and redirect-URI hosts, validated against a JSON Schema before it is read, with no expression language and nothing tenant-authored ever evaluated. Evaluation is a set membership per rule, total and deterministic (fuzzed). An empty allow-list means "none", never "any". The same evaluation runs at `POST /register`, at RFC 7592's `PUT`, and in the admin console, so no door is laxer than another | `ast-m9c.6`, `ast-0qv` |
| A1, A5 | G1 | Finds a `registration_endpoint` in a deployment's discovery document, at a deployment or a tenant that registers nobody, and works through it | What gates the announcement gates the route: `[registration] mode` drives the `dynamic_client_registration` capability, a tenant's stored policy subtracts from it, and both the metadata document and `tenant_feature_guard` read the same effective capabilities. A tenant that registers nobody has no such member in its document and answers 404 at the path — not the 403 that told a caller there was something behind it | `ast-m9c.6`, `ast-0qv`, `ast-o0t.3`, `ast-edc` |
| A1 | G1, G4 | Holding `admin.clients:write` on one tenant, mints an initial access token from the admin console and uses it outside the console to register clients at a tenant, so that the clients it creates carry no administrative actor and appear as ordinary dynamic registrations | Issuance is a mutation: CSRF, an `Idempotency-Key`, `admin.clients:write` on that tenant, and an append-only audit record naming the actor, the label, the quota and the expiry — never the token. The credential's authority is exactly what that scope already grants, so it widens nobody: the holder could have created the same clients through `POST /clients`. What it changes is *attribution*, which is why the issuing administrator is also on the token's row (`initial_access_tokens.created_by`) and why the quota is stamped from the tenant's `max_clients_per_initial_access_token` rather than chosen by the caller — an administrator cannot mint themselves an unlimited credential at a tenant whose policy caps them | `ast-cu3`, `ast-f7m.5` |
| A1, A2 | G1, G2 | Recovers a registration access token — the bearer credential authorising changes to a client's keys and redirect URIs — from a backup, a read replica or a `pg_dump` pasted into a support ticket | Only `sha256(token)` is stored, in `clients.registration_access_token_hash`; the token itself exists in one response and nowhere else. An initial access token is treated the same way: configuration is hashed at load, so the running process holds no value that could be replayed against it, and the comparison accumulates over every configured digest rather than short-circuiting | `ast-m9c.4`, `ast-m9c.5` |
| A1 | G1 | Reads a registration document back out of the `error_description` of a *failed* registration, or splits a response header with a crafted field value | The description is written by this server from field names, indexes and counts, and is then reduced to RFC 6749 Appendix A.8's `NQSCHAR` — `%x20-21 / %x23-5B / %x5D-7E` — which drops CR, LF, `"` and `\`. RFC 7591 §3.2.2 requires ASCII; the filter is what makes the domain's human-readable `§` citations safe to put on the wire | `ast-m9c.4`, `ast-m9c.1` |
| A1 | G1, G2 | Presents its own registration access token at another client's `registration_client_uri` and reads, rewrites or deletes that client's registration — its redirect URIs, its keys, its whole record | The token is compared only against the digest stored for the client the URL names, in constant time over SHA-256 (`ct_eq`). There is no lookup by token anywhere, so a credential cannot be matched to a client it was not issued for even by accident — OIDC Registration §4.1 requires the client a configuration URL identifies to be "matched against the Client to which the Registration Access Token was issued". All three verbs go through one authentication function | `ast-m9c.5` |
| A5 | G1, G4 | Enumerates which `client_id` values are registered by probing the client configuration endpoint and reading the difference between "no such client" and "wrong token" | Both are one refusal value with one status, one error code, one description and one `WWW-Authenticate` challenge — OIDC Registration §4.4: "for security reasons, to inhibit brute force attacks, endpoints MUST NOT return the HTTP 404 Not Found status code". A client with no stored digest is compared against a per-process decoy, so an absent credential and a wrong one do the same cryptographic work. The only 403 is reachable after a token has been accepted | `ast-m9c.5` |
| A1 | G1, G3 | Updates one field of its registration and keeps a redirect URI, scope or algorithm it asked to drop, because the server merged the document into the stored row | A `PUT` is a replacement and nothing reads the old row into the new one: the body goes through `ClientRegistration::from_json` exactly as a fresh registration would, so an omitted field takes its registration-time default. RFC 7592 §2.2: "Omitted fields MUST be treated as null or empty values by the server, indicating the client's request to delete them" | `ast-m9c.5`, `ast-m9c.1` |
| A1 | G1, G2 | Updates itself into another client, into an unsuspended one, or into one holding a resource allow-list or agent profile it was never granted | The `update` statement names only the columns a registration document can express. `registration_access_token_hash`, `resources` (`ast-m9c.6`), the agent profile (`ast-lh3.1`), `software_statement`, `status`, `client_type` and `created_at` are untouched by construction rather than by a check. `client_id` must be present and must equal the one the URL names (RFC 7592 §2.2), and `client_secret`, `client_secret_expires_at` and `registration_access_token` are refused outright — a client that asked to set a credential and got a 200 would hold a false belief about its own | `ast-m9c.5` |
| A1, A5 | G1 | Keeps using a client's grants, refresh tokens or pushed requests after the registration is deleted | `DELETE` removes the row, and the schema cascades take `client_keys`, `auth_requests` and `grants` with it, and `authorization_codes` and `refresh_tokens` through `grants` — RFC 7592 §2.3's SHOULD, satisfied by the foreign keys rather than by a statement somebody has to remember to extend. The registration access token goes with the row, which is RFC 7592 §5's MUST, and every later request for that client is the same 401 a stranger gets. `audit_events` has no foreign key here, so the record of what the client did survives it | `ast-m9c.5`, `ast-83p.11` |
| A1, A5 | G1 | Keeps using an access token it was issued before its registration was deleted — a signed JWT inside its own `exp`, which no cascade can reach because this server holds no row for it and has never inventoried the `jti` values it signed | `deprovision` writes a cutoff for the `client_id` in the same transaction as the delete, in a table with no foreign key to `clients` so that the mark outlives the row it is about. UserInfo reads it beside the `jti` denylist, before the grant is loaded, and refuses any token whose `iat` is at or before the cutoff. One row per deprovisioning rather than one per token issued, expiring at the cutoff plus `MAX_ACCESS_TOKEN_LIFETIME` — past which every token it could refuse has failed on `exp` anyway | `ast-m9c.13`, `ast-m9c.5` |
| A1 | G1, G4 | Manages a client belonging to another tenant, where the same `client_id` exists | Every query is tenant-scoped by the handle, not by an argument: `TenantScope` is the only way to reach the repository. A `managed`, `replace` or `deprovision` aimed across tenants finds nothing, writes nothing and creates nothing — asserted against a table holding the same identifier in two tenants | `ast-m9c.5`, `ast-83p.10` |
| A1 | G3 | Sends a user to `/logout` with a `post_logout_redirect_uri` of their choosing, turning the end-session endpoint into an open redirect that starts on the provider's own origin | The URI is honoured only when a relying party has been *identified* — by an `id_token_hint` this server signed — and only when the value matches one of that client's registered `post_logout_redirect_uris` byte for byte (RP-Initiated Logout §3, §3.1). Anything else renders the neutral logged-out page, and `state` is echoed on a redirect and nowhere else. The registered set is the client's own §3.1 `post_logout_redirect_uris`, which pass the same admissibility gate as an authorization callback (https, no fragment, no userinfo, no re-spelling) and are compared with no exception at all — not even the RFC 8252 §7.3 loopback port a native client's callback may vary | `ast-o4u.1`, `ast-2jp` |
| A1 | G3 | Ends a victim's session from another site — an `<img src="…/logout">`, a cross-site form — which is a denial of service against every application the session serves | A logout with no verified `id_token_hint` never changes anything: it renders a confirmation question, and the answer is a POST carrying a synchroniser token derived from the session cookie, so a page that cannot read the cookie cannot produce the token. A verified hint is the RP's own request and is honoured, which is what §2 intends | `ast-o4u.1`, `ast-2vk.1` |
| A1 | G3 | Registers a client called "Example Bank", then links to `/logout?client_id=…` so that the provider itself renders the attacker's name and logo on a page asking the user to act | The confirmation page has no field a relying party can fill: it names the tenant and nothing else, and a template-level test asserts that no client-chosen value can be interpolated into it. A `client_id` alone never identifies an RP, so it cannot select branding | `ast-o4u.1` |
| A1 | G3 | CSRF on the authorization endpoint or on login/consent forms | PAR-only requests (a request the attacker cannot forge without client authentication); per-form CSRF token bound to the interaction; `SameSite` session cookie | `ast-gxh.1`, `ast-gxh.2`, `ast-2vk.1` |
| A1 | G1, G2 | Registers a tenant, or exploits an operator typo, so that two tenants answer to one issuer and `iss` becomes ambiguous | Issuer identifiers are validated (https, no query, fragment or userinfo) and canonicalised once at startup; duplicate ids and duplicate *canonical* issuers refuse the boot | `ast-83p.2` |
| A1 | G1, G2 | Reaches a tenant through a hostname it does not own, so tokens claim an issuer the request never spoke to | The resolved tenant is served only when the request's host is its issuer authority or its configured `custom_host`; anything else is 404 | `ast-83p.10` |
| A1 | G1 | Reaches a handler through a path spelling that routing and review did not consider — a relative segment, a non-absolute path | `tenancy::route` refuses any path that is not absolute or that contains a `.` or `..` segment, before a tenant is looked up. Both were found by fuzzing, not by review | `ast-83p.10`, `ast-83p.7` |
| A1 | G1 | Escapes a tenant path segment with traversal or encoding to reach another tenant's keys | `TenantId::parse` admits only `[a-z0-9][a-z0-9_-]{0,63}` — no `.`, no `%`, no upper case — and a malformed tenant path is refused before the directory is consulted | `ast-83p.10` |
| A1 | G1, G3 | Chooses the prefix the login page's own URLs are built from — a `X-Forwarded-Prefix`-style header, or a tenant named in a parameter — so that a form action, a `Location` or the path the sign-in script fetches points somewhere the attacker controls | The prefix a page hands back is the one `tenancy::layer` removed from *this* request and nothing else: a `MountPrefix` is built from the resolved route, never from a header or a parameter, and it is empty for a tenant resolved by host. It can only ever be `""` or `/t/{tenant}` with a `TenantId` that already passed `TenantId::parse`, so what it produces is a same-origin absolute path with no scheme, authority or control character in it — an open redirect cannot be spelled. Handlers still see the stripped path, so none of them gains a tenant parameter to get wrong | `ast-295`, `ast-83p.10` |
| A1 | — | Enumerates which tenants exist, and which have been suspended | Absent, disabled and wrong-host tenants return an identical 404 with an identical body | `ast-83p.10` |
| A1 | G1, G2 | Relies on metadata that describes a server other than the one running — an endpoint advertised but absent, or a capability advertised but off | One `Endpoint` registry is the only input to both the router and the document, and a test asserts both directions: every advertised URL resolves to a route, and every routed protocol endpoint is advertised (RFC 8414 §2) | `ast-o0t.3` |
| A1, A2 | G1 | Reads a private key out of the published key set, or is pointed at a key set the server does not control | The JWKS carries only public members — a test greps the response for `d`, `p`, `q`, `dp`, `dq`, `qi` and `k` — and never emits `x5u`, `jku` or `x5c` (FAPI 2.0 SP §5.4.2); no two published keys share a `kid` | `ast-mxc.2` |
| A1 | G1 | Mix-up: honest client is tricked into sending a code to the wrong AS | `iss` in the authorization response (RFC 9207); audience-bound tokens; per-tenant issuer identity | `ast-gxh.4`, `ast-83p.10` |
| A1 | G2 | Uses a leaked or replayed ID Token at a client | `nonce` binding, explicit `typ`, `aud` = client, short lifetime, `at_hash` | `ast-a05.4`, `ast-mxc.4` |
| A1 | G1 | Presents an ID token at a resource server as though it were an access token: it is signed by the same tenant key, carries the same `iss`, and names a `sub` | The two claim sets are disjoint and neither builder can write the other's, so this is a token that cannot be assembled rather than one that has to be spotted — an ID token carries no `cnf`, `scope`, `client_id`, `act` or `authorization_details`, and an access token carries no `nonce` or `at_hash`. Both carry an explicit type, `at+jwt` (RFC 9068 §2.1) and `JWT`, which `TypRule::Exactly` holds them to before a key is fetched. RFC 9068 §2.1 names this as the reason the media type was registered at all | `ast-a05.4`, `ast-a05.3`, `ast-mxc.4` |
| A1, A3a | G2 | Defeats the `at_hash` binding between the two halves of one token response — by having the hash computed under the wrong algorithm, so that a client which checks it either fails every honest sign-in or is patched to stop checking | `at_hash` is OIDC Core §3.1.3.6's "left-most **half** of the hash", taken under the hash the ID token's own `alg` names — and that `alg` is the client's registered `id_token_signed_response_alg`, pinned by `UnsignedToken::required_algorithm` and carried into `Signer::sign` rather than left to whichever tenant key the signer reaches for — a tenant holding no key of that algorithm refuses the request (`DomainError::NoSigningKey`) rather than substituting one. EdDSA is the trap: RFC 8037 §3.1 leaves the hash to the curve rather than to `alg`, and Ed25519 is EdDSA with SHA-512 (RFC 8032 §5.1), so the half is 256 bits and not the 128 the specification's `RS256` example shows. Both branches are checked against values computed elsewhere — OIDC Core Appendix A.3's own published `at_hash`, and the reference implementation's Ed25519 vector | `ast-a05.4`, `ast-a05.12` |
| A1 | G2 | Has a claim released by claims resolution land on top of one the authorization server asserts, so the `sub` an RP treats as the user's identity comes out of a user record | Keyed by `ReleasableClaim`, which has no variant for a server-issued name — and the ID token builder re-checks every key against `ClaimName::SERVER_ISSUED` and refuses, rather than trusting that the map came from where it should have. The server's own claims are written *after* the released ones as well, so deleting the check would still not produce a token whose `sub` came from a record | `ast-a05.4`, `ast-1sk.4` |
| A1 | G1 | Registers an agent client and asks for authority beyond its policy | Per-tenant DCR policy engine; agent client profile pinning allowed grants, audiences and RAR types | `ast-m9c.6`, `ast-lh3.1` |
| A1 | G1, G3 | Floods login, consent, device or CIBA endpoints (credential stuffing, approval fatigue) | Failed sign-ins are counted in fixed windows in the database — shared by every replica, not one counter per process — per client address *and* per typed identifier: the account limit bounds stuffing one known account, the address limit bounds a sweep across many, and neither substitutes for the other. Past a limit the same login page comes back with the same words, a `429` and a `Retry-After`. The account bucket is the SHA-256 of the normalised identifier and is created whether the account exists or not, so a locked-out identifier and an invented one are one observable; the wrong-password message is already the wrong-username message, and the verifier equalises the timing with a decoy hash. A credential that verifies empties the account bucket and nothing else (`ast-b3u`), so the count is of wrong guesses since the last proof rather than of a quarter hour. Refusals are audited as `auth.throttled` and counted as `asterius_login_throttled_total`, labelled by which limit was full and never by whom. The device verification page carries its own budget (`ast-lh3.3`): five failed `user_code` submissions per address per ten minutes, counted in the same table, and a tenth failed confirmation against one authorization refuses that authorization outright so the device stops polling rather than waiting out an attack on it. `POST /bc-authorize` carries three limits of its own (`ast-5lw`): per address, per authenticated client, and — uniquely — per *person the hint resolved to*, because a backchannel request costs a third party a message and a decision rather than costing its caller; above any of them the answer is a `429` with `Retry-After`, in one shape, so a client cannot read "this hint named somebody real" off which bucket was full. A fourth ceiling is not a window at all: at most `ciba::MAX_PENDING_PER_USER` (five) requests may be waiting for one person at once, and the *new* request is refused rather than the oldest silently replaced. `/device_authorization` is still outside `LimitedEndpoint`; CIBA polls arrive at `/token`, which is in it, and are paced per request by `slow_down` and then refused (`ast-lh3.5`). The approvals inbox's decision form has a per-session budget of its own (`approvals::DECISIONS_PER_WINDOW`). The client-facing endpoints reuse the same limiter and the same table, counting *requests* rather than failures because their cost is in the work: `/register`, the RFC 7592 configuration endpoint, `/par`, `/token` and UserInfo each carry their own limit, sized to the traffic each legitimately sees, and each refusal is a `429` with `Retry-After`, `asterius_endpoint_throttled_total` and one `request.throttled` record per window | `ast-2vk.9`, `ast-p2l.3`, `ast-b3u` |
| A1a | G1, G2 | Operates a rogue AS and replays honest messages; serves malicious metadata or JWKS | Client keys come only from the source that client's own registration named — an inline `jwks` or its `jwks_uri`, never a `jku` or `x5u` in a token header (SP §5.4.2), and never a key the token brought with it; `iss`/`aud` are checked on every JWT | `ast-mxc.5`, `ast-mxc.4` |
| A1a | G1 | Replays a client assertion captured from an honest AS against Asterius | `private_key_jwt` audience is this tenant's issuer; single-use `jti` replay cache with the assertion's own lifetime | `ast-m9c.2`, `ast-mxc.4` |
| A2 | G1, G2, G3 | Reads or rewrites any message in flight; strips TLS | TLS 1.2/1.3 only, BCP 195 suites, HSTS with `preload` on every browser-facing response, RFC 9525 certificate checks, HTTP→HTTPS never downgraded (SP §5.2.1–5.2.3) | `ast-83p.4` |
| A2 | G3 | Uses a 307 redirect to make the browser replay a credential-bearing POST to the attacker's URL | A single `SeeOther` helper that can only emit 303 (SP §5.3.2.2 items 10–11); a source audit fails the build on any other redirect status, and on `StatusCode::SEE_OTHER` used outside the helper | `ast-83p.4` |
| A1 | G1, G3 | Reads an authorization request or a token response from a cross-origin script in a victim's browser | No CORS layer exists anywhere; a source audit fails the build if one is added, and the `cors` feature of tower-http is not enabled (SP §5.2.3) | `ast-83p.4` |
| A1 | G1, G2, G3 | Runs script on a login or consent page — through a reflected parameter, a themed asset, a compromised CDN — and reads the password out of the form or approves the grant on the user's behalf | Every document is served under `default-src 'none'` with `script-src 'nonce-…' 'strict-dynamic'` and no `'unsafe-inline'`, `'unsafe-eval'` or host source. The nonce is 128 bits from the OS CSPRNG, drawn once per request by the middleware (CSP Level 3 §7.1) and reaching the template only through a type the response cannot be built without, so a page rendered without one does not compile. RFC 9700 §4.16 asks for CSP on the authorization endpoint and every page used to authenticate the user; a workspace source audit fails the build on an unsafe keyword anywhere, and on `text/html` produced outside the one type that carries the policy | `ast-ndk.3` |
| A1 | G2, G3 | Frames the consent screen under an innocuous page and collects an approval the user never meant to give (RFC 9700 §4.16: "Authorization servers MUST prevent clickjacking attacks") | `frame-ancestors 'none'` in the policy and `X-Frame-Options: DENY` from the transport layer. Both, because §4.16 says the CSP technique "SHOULD be combined with others" for user agents that do not support CSP, and CSP Level 3 §6.4.2.2 makes the directive win wherever both are read. The §4.16 suggestion that operators be able to allow framing origins per client is declined: an embeddable consent screen is a clickjacking target for an embedding nobody has asked for | `ast-ndk.3` |
| A1 | G1, G3 | Reads `state`, a `request_uri` or an interaction id out of a `Referer`, or out of a third-party resource an interaction page fetched | RFC 9700 §4.2.4 word for word: `Referrer-Policy: no-referrer`, and a policy under which a third-party resource cannot be fetched at all — `default-src 'none'`, `img-src 'self' data:`, `font-src 'self'`, `connect-src 'self'`. `Cache-Control: no-store` on every page keeps the same values out of a shared cache and off the back button, which is RFC 9700 §4.3's leak arriving through the cache instead of the URL | `ast-ndk.3` |
| A1 | G1, G2 | Registers a `redirect_uri` whose origin carries a `;` or a newline, so that the `form_post` page's `form-action` gains a directive — or the response gains a header | The one attacker-supplied string that reaches a policy is parsed into `FormActionOrigin` first: `https://host[:port]` (or the RFC 8252 §7.3 loopback), lower case, no path, userinfo, query or wildcard, and nothing outside CSP's `host-char` grammar (CSP Level 3 §2.3.1). A fuzz target asserts over arbitrary input that an accepted origin renders into a policy with the same directive count, the same quote count and the same `'none'` directives as the policy without it | `ast-ndk.3`, `ast-gxh.5` |
| A1 | G1, G3 | Reads the authorization code out of the `response_mode=form_post` page, or makes that page post it somewhere else — an injected form, a widened `form-action`, a cached copy on a shared machine, or the `state` the client chose rendered as markup | The page is a document like every other: `Cache-Control: no-store` and the nonce policy come from the one middleware that writes them, and `form-action` names `'self'` plus exactly one origin — the one belonging to the `redirect_uri` this authorization was validated against at push time, never a parameter of the request being answered. Every response parameter reaches the markup as an escaped attribute value, and the auto-submit script interpolates nothing at all: it names one element by id and submits it, so a hostile `state` is data and can never be source text. A client whose callback origin CSP's `host-char` grammar cannot spell is refused `form_post` at the push, rather than served a page whose own submission its policy forbids. `fragment` is refused for the same reason it is not implemented: recovering a code from a fragment needs script in the client's page (RFC 9700 §2.1.2) | `ast-gxh.5`, `ast-ndk.3` |
| A1 | G3 | Mails a victim a `verification_uri_complete` for a device the attacker holds, so that one click authorises it — RFC 8628 §5.4's remote phishing, where the whole ceremony is the link being followed | The complete URI prefills the code and decides nothing: the page is reached with a session, the code is compared server-side, and a visitor who is not signed in is sent through the ordinary interaction pages first, which drops the prefill. It leads to a confirmation page that shows the `user_code` this server holds — not the string that was typed — and asks whether it matches the device in front of the user (§3.3.1), which is the step that cannot be performed by somebody who is not looking at the device. The page names the client, lists the scopes and rich authorization the device asked for, and says in words that a code somebody sent you is a code somebody else is waiting on (§5.3) — with the same caveat that a registered name is a hint rather than an identity; the answer is a POST under a session-bound synchroniser token, so the link cannot carry the decision either | `ast-lh3.3`, `ast-ndk.2` |
| A1 | G1, G2 | Polls the token endpoint with a `device_code` that is not theirs — guessed (RFC 8628 §5.2), read off a log, or taken from another client of the same tenant | The device authorization endpoint authenticates its client (FAPI 2.0 SP §5.3.2.1 item 3, a documented deviation from the public-client usage RFC 8628 §3.1 assumes), so every poll is made by a client that has proved a key. A device code is 256 bits, stored as a SHA-256 digest, and shape-checked before any query. The client that polls must be the client the code was issued to, and that is decided before the state is acted on — so another client cannot read the progress of a flow, spend it, or tell an unknown code from a pending one: all of them are `invalid_grant`. Redemption is one `update … where redeemed_at is null … returning`, so a code is spent once, and the access token is bound to the DPoP key or the certificate the redemption proved | `ast-lh3.3` |
| A1 | G1, G3 | Walks the `user_code` space — 20⁸ ≈ 34.5 bits, short by construction because a person has to type it (§6.1) — using the verification page as the oracle: "expired", "already used" and "no such code" are three different answers and each of them is progress | One message for every way a code can fail, and the same page either way (§5.1). A code that could not have been minted here is refused on its shape before any query, and it still spends an attempt, so a well-formed guess and a malformed one cost the same. Entropy alone is not the answer at 34.5 bits, so the budget is: five failed submissions per address per ten minutes, in the `rate_limits` table shared by every replica (`ast-2vk.9`), and ten failed confirmations against one authorization refuse that authorization — the device is told `access_denied` rather than left to time out. A limiter that cannot be read refuses rather than admits. The terminal page for an unauthorised device names no client and gives no reason, so a cancellation, an expiry and a code that was never issued are indistinguishable; the successful one names the client, which is only reachable by someone who had the code | `ast-lh3.3`, `ast-ndk.2` |
| A1 | G2 | Uses the password-reset form to test a list of addresses against a tenant — "no account for that address" turns a breach dump into a customer list (RFC 9700 §4 treats account discovery as an attack, not hygiene) | The confirmation is a page with no field that could differ: `PasswordResetSentPage` cannot carry the address, a name or a count, so the two cases are the same bytes rather than the same wording. Structural rather than conditional, because a conditional is a line somebody edits later; a test renders it and asserts the address never reaches the markup | `ast-ndk.2` |
| A1 | G1 | Reads a password-reset token out of a browser history entry, a bookmark or a `Referer` sent by the reset page itself | The token is a hidden field on the form, never a path segment of its action, so it is not in the URL the browser records. `Referrer-Policy: no-referrer` and its `<meta>` twin are the second half. It is not the synchroniser token and does not stand in for one: one says which account, the other says the submission came from this page | `ast-ndk.2` |
| A1 | G1 | Puts a newline into a redirect parameter to split the response and inject headers | The `Location` value is built through `HeaderValue`, which rejects CR, LF and NUL; a redirect that cannot be expressed is refused rather than emitted | `ast-83p.4` |
| A1, A2 | G1, G3 | Spoofs `X-Forwarded-For` to escape a rate limit, or to plant someone else's address in the audit trail | Forwarding headers are read only when the immediate peer is inside the configured trusted-proxy CIDRs, and the chain is walked from the right past our own hops; an empty trust list refuses the boot rather than silently merging every client | `ast-83p.4`, `ast-p2l.3` |
| A2 | G1, G2, G3 | Exhausts memory or connections with an unbounded body or header block | 64 KiB request body limit (413), bounded header block (431) and a 10 s request timeout (408) — all applied below the security-header layer, so a refusal is still a hardened response | `ast-83p.4` |
| A2 | G1 | Steals a bearer access token off the wire or from a log and replays it | Sender-constrained tokens only: DPoP proof-of-possession (`cnf.jkt`), or certificate binding under the `mtls` flag. A stolen token is useless without the private key | `ast-a05.6`, `ast-a05.7` |
| A2, A5 | G1 | Captures a DPoP proof in flight and replays it at the endpoint it was made for, inside its own validity window | Single use, enforced in one statement over shared storage: the `jti` is claimed through `ReplayGuard` with an `insert … on conflict do nothing`, namespaced by the key's RFC 7638 thumbprint, so two concurrent replays cannot both win and *n* replicas do not each accept one (RFC 9449 §11.1). The row is kept exactly as long as the proof's `iat` window, so the table is sized by traffic rather than by policy. An unavailable store is a refusal, never an acceptance | `ast-a05.6` |
| A2, A5 | G1 | Replays a captured proof at a *different* endpoint — a token-endpoint proof presented at UserInfo, or one tenant's presented at another's | `htm` and `htu` are compared against values this server derives, not values the request carries: the method from the router and the URL from the tenant's issuer plus the endpoint's own path. Both sides go through one normaliser implementing exactly RFC 9110 §4.2.3 (scheme and host case, default port, empty path, unreserved percent-escapes) and nothing more; userinfo is refused outright per RFC 9110 §4.2.4. Widening that function is the only way this control fails, which is why the fuzz target asserts the authority is never rewritten | `ast-a05.6` |
| A1 | G1, G4 | Pre-generates a year of DPoP proofs while holding the key — the "bank employee" case of RFC 9449 §11.2 — exfiltrates them, and uses them from a machine that has never held the private key | Server-issued nonces, when the `dpop_nonce` flag is on: the nonce is an HMAC over a server secret and a five-minute window, so a proof cannot be minted before the window it is used in exists. It is derived rather than stored, so requiring one costs no write on the authentication path; it is accepted for the current window and the one before it, so a client that fetches a nonce near a boundary retries once rather than looping. Without the flag, the `iat` window alone bounds pre-generation to five minutes | `ast-a05.6` |
| A2, A5 | G1, G2 | Presents a stolen DPoP-bound access token at UserInfo under the `Bearer` scheme, or with a proof captured from an earlier call to the same endpoint, and reads a person's claims | The `cnf` decides which scheme is acceptable, not the request: a token carrying `cnf.jkt` is answered only under the `DPoP` scheme, only with a proof whose thumbprint equals that `jkt`, and only when the proof's `ath` hashes the token that actually arrived (RFC 9449 §4.3 item 12, §7.1). A token carrying `cnf.x5t#S256` is the other case and is answered under `Bearer` only against the certificate the request arrived with (RFC 8705 §3, `ast-a05.7`); a token whose `cnf` names a key is never answered under `Bearer`, whatever certificate is on the connection, because that would turn a sender-constrained token into a bearer one | `ast-1sk.3`, `ast-a05.6`, `ast-a05.7` |
| A2 | G1, G2 | Puts the access token in the UserInfo URL — `?access_token=…` — so that it lands in the browser history, the `Referer` of the next request and every access log on the way | Refused before the credential is parsed, let alone verified (FAPI 2.0 SP §5.3.4, RFC 6750 §3.1's "uses more than one method"). The query string is examined first and a request naming `access_token` is a 400 whatever its headers say, so the refusal cannot be arranged away by also sending a good header. The fuzz target asserts over arbitrary input that no query carrying the parameter ever yields a presentation, and the endpoint's test asserts that no row was read | `ast-1sk.3` |
| A5 | G2 | Uses a still-valid access token after the grant behind it was withdrawn, or after consent was narrowed, and receives claims the person no longer agreed to release | UserInfo resolves claims through `claims::resolve_for_grant` and nothing else: the scopes, the `claims` request and the locales all come from the grant row, so "output ⊆ consented" is a property of the call rather than of the handler's discipline. The grant is re-read on every request and must be `Active`, the `jti` denylist is consulted (FAPI 2.0 SP §5.3.4 item 3), and `sub` is the grant's — pairwise as registered — rather than anything the token or the user row supplies. A token whose `sub` disagrees with its grant is refused rather than reconciled | `ast-1sk.3`, `ast-1sk.6` |
| A3a | G1 | Redeems a stolen authorization code with a DPoP key of their own, so the token is sender-constrained to the attacker | `dpop_jkt` pins the key at the pushed authorization request and the thumbprint of the proof at the token endpoint must equal it (RFC 9449 §10, FAPI 2.0 SP §5.3.2.1 item 12). A code pinned to a key is not redeemable without a proof for that key — including with no proof at all. Both spellings RFC 9449 §10.1 requires are accepted, and a request that uses both and disagrees is refused rather than resolved | `ast-a05.6`, `ast-a05.2` |
| A1, A2 | G1 | Publishes or leaks a private key by signing it into a DPoP proof's `jwk`, which every hop on the path can read | A `jwk` carrying `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth` or `k` is refused as a disclosure rather than skipped as unusable — the same rule, and the same list, that refuses a client JWK Set containing private material (RFC 9449 §4.2, §4.3 item 7) | `ast-a05.6`, `ast-m9c.2` |
| A1, A3a | G1, G3 | Pushes a signed request object (RFC 9101) whose parameters differ from the form around it, so that a server reading both honours the query values the signature exists to fix — the JAR half of the parameter-pollution family | The object replaces the form outright, which is RFC 9101 §6.1: what reaches `authorize::validate` is `request_object::parameters(claims)` and nothing from the body, except the parameters that authenticated the client. `client_id` is the one that is both, so it is reconciled rather than dropped — a form naming one client and an object signed by another is refused before either is honoured | `ast-gxh.9`, `ast-gxh.1` |
| A1 | G1, G3 | Sends an unsigned request object, one signed with `alg: none`, or one signed with an algorithm the client did not register — the classic JWT downgrade, aimed at the one place a client's own key decides what an authorization request says | No `none` exists to select: `SigningAlgorithm` cannot parse it (ADR-0003), so it is neither registrable nor acceptable. The accepted algorithm is the *single* value the client registered in `request_object_signing_alg`, not the deployment's allow-list, so a client that registered `EdDSA` cannot downgrade itself to another member of the list. `typ` must be `oauth-authz-req+jwt` (RFC 9101 §10.8, RFC 8725 §3.11), checked before any key is fetched, so an ID token or a DPoP proof is not presentable as a request object | `ast-gxh.9`, `ast-mxc.4` |
| A1, A5 | G1, G3 | Captures a request object and presents it later, at another tenant, or at another authorization server the same client talks to | `iss` must be the authenticated client, `aud` must be *this* tenant's issuer **as a string** — an array would be one object minted for several servers, replayable from one at another (OIDC Core §6.3 items 2–3) — and `exp` must be present and at most ten minutes ahead (RFC 9101 §10.2). The window is what bounds a captured object, since the object itself carries no server-issued value | `ast-gxh.9` |
| A1 | G1, G2 | Signs an authorization request whose `authorization_details`, `claims` or `resource` are shapes only a second parser would accept, on the bet that the JAR path is newer and laxer than the form path | There is no second parser. The claims are mapped to form values and handed to the one validator, so every limit of `ast-gxh.6`, `ast-gxh.7` and `ast-2vk.7` applies unchanged — a test asserts an invalid `authorization_details` gives byte-for-byte the same error in both spellings. A claim whose JSON has no form spelling is refused rather than rendered into one, because inventing a spelling is how the second parser gets written by accident. The fuzz target signs nothing: it starts from an arbitrary claims object, which is exactly what a client holding its own key controls | `ast-gxh.9`, `ast-gxh.6` |
| A1 | G1, G3 | Chains a `request_uri` this server issued into a new pushed request, or supplies one of its own for the server to dereference | RFC 9126 §3: `request_uri` in a pushed request is `invalid_request`, checked on the outer form before the object is unwrapped — otherwise the outer parameter would vanish from what the validator sees. `request_uri_parameter_supported` is `false` in every posture, so there is no by-reference path to fetch and no server-side request forgery reachable from an authorization request | `ast-gxh.9`, `ast-gxh.1` |
| A3a | G1, G3 | Reads the authorization request and learns `state`, `scope`, the PKCE challenge, or a leaked secret | PAR: the front-channel request carries only `client_id` and `request_uri`, so there is nothing in it to read. PKCE S256 means the challenge is not the verifier | `ast-gxh.1`, `ast-gxh.3` |
| A3a | G1 | Injects a stolen authorization code into an honest client's callback (code injection) | PKCE `S256` mandatory: `code_challenge_method` is compared to that literal and every other value — including the absent one RFC 7636 §4.3 defines as `plain` — is `invalid_request` (FAPI 2.0 SP §5.3.2.2 item 5). There is no method type with a second variant, so `plain` is not a setting that exists. Code bound to the PAR request, the client and the DPoP key; single use with revocation of the whole grant on replay; ≤ 60 s lifetime (SP §5.3.2.1 item 11) | `ast-gxh.3`, `ast-gxh.4`, `ast-a05.2` |
| A1 | G1 | PKCE downgrade (RFC 9700 §4.8): strips `code_challenge` from the request so the code is issued with no proof attached, then redeems it with any `code_verifier` | Not a check but a shape. `CodeChallenge` is the only way to carry a challenge and it is not an `Option`, so "a code issued without PKCE" is not a state the protocol crate can represent — §4.8.2's countermeasure has no flag left to guard | `ast-gxh.3` |
| A1, A2 | G1 | Recovers a `code_verifier` a character at a time by timing the rejection at the token endpoint, or reads part of one back out of an `error_description` | The comparison is `ct_eq` over the derived and the stored challenge. Neither `CodeChallenge` nor `CodeVerifier` implements `PartialEq` and the `S256` transformation is private, so the only way to relate a verifier to a challenge is the constant-time one. No rejection interpolates the verifier, and a malformed verifier and a wrong one are both `invalid_grant` — so the response does not say which | `ast-gxh.3`, `ast-mxc.6` |
| A1 | G1 | Presents a `code_verifier` outside RFC 7636 §4.1's production — an unbounded one, or bytes that are not the ASCII the clause names — to reach SHA-256 with something the specification does not describe | The 43–128 unreserved production is enforced before the value is hashed, so nothing outside it is ever digested and an unbounded verifier is not work an unauthenticated caller can ask for | `ast-gxh.3` |
| A1 | G1 | Pushes a `code_challenge` that is 43 characters but is not the encoding of a digest, so the code it starts can never be redeemed and the failure surfaces at the token endpoint as if the client's verifier were wrong | The challenge is decoded at PAR and must be exactly 32 bytes, unused trailing bits included. RFC 7636 §4.2's `43*128unreserved` describes a `plain` challenge; an `S256` one is always the base64url of a SHA-256 digest | `ast-gxh.3` |
| A1 | — | Two relying parties compare the `sub` values they hold and discover that they describe one person (OIDC Core §8's "without permission") | Pairwise subjects: `sub = BASE64URL(SHA-256(domain ‖ len‖sector ‖ len‖user_id ‖ salt))`. The concatenation is length-prefixed rather than the plain one OIDC Core §8.1 gives as an example, so "distinct Sector Identifier values MUST result in distinct Subject Identifier values" holds by injectivity of the encoding rather than by luck | `ast-2vk.6` |
| A1, A2 | G2 | Recovers the local account id from a `sub` read out of a token, or confirms a guessed one | The derivation is one-way over a per-tenant 256-bit secret salt and a random UUID. The salt is a `Secret` — redacted in `Debug`, zeroed on drop, no `PartialEq` — and a `sub` is 43 characters of digest carrying none of its inputs (OIDC Core §8.1: "MUST NOT be reversible by any party other than the OpenID Provider") | `ast-2vk.6` |
| A1, A2 | G2 | Reads a tenant's pairwise salt out of a database dump or a replica, then re-derives or confirms every `sub` in the tenant | The salt is key material, not configuration: sealed under the `Kek` port into `tenant_pairwise_salts.salt_ciphertext`, with the tenant bound in as AEAD additional authenticated data, so a row copied into another tenant is undecryptable rather than useful. It is generated once at tenant creation, in the same transaction as the tenant row, and no code path can supply one — `PairwiseSalt::derive_subject` takes the salt as its receiver and `PgUserRepository::subject` reads it from the store, so a caller cannot pass the wrong salt or an empty one. A tenant with no salt refuses to mint rather than defaulting | `ast-2vk.11`, `ast-mxc.3` |
| A1 | G1, G2 | Writes a `sub`, `aud`, `acr` or `cnf` claim into a user record — through an admin API, a bulk import or a hand-edited row — and has it projected into an ID Token | The claim bag cannot express them. `ClaimName::parse` refuses every claim the authorization server issues and every claim the `users` row already holds in a column, and the JSONB bag is put back through the same parser on the way out, so a row edited during an incident fails to load rather than reaching a token | `ast-2vk.6`, `ast-1sk.4`, `ast-83p.3` |
| A1 | G2 | Puts a right-to-left override in a claim name, so the consent screen reads as another organisation's while the markup is innocuous | Control, whitespace and bidirectional formatting characters are refused in a claim name, for the same reason they are refused in `client_name`. A suffix after `#` that is not a BCP 47 language tag is an error rather than a name silently read as tagged (OIDC Core §5.2) | `ast-2vk.6`, `ast-m9c.1` |
| A1 | G1, G2 | Two users end up sharing one `sub`, so one person's tokens resolve to the other | `subject_identifiers` is unique on `(tenant_id, subject)`, so the second write is refused rather than noticed later. The identifier is derived once and then read back, which is also what stops a `sub` already handed to a relying party from depending on the salt still being the one it was derived under | `ast-2vk.6`, `ast-83p.3` |
| A1 | G1, G2 | Has an account deleted and recreated — a restore from backup, an import that preserves ids, an operator retrying a provisioning run — so that a `sub` a relying party still holds is issued to somebody else, and that party's records for the old person become the new one's | `subject_identifiers` cascades from `users`, so the reservation goes with the account; `retired_subject_identifiers` is the tombstone that does not. It has no foreign key at all — not to `users`, whose cascade is the problem, and not to `tenants`, since deleting and recreating a tenant recreates the issuer — refuses `UPDATE` and `DELETE` in a trigger, and is `Kept` by the retention policy, a tombstone with an expiry being a `sub` that comes back. It stores the emitted value and not the inputs, so nothing about the deleted person is retained. A derivation that lands on a retired value is refused and never regenerated (OIDC Core §8 "never reassigned"; §8.1 makes the pairwise calculation deterministic, so there is no second value to offer), both in `PgUserRepository::subject`, which records a `subject.collision` audit event, and in the schema, where a trigger refuses the reservation whatever wrote it | `ast-2vk.12` |
| A4 | G1 | Substitutes the token endpoint and reads or rewrites the token exchange | Token endpoint is published in signed, TLS-served tenant metadata; clients authenticate with `private_key_jwt`/mTLS, so a substituted endpoint cannot mint a valid token; tokens are audience-bound | `ast-o0t.1`, `ast-m9c.2`, `ast-a05.3` |
| A5 | G1 | Reads resource requests at the RS (TLS-intercepting proxy) and replays the access token | DPoP binding makes a captured token unusable; the resource indicator (`resource`) narrows `aud` so a token for RS-A is rejected by RS-B | `ast-a05.6`, `ast-gxh.7`, `ast-a05.3` |
| A5 | G1 | Is issued an access token bound to nothing, so a copy read out of a proxy log, an RS access log or a crash dump is usable by whoever finds it | `cnf` is not a field a call site can forget: `AccessToken::new` takes a `Confirmation` by value, and `Confirmation` has no `Default`, no empty constructor and no variant that carries neither a `jkt` (RFC 9449 §6.1) nor an `x5t#S256` (RFC 8705 §3.1). "An access token with no `cnf`" is a call that does not compile rather than a token something rejects, which is FAPI 2.0 SP §5.3.2.1 item 4 enforced by the type system. Both members are held to the 43-character base64url shape a SHA-256 digest has, because a truncated or hex-spelled thumbprint is a binding no resource server ever matches — a bearer token wearing a `cnf` | `ast-a05.3`, `ast-a05.6`, `ast-a05.7` |
| A1 | G1 | Obtains an access token whose `aud` is its own `client_id`, or a resource identifier that no resource server can compare against, so that every RS has to decide for itself whether the token was meant for it | `Audience` is non-empty by construction and admits only absolute URIs without a fragment (RFC 8707 §2); the builder refuses an audience naming the client the token was issued to. RFC 9068 §5: "To prevent cross-JWT confusion, authorization servers MUST use a distinct identifier as an `aud` claim value to uniquely identify access tokens issued by the same issuer for distinct resources." An access token audienced at its client is also an ID token's audience, which is the confusion the mandatory `at+jwt` type (§2.1) exists to prevent — refused twice | `ast-a05.3`, `ast-gxh.7` |
| A1 | G1 | Redeems a code on a grant that named no resource, and is issued a token audienced at whatever the deployment happens to fall back to — the issuer, the client, or an empty set — so a token minted for one purpose is accepted by every resource server that trusts this issuer | RFC 9068 §3's default resource indicator is a per-tenant column an operator sets, checked three times over: by the config parser, which names the key to fix; by the schema, whose `default_resource` check admits only `https` without a fragment; and by `Audience::new` at issuance. Per tenant and not per deployment, because `aud` is what a resource server compares to decide a token was meant for it, and two tenants sharing one identifier would leave it nothing to tell them apart by but `iss`. A tenant whose default is unusable refuses to issue rather than falling back to something broader. Since `ast-gxh.7` the default is also filtered through the resource-server registry, and a client with an allow-list of its own defaults to that instead — the narrowest audience available, never a wider one | `ast-a05.2`, `ast-a05.3`, `ast-gxh.7` |
| A1 | G1 | Names a `resource` of its own choosing — an API this deployment does not front, a URI with a fragment, a relative one — and is issued a token whose `aud` a resource server it was never meant for may still match | RFC 8707 §3's "the authorization server MUST validate the resource parameter" is two gates, and a value must pass both: the client's own allow-list (`clients.resources`, which is *who may ask*) and the per-tenant registry `resource_servers` (which is *what exists*). One parser turns the bytes into a `ResourceIdentifier` — absolute, host-bearing, fragment-free, length-bounded, kept byte for byte because §2's comparison is a simple string comparison — and it is the same parser at the pushed authorization request endpoint and at the token endpoint, so the two cannot develop different opinions about one value. Every refusal is one `invalid_target` with one description, so a client cannot enumerate a tenant's resource servers a token request at a time | `ast-gxh.7`, `ast-m9c.6` |
| A1, A3a | G1 | Redeems a code, or refreshes, naming a `resource` the authorization request never asked for — so a token authorized for one API is minted for another, after the person consented to the first | RFC 8707 §2.2: "the requested resources MUST be a subset of the resources authorized". The authorization request's resources are stored with the pushed request and copied onto the grant at consent, and the token endpoint compares against *that* set rather than against the client's allow-list — a client allowed two APIs and authorized for one cannot reach the second. A request naming none is audienced at the authorized set, never widened | `ast-gxh.7`, `ast-gxh.1` |
| A1 | G1 | Obtains a token with no audience at all, by naming no `resource` under a client and tenant that have no default — a token every non-conforming resource server accepts | There is no audience-less path: `ResourceRegistry::targets` returns `invalid_target` for an empty result and `Audience` is non-empty by construction. The default audience is the client's own allow-list when it has one and the tenant's `default_resource` otherwise, and either is filtered through the registry — a resource server an operator withdraws stops being a default audience rather than quietly continuing to receive tokens | `ast-gxh.7`, `ast-a05.3` |
| A1 | G1 | Asks for two resources at once and receives one token carrying, at each of them, the authority the *other* one granted | Several `resource` values are allowed (RFC 8707 §2) and produce one token with an `aud` array — the documented policy choice — but the `scope` claim is then the scopes **every** named resource server understands, so widening the audience never widens the authority. The grant remains the ceiling: a resource server's scope list can only narrow | `ast-gxh.7`, `ast-a05.3` |
| A1 | G1, G3 | Pushes an `authorization_details` (RFC 9396) that is enormous, deeply nested, or names a `type` nobody defined — so the AS spends a tree walk per element, stores an authorization it cannot describe, and shows a person a JSON blob to agree to | Limits come before meaning: at most 8 KiB of input (checked on the bytes, before serde), 16 elements and 8 levels of nesting, all applied before any schema is consulted. Then the shape RFC 9396 §2 requires — an array of objects, each with a string `type`, `locations` an array of strings when present — then three gates a value must pass all of: the client's §9.2 `authorization_details_types` (an empty registration means *none*, never *all*), the per-tenant `authorization_details_types` registry, and that type's schema. Every refusal is one `invalid_authorization_details` with one description, so a client cannot enumerate a tenant's types a push at a time | `ast-gxh.6`, `ast-gxh.1` |
| A1 | G3 | Composes an `authorization_details` element whose members are chosen to read as a sentence, and has the consent page render it — asking a person to agree to text the attacker wrote | The element's JSON never reaches the page. What is rendered is the *operator's* sentence for the type, from the tenant's registry, plus the three RFC 9396 §2.2 fields with an agreed meaning (`locations`, `actions`, `datatypes`) — each of them escaped by Askama's autoescape, and each pinned in the `en` and `fr` consent goldens with hostile input. A type registered without a sentence is shown as undescribed rather than falling back to the document, which is deliberately ugly: an unexplained authorization should look unexplained (RFC 9396 §12) | `ast-gxh.6`, `ast-ndk.1` |
| A1 | G1 | Names in RFC 9396 §2.2 `locations` a resource server the client may not reach, so a rich authorization is recorded — and shown to the user — for an API this client could never be issued a token for | `locations` is held to the intersection of the client's RFC 8707 allow-list and the tenant's `resource_servers` registry, which is the same authority `resource` passes (`ResourceRegistry`, not a second notion of what a resource is). A location outside it is `invalid_authorization_details` at the push, where the client is still on the connection to be told | `ast-gxh.6`, `ast-gxh.7` |
| A1 | G1, G4 | Registers a per-tenant JSON Schema that this server silently fails to understand — a `pattern`, a `$ref` to a URL it will fetch — so every element the schema was written to refuse is admitted, or the AS is turned into a request-forgery primitive | The validator is a deliberate subset written in `asterius-domain` (`type`, `required`, `properties`, `additionalProperties`, `enum`, `maxLength`, `items`, `maxItems`) and not a dependency: nothing resolves a `$ref`, because the centre of the hexagon may not reach a network. A keyword outside the subset is refused **at registration**, not ignored at validation, and a stored schema that cannot be parsed fails the read rather than being replaced by an empty one — an unparseable schema read as `{}` would admit everything | `ast-gxh.6` |
| A1, A3a | G2 | Registers a passkey against a page that only resembles the tenant's, or replays a captured `webauthn.get` response into a registration, so a credential the user meant for one purpose is bound to another | WebAuthn L3 §7.1 is implemented step by step (ADR-0007): `type` must be `webauthn.create`, so an assertion cannot register; the challenge is compared in constant time against one this server issued; the origin is compared byte-exactly against a list somebody wrote down, with no parsing or normalisation for a hostile spelling to exploit, and a cross-origin ceremony is refused outright rather than reconciled against `topOrigin`. The RP ID is checked separately from the origin, because a browser will let any subdomain use a credential scoped to the registrable suffix and §7.1 step 9 is where a relying party declines to | `ast-2vk.3` |
| A1 | G2 | Presents an attestation statement in a format nobody verifies, or a credential public key whose type and algorithm disagree, so a structure assembled by hand is stored as a credential | Only `none` attestation is accepted, and §8.7 defines its statement as empty — a `none` object carrying anything is refused rather than ignored, and every format with a signature in it is refused because verifying one needs a root store this deployment does not have (ADR-0007). A `COSE_Key` whose `kty` and `alg` disagree is refused, as is a coordinate of the wrong length: a short coordinate is a different point once left-padded, so accepting it would let one key have several spellings. All four parsers have fuzz targets | `ast-2vk.3` |
| A1, A3a | G2 | Replays a registration ceremony captured from another tab, another session or an earlier attempt, so a credential is bound to an account that never ran the ceremony | The challenge is a row, not a signed blob, because single use is something a row can be. It lives in `passkey_enrolments`, keyed by the session's lookup digest with a foreign key onto `sessions`: it cannot be moved to another session, and signing out deletes it by cascade. `spend_challenge` is one `update ... from` that returns the previous value and nulls it, so two finishes racing on one challenge cannot both come back with bytes; the loser's update matches no row. It is spent before the ceremony is parsed, so a ceremony that fails does not leave its challenge outstanding for a second try. Thirty-two bytes from the CSPRNG, and at most five minutes (`ENROLMENT_TTL`), swept by `POLICY` rather than left to the session's own hours | `ast-2vk.15`, `ast-2vk.3` |
| A1 | G2, G3 | Posts to `/passkeys/options` or `/passkeys/finish` from another site, riding the session cookie, to burn a victim's outstanding challenge or enrol an attacker-held authenticator against their account | Neither endpoint is a form, so neither can be reached by one: both read a synchroniser token from a JSON body, and the digest of that token is stored against the session when the page is rendered. The token is checked *before* the challenge is spent, so a forged request cannot destroy a ceremony it cannot complete; `SameSite=Lax` on the session cookie is the second half rather than the first | `ast-2vk.15`, `ast-2vk.1` |
| A1 | G2 | Registers a credential id already held by another account in the tenant, either to collide with it or to learn that it exists | Uniqueness is the `credentials_by_passkey_id` index over `(tenant_id, passkey_credential_id)`, not a read followed by a write — a check with a gap in it is a check two concurrent ceremonies both pass. The conflict comes back as the same refusal as every other failure: one status, one error code, no reason. Distinguishing "already registered" from "the origin was wrong" would answer a question about somebody else's account | `ast-2vk.15`, `ast-2vk.3` |
| A1 | G2 | Adds a passkey to an account that has been disabled or locked, or to a session that has expired, idled out or been revoked, so a credential outlives the decision that stopped the account being used | Enrolment resolves the session cookie through `SessionRepository::find` and requires `SessionStatus::is_usable`, then reads the account and requires `UserStatus::Active`. All four refusals are the one answer the page gives an unauthenticated visitor, and none of them opens an enrolment row | `ast-2vk.15`, `ast-2vk.2` |
| A1, A3a | G1, G2 | Replays a captured `webauthn.get` assertion — from a proxy, a log or another tab — to sign in as its owner | The challenge is a row again, and a different one: authentication has no session to hang it on, so it lives in `auth_requests.passkey_challenge`, bound to the interaction the browser already holds a credential for. `spend_assertion_challenge` is one `update … from … returning previous` that reads it and nulls it, spent *before* the assertion is parsed, so a replay finds nothing outstanding however fast it arrives. Thirty-two bytes, five minutes (`ASSERTION_TTL`), and the interaction's own expiry on top of that | `ast-2vk.4` |
| A1 | G1, G2 | Presents an assertion produced by a **cloned** authenticator — a credential copied off a device, used elsewhere, and now behind the copy it was taken from | WebAuthn L3 §7.2 step 21 is read rather than merely stored. `assertion::verify` compares the counter in the signed authenticator data against `credentials.passkey_sign_count` *after* the signature has verified, so the comparison is only ever made about a genuinely signed ceremony. A counter that did not advance, with either side non-zero, blocks the credential (`disabled_at`) and writes an `auth.failed` event carrying both counters; the browser is told the same nothing every other failure gets. §6.1.1's legitimate case — an authenticator that reports zero for ever, which is most synchronised passkeys — is exempted exactly as the specification exempts it: both sides zero, and nothing is inferred | `ast-2vk.4` |
| A5 | G4 | Probes `/interaction/{id}/passkey/finish` with guessed or harvested credential ids to learn which exist, which are disabled, and which belong to a live account | One refusal for all of it, byte for byte: an unknown credential id, a blocked credential, an assertion for another relying party, a user handle naming another account, a signature that does not verify and a disabled account produce the same 400 and the same body, with only a correlation id to distinguish them in the log. No username is sent in either direction — `allowCredentials` is omitted, so the options answer describes no account at all — which is what removes the oracle rather than equalising it | `ast-2vk.4`, `ast-2vk.9` |
| A1 | G1, G3 | Posts to `/interaction/{id}/passkey/options` or `/finish` from another site, or with an interaction id belonging to somebody else's flow, to sign a victim's browser into an authorization they did not start | Both endpoints resume the interaction the way the pages do: the id in the path and the id in the `__Host-` interaction cookie must both be present and equal, and a disagreement destroys the interaction for both parties (FAPI 2.0 SP §6.5). On top of that each reads the synchroniser token of the rendered login page from its JSON body, so neither can be reached by a form; the token is checked before the challenge is spent | `ast-2vk.4`, `ast-2vk.1` |
| A5 | G1 | Uses a long-lived token after the user's access should have ended | Every credential records the grant it was minted under, and the only way to obtain the authority to mint one is `Grant::claim`, which reads a live grant — so "a token with no grant" and "a token minted from a revoked grant" are not states a caller can express. Revoking a grant marks its refresh tokens revoked and denylists its still-live access tokens until their own `exp` (FAPI 2.0 SP §6.8 item 4, credential linking). Short access-token lifetimes and CAEP `session-revoked` close the remaining window | `ast-uwv.2`, `ast-1sk.2`, `ast-0ju.8` |
| A1, A2 | G1 | Steals a refresh token — from a log, a backup, a compromised client host — and presents it at the token endpoint. It is the credential worth stealing: no user is present, no browser is involved, and it lives for weeks | Two things must be true, not one, and a tenant may ask for a third. The client authenticates (RFC 6749 §6) and the request carries a DPoP proof (FAPI 2.0 SP §5.3.2.1), so a token taken without the client's credentials is worth nothing. The third — the tenant's `bind_to_dpop_key`, requiring that proof to be for the key the token was *issued* to — is off by default, because RFC 9449 §5 binds a refresh token to the proof key for public clients and says one issued to a confidential client is not so bound, client authentication having already sender-constrained it; every client here is confidential. A tenant that turns it on also stops any client from rolling its DPoP key (`ast-1h1`). The value itself is never stored: `refresh_tokens.token_hash` is the SHA-256, so the database is a list of digests | `ast-a05.5` |
| A1, A5 | G1 | Uses a refresh token long after the authorization stopped being one anybody would recognise — an integration nobody remembers, a person who has left | Two deadlines that behave differently, in two columns. The absolute one is fixed at issuance and cannot be extended by using the token, so a stolen token dies on a clock the thief cannot touch. The idle one is pushed out by every successful refresh and answers a different question: whether the integration is still in use. Collapsing them into one column would mean whichever rule wrote last is the rule that applies. Every refresh, successful or refused, is an audit event, which is what makes a forgotten integration visible at all | `ast-a05.5`, `ast-p2l.4` |
| A1 | G1, G3 | Widens a refresh: presents a token narrowed to `openid` and asks for `payments` back, with no user anywhere near the request to notice | RFC 6749 §6's subset rule, compared against what *this token* was issued for rather than against the grant — so a narrowing is permanent for the token that took it, and cannot be undone by the next refresh. A widening request fails whole with `invalid_scope` rather than being trimmed, because a client handed a token narrower than it asked for will act as if it holds the broader one. The tokens are minted from a narrowed copy of the grant, so the `scope` claim a resource server reads cannot disagree with what was granted. Fuzzed as a containment property over arbitrary sets: whatever comes back is a subset of what went in | `ast-a05.5` |
| A1, A5 | G1, G4 | Causes a revocation to fail half-way — a failed statement, a dropped connection — so the refresh token is revoked, the access token is not, and the user is told the application's access has ended while it keeps working until `exp` | The cascade is one transaction: it takes the grant's row with `select … for update`, revokes the refresh tokens, denylists the access tokens, and stamps the grant last. Any failure rolls all of it back, and the caller is given an error rather than a success. A database test arms a trigger that makes the denylist insert fail and reads all three tables back | `ast-uwv.2` |
| A1, A5 | G1, G4 | Waits out the unclaimed-grant timeout on an ordinary code-flow login that issued no refresh token, so garbage collection deletes the grant while its access token is still live and the token becomes unrevocable | `grants.claimed_at` is stamped by `PgGrantRepository::claim`, which is the only way to obtain the authority to mint any credential, and it is stamped *before* the credential exists — so no live credential has a grant reading unclaimed. The sweep's whole predicate is `claimed_at is null`, replacing a derivation over refresh tokens and consumed authorization codes that could not see a bare access token: a stateless JWT (RFC 9068) that nothing records, whose ≤60 s code (FAPI 2.0 SP §5.3.2.1 item 11) is already purged | `ast-uwv.7`, `ast-uwv.2` |
| A1 | G1, G4 | Edits a `grants` row during an incident — a scope with a space in it, an `authorization_details` that is a string, a revocation stamp with no reason — and has it copied into an access token | A row is validated by the same code on the way out as the values were on the way in. RFC 6749 §3.3's scope grammar is what stops one stored scope becoming two at the resource server once the `scope` claim is split; a resource must be an absolute URI without a fragment (RFC 8707 §2); the `jsonb` columns must hold the shapes their specifications name; and a half-written revocation fails to load rather than reading as "not revoked" | `ast-uwv.2`, `ast-83p.3` |
| A1 | G1, G2 | Sends a `claims` request parameter naming `sub`, `aud`, `cnf`, `sid` or `acr`, so that a claim the authorization server computes is overwritten by one the client chose — an RP that trusts `sub` as the user's identity would then be told about somebody else | Not filtered: unrepresentable. Resolution is keyed by `ReleasableClaim`, which has exactly two variants — a `ClaimName`, whose parser refuses every name in `ClaimName::SERVER_ISSUED`, and the three column-backed claims of `User` matched by exact spelling. There is no key for `sub`, so a `claims` member naming one is a value that never becomes a key, on every path: the scope table, the `claims` parameter and the language fallback all write through the same type. A unit test walks the reserved list itself rather than a copy, including its language-tagged spellings, and the `claims_request` fuzz target re-checks it over arbitrary JSON | `ast-1sk.4`, `ast-2vk.6` |
| A1 | G1 | Pushes a `claims` parameter that is enormous or deeply nested — a JSON document whose size, shape and nesting the client chose, stored on the pushed request, stored again on the grant, and read on every issuance for the life of that grant | Bounded before it is believed: 4 KiB of text, 64 members per section, six levels of nesting. The parse itself is kept off the stack by `serde_json`'s own recursion limit rather than by the depth check, which runs afterwards and bounds what is *stored*. Wrong shapes are refused rather than dropped — a client whose parameter was silently ignored would walk away believing it has an authorization it does not | `ast-1sk.4` |
| A1 | G2 | Marks every claim `essential: true` to compel release of claims the user did not agree to | `essential` is recorded and carried to the consent screen, and changes nothing about what is released. OIDC Core §5.5.1: the authorization server "MUST NOT generate an error when Claims are not returned, whether they are Essential or Voluntary" — so `claims::resolve` has no error to return, and an unavailable claim is absent rather than `null` (§5.3.2). What bounds release is the grant: `resolve` takes the *grant's* scopes and claims request, not the authorization request's | `ast-1sk.4`, `ast-uwv.3` |
| A1 | G2 | Asks for `birthdate` with `"value": "1970-01-01"` and learns the answer from whether the member comes back — a claims response used as an oracle | `value` and `values` are parsed and carried but applied to nothing. They are honoured for `acr` alone (OIDC Core §5.5.1.1), where the value is one the authorization server asserts about the authentication rather than a fact about the person, so there is nothing to probe | `ast-1sk.4` |
| A1, A5 | G2 | Obtains a claim from an ID token rather than from UserInfo, because an ID token travels further: through the browser, into a client's session store, into a log line pasted onto a ticket | Placement is a rule, not a default. OIDC Core §5.4 returns scope-derived claims from UserInfo whenever an access token is issued, and `code` is the only `response_type` this server implements (ADR-0002) — so the exception never arises and **no scope ever puts a claim in an ID token**. A claim reaches one only when the client named it under the `claims` parameter's `id_token` member, which is the client choosing that trade for its own users. Reading it at UserInfo needs the sender-constrained access token, and so the client's key rather than a copy of a string | `ast-1sk.4`, `ast-1sk.3`, `ast-a05.4` |
| A1 | G2 | Redefines what a standard scope means for one tenant — `email` carrying a national identifier, `profile` widened — and produces ID tokens that lie to every RP that trusts the OIDC Core §5.4 meaning | The scope-to-claim table is `const` in `asterius-oidc::claims` with no tenant override, so changing it is a code change somebody reviews and a test reads against §5.4 name by name. A tenant that wants to release something else uses its own scope or the `claims` parameter, both of which are spelled differently and so cannot be mistaken for the standard ones. An unknown scope releases no claims rather than failing, which is what keeps a deployment scope such as `payments` from breaking UserInfo | `ast-1sk.4` |
| A1, A2 | G1 | Reads a secret out of a log line, a panic message or a `Debug` dump of the configuration | `Secret<T>` prints `[REDACTED]` from both `Debug` and `Display`, has no `Deref` or `Serialize`, and zeroes on drop; exposing it requires a greppable `expose()` call | `ast-83p.2`, `ast-mxc.6` |
| A1, A2 | G1 | Reads a credential out of a log line, a `Debug` dump or an error message — including one embedded in surrounding prose | Redaction is a `tracing` field formatter, not a call-site rule: every field of every event is scanned, whole values *and* credential-shaped runs inside larger strings; fields named like secrets are redacted regardless of shape, and subjects are hashed so lines stay correlatable | `ast-83p.5` |
| A1, A2 | G1 | Reads a live credential out of the audit trail — the one artefact kept for years and copied into a SIEM | Detail values are typed: a credential can only be recorded as a SHA-256 fingerprint, and free text is scanned for JWT, `Bearer`/`DPoP`, PEM and ≥128-bit opaque shapes and replaced before insert | `ast-83p.11` |
| A1 | G1, G2, G3 | Edits or deletes an audit record to hide what was done | `audit_events` refuses `UPDATE` unconditionally and `DELETE` except for the retention job, which must announce itself for the transaction; each record hashes its predecessor with its own length-prefixed canonical encoding, so an edit or a deletion is detected and located | `ast-83p.11` |
| A1, A2 | G1, G2 | Runs the server with a key-encryption key it cannot decrypt with — a swapped mount, a stale secret — and discovers it only when a token fails | The KEK has no default and its absence refuses the boot; the server decrypts the tenant's active signing key at startup, so a wrong KEK is a boot failure naming both key ids rather than a runtime one | `ast-mxc.7` |
| A1, A2 | G1 | Reads credentials out of the database after a backup or replica leak | Opaque credentials (codes, refresh tokens, device codes, `auth_req_id`, registration tokens) stored only as SHA-256 digests; passwords as Argon2id; private keys encrypted at rest | `ast-83p.3`, `ast-mxc.3` |
| A1, A2 | G1 | Guesses a credential — an authorization code, refresh token, device code or registration access token | `OpaqueToken` draws from the OS CSPRNG only, defaults to 256 bits and will not compile below the 128-bit floor (SP §5.4.1 item 4, RFC 6749 §10.10); rendered as unpadded `base64url` so no transport can mangle it; stored only as `sha256_hex` of itself | `ast-mxc.6` |
| A1, A2 | G1 | Recovers a credential a character at a time by timing the comparison that rejects it | Every comparison of a code, token, PKCE verifier or CSRF token goes through `ct_eq` (`subtle`). `Secret` and `OpaqueToken` do not implement `PartialEq`, so `==` on them is a compile error rather than a review finding; a workspace source audit fails the build if an exposed secret is compared with an operator instead | `ast-mxc.6` |
| A1 | G1, G2 | Downgrades signing to `none`, to HMAC with a public key, or to any algorithm the profile excludes | `SigningAlgorithm` is a closed enum with three variants, so `none` and `HS256` are not values that exist. Verification uses the *key's* algorithm and requires the header to agree (RFC 8725 §3.1–3.2); a header naming anything else is refused before a key is fetched | `ast-mxc.1`, ADR-0003, ADR-0004 |
| A1 | G1, G2 | Mints a client assertion or request object dated for later, or replays one whose clock window never closes | One verifier for every JWT the server accepts: `iat`/`nbf` up to 10s ahead are accepted and beyond 60s refused (FAPI 2.0 SP §5.3.2.1 item 13, clamped so configuration cannot widen it), `exp` has no leeway, and a token over 8 KiB is refused before it is parsed | `ast-mxc.4` |
| A1 | G1 | Publishes two keys under one `kid` so a verifier picks the wrong one | Candidates are filtered by algorithm and then each is tried (FAPI 2.0 SP §5.4.3); the resolver supplies the trusted set and the token's `kid` only narrows it — it is never a pointer the verifier follows | `ast-mxc.4` |
| A1 | G1 | Substitutes a token minted for one purpose where another is expected | Every issued JWT carries an explicit `typ` (RFC 8725 §3.11) and verification requires the expected one; `crit` headers are refused outright, since we understand none of them | `ast-mxc.1` |
| A1, A2 | G1, G2 | Reads a signing key out of a database dump, a backup or a read replica, and mints tokens for any subject of that tenant | The private half is stored only as AES-256-GCM ciphertext under a key-encryption key held outside the database, reached through a `Kek` port so a KMS or HSM can hold it (`LocalKek` is the file/environment implementation for development). A test reads the row and asserts the bytes are neither a JWK nor a PKCS#8 encoding of anything, and that no 16-byte run of the key appears in them | `ast-mxc.3` |
| A1 | G1, G2 | Keeps using a signing key that leaked months ago, because nothing ever rotates it | Per-tenant automated rotation with a stored schedule, created with defaults on first use rather than only when someone configures it (FAPI 2.0 SP §6.8 item 1). A key is published before it signs and stays published for a grace period after, per OIDC Core §10.1.1, so rotating is not an outage and there is no reason to postpone it | `ast-mxc.3` |
| A1, A2 | G1, G2 | Holds a copy of a signing key that leaked — from a stolen backup, a mis-set file mode, a screenshot of a `psql` session — and keeps minting tokens with it after the key was taken out of service, because retiring a key leaves its encrypted private half in the table for anyone who gets the database again | `POST /keys/{kid}/purge` (`ast-7rq`): the ciphertext, nonce and `kek_id` columns are emptied in place, the key moves to the terminal `purged` state, it leaves the JWK Set at once, and the key store stops resolving its `kid` — so this server also stops *accepting* its signatures, which is the one difference from `retired`. The reason is required by the type and lands in a `key.purged` audit record; the row itself stays, so the `kid` is never reused and a review can see the key existed. The active key is refused with a 409: the compromise path is a rotation with immediate activation, then a purge | `ast-7rq`, `ast-mxc.3` |
| A1 | G1, G2 | Obtains a decryption oracle for a key that also signs — or the reverse — and turns one into a forgery | One key, one purpose (FAPI 2.0 SP §6.8 item 2). The `purpose` column, a check that the published JWK's `use` member agrees with it, and a unique index over the key material itself; a P-256 or RSA pair is usable for both operations, so nothing about the key type would have prevented it. Every signing query filters on the purpose | `ast-mxc.3` |
| A1 | G1, G2 | Edits a `signing_keys` row — moves it to another tenant, relabels its purpose, pairs a ciphertext with a different public key — so a key signs for somebody it does not belong to | The ciphertext is bound to the tenant, `kid`, purpose and algorithm of its row as AEAD additional authenticated data, in a length-prefixed encoding where two bindings cannot collide. A moved or relabelled row stops decrypting rather than becoming a working key in the wrong place | `ast-mxc.3` |
| A2 | G1, G2 | Recovers a key-encryption key, or forges ciphertext, from two records sealed under one AES-GCM nonce | Nonces are drawn by the provider inside the sealing call — the API has no parameter to supply one — as the 96-bit RBG construction of NIST SP 800-38D §8.2.2, and a unique index on `(kek_id, private_key_nonce)` makes a repeat unstorable rather than merely unlikely | `ast-mxc.3` |
| A1 | G1 | Triggers two rotations at once, so a tenant ends up with two active keys, a queue of unused ones, or a rotation nobody recorded | Every mutation runs in a transaction holding a per-tenant advisory lock, in a lock space distinct from the audit sink's so the two cannot deadlock; the partial unique indexes permit one active and one pending key per algorithm; a triggered rotation always writes a `key.rotated` audit record | `ast-mxc.3` |
| A1 | G1 | Registers a client whose `jwks_uri` names the server's own network — `169.254.169.254` for the cloud credentials that mint tokens for every tenant, a neighbour in the container network, an admin port on loopback — and uses the fetch as a probe or an exfiltration channel | The fetch is refused before a packet: `https` only, no userinfo, no fragment, and a host that must be a public DNS name or an IP literal outside every reserved range. IPv6 is an allow-list (global unicast only), so unique-local — where `fd00:ec2::254` lives — link-local and IPv4-mapped loopback are refused without an entry. A refusal reaches the client as the same "keys unavailable" as a timeout | `ast-mxc.5` |
| A1 | G1 | Passes the address check with a public DNS answer, then rebinds the name to `127.0.0.1` for the connection that follows | The name is resolved once, *every* address in the answer is checked, and the connection is made to one of those addresses — `TcpStream::connect(SocketAddr)`, never to the name. After the check nothing that could resolve is handed the name again, so there is no second answer to poison; the name is used only as the TLS server name, where it is matched against a certificate. An answer mixing permitted and refused addresses fails whole rather than falling back to the one that passed | `ast-mxc.5` |
| A1 | G1 | Redirects the fetch to somewhere the guard already approved of, and then somewhere it did not | No redirect is followed. A 3xx is a failure with its own message; a client that needs one publishes the final URL, which is a URL the guard can judge | `ast-mxc.5` |
| A1 | — | Points a `jwks_uri` at a third party and turns the AS into an amplifier: assertions naming `kid`s that exist nowhere, each triggering the refetch OIDC Core §10.1.1 asks for | One fetch per client per minute, claimed *before* the fetch starts so concurrent requests collapse into one attempt rather than each starting their own; a failure is remembered for its own period, so a broken or hostile `jwks_uri` is asked once and not again. A suppressed refresh still answers with the keys already held, so an honest request inside the window fails at the signature and not before | `ast-mxc.5` |
| A1, A2 | G1 | Answers a key fetch with a body that never ends, a gigabyte of JSON, or ten thousand keys — each of which is a signature check an unauthenticated request asked for | 5 s over the whole exchange and 3 s to connect; 64 KiB read frame by frame with a running total, so an endless or lying `Content-Length` stops at the cap; at most 32 keys and 16 resolved addresses; only `application/json` and `application/jwk-set+json` are read at all | `ast-mxc.5` |
| A1 | G1, G2 | Publishes a JWK Set holding a key the profile excludes — RS256, a 1024-bit modulus, a key marked `use: enc` — and has it used to check that client's own credentials | The set is filtered to keys this server can verify with: `use`/`key_ops` honoured, `alg` matched against the closed enum *and* against `kty`, coordinates required to be the full curve length, RSA below 2048 bits dropped (SP §5.4.1). An unusable key is skipped rather than failing the set, because one stale entry must not cost a client every other key it published | `ast-mxc.5`, ADR-0003 |
| A1 | G1, G2 | Publishes a JWK Set containing its own private key — by accident, or to see what the server does with it | The whole set is refused, not filtered: a `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth` or `k` in a published document means that client's private key is public, and continuing to authenticate it from the remaining keys would paper over a compromise | `ast-mxc.5` |
| A1 | G1 | Registers a `jwks_uri` whose host or path carries a CR or LF, splitting the outbound request into two | The URL is taken apart by a WHATWG parser and only its normalised authority and path become a request; a fuzz target asserts over arbitrary input that whatever survives is a valid header value and a valid URI | `ast-mxc.5` |

| A1, A2 | G1, G2 | Steals a database dump and finds it holds every authorization code, `request_uri`, PAR parameter set, session fingerprint and replay marker the deployment has ever issued, because nothing ever deleted them. RFC 9700 §4.2-4.3; FAPI 2.0 SP §7 counts the AS itself as a place data leaks from | A retention policy that names **every** table in the schema — swept, with the statement that sweeps it, or kept, with the reason. A background sweep applies it per tenant every five minutes. A table added by a later migration with no rule fails a test against `information_schema`, because the failure mode here is not a wrong rule but a forgotten table: it works perfectly and accumulates for a year | `ast-p2l.4` |
| A1 | G1 | Makes the sweep itself the outage: several replicas delete the same rows at once, contending on every one of them, or one enormous transaction holds `jti_replay` while the endpoint that inserts into it waits | Per-tenant `pg_try_advisory_lock` in its own two-key space, so a second replica declines rather than waits and neither can deadlock against the audit sink's lock or key rotation's; deletes run in bounded batches, each its own transaction, with a ceiling per pass so a backlog is spread over sweeps rather than held in one lock. A test holds the lock the way another replica would and requires the sweep to decline without deleting a row | `ast-p2l.4`, `ast-p2l.7` |
| A1, A5 | G1, G4 | Reads a credential or a person's identity out of a log written by a background worker — a sweep's `sqlx` error quotes the connection string that produced it, password and all, and no request handler was ever in scope to sanitise it | Redaction is a property of the log *formatter*, not of the call site, so a worker line is redacted like any other; the scanner also strips the `user:password@` of any URL while keeping the host, which is the half that made the line worth writing. A workspace-wide test fails on any subscriber built without `RedactingFields`, naming the file and line — which is what will cover the admin console the day it installs one | `ast-p2l.4`, `ast-83p.5` |
| A1, A5 | G4 | Reads a user's email address, username or phone number out of the audit trail — the one artefact deliberately kept for years, copied into a SIEM and read by whoever is on call. The credential scanner does not help: `alice@example.com` is not credential-shaped | `Detail::pii` records personal data as the same deterministic fingerprint `Detail::credential` uses, so one person can still be followed across a trail without their identity being in it, and there is one hashing scheme to get right rather than two | `ast-p2l.4` |

### Revocation endpoint (RFC 7009)

`ast-1sk.2` adds `POST /revoke`, which moves a trust boundary twice. It is a
new **authenticated** endpoint any registered client can reach, and it is the
first writer of the access-token denylist — a table now read on the path of
every access token this server verifies itself.

| Attacker | Goal | Attack it enables | Control | Bead |
|---|---|---|---|---|
| A1 | G1, G3 | Turns `/revoke` into an oracle. Any registered client can reach it, so a client that has come by a value — a log line, a proxy trace, another tenant's leak — asks "was that a live credential here?" and reads the answer off the status code or the timing of the two branches | Every outcome that is about a *credential* is the same empty 200: unknown, expired, already revoked, and issued to another client. RFC 7009 §2.2 requires it, and it is implemented by putting `client_id` inside the `where` clause rather than comparing after a read, so another client's token matches no row and there is nothing to leak. The only two refusals — `invalid_request` and `unsupported_token_type` — are decided from the request and the token's own `typ` header, before any lookup, so neither depends on what the store holds | `ast-1sk.2` |
| A1 | G1 | Revokes somebody else's credential: a client with a valid registration presents a refresh token or access token it was not issued, and the authorization behind an integration it does not own stops working | Two comparisons against signed or stored facts. The refresh token's row carries the `client_id` it was issued to and the update matches on it; the access token's `client_id` claim is read only *after* the signature, the `typ` and the issuer have been checked against this tenant's published keys, through the same verifier UserInfo uses. A client with no valid assertion never gets that far: RFC 7009 §2.1's client authentication is the token endpoint's authenticator, unchanged, with its replay check and its timing equalisation | `ast-1sk.2` |
| A1 | G1 | Writes rows of an attacker's choosing into `access_token_denylist`: the primary key is a `jti`, and a `jti` read from an unverified token is a database key chosen by whoever sent the request — as is the `exp` that decides how long the row lives | Nothing is read out of a token before it verifies. The denylist write takes the `jti` and the `exp` of a `Verified` token only, so both are values this server signed; the row's lifetime is the token's own `exp` and the insert is `on conflict do nothing`, so a repeat neither grows the table nor moves an existing revocation's instant. The classifier in front of it is bounded (8 KiB of token, 4 KiB of header) and fuzzed | `ast-1sk.2` |
| A1, A2 | G1 | Makes revocation look like it worked when it did not: a client hands a token back during a database outage, is told 200, discards it — and the token stays live for the rest of its lifetime | A storage failure is a 503 `temporarily_unavailable`, never the 200 that ends the client's attempt. The same rule the other way: UserInfo's denylist read refuses rather than serving a token it could not check | `ast-1sk.2`, `ast-1sk.5` |
| A1 | G1 | Uses the endpoint as an amplifier: it verifies a `private_key_jwt` assertion — a public-key signature — before it decides anything, and unlike `/token` and `/par` it is not behind a per-endpoint limiter | **Known gap.** `/revoke` is not in `LimitedEndpoint` and is unlimited; a flood costs the same signature verification a `/token` flood would. The limiter's own module documentation now says so rather than claiming the endpoint is unbuilt. The blast radius is bounded by what the endpoint can do — it writes at most one row per authenticated request and issues nothing — but the CPU is real | `ast-1sk.2`, `ast-p2l.3` |
| A5 | G4 | Reads which credential was revoked out of the audit trail | The event records the client, the tenant, the grant when one was reached, the hint the client sent and which *kind* of thing was revoked. The token is not recorded in any form. A revocation that revoked nothing is recorded too, so a run of them against one client is visible rather than invisible | `ast-1sk.2` |

One thing this endpoint deliberately does **not** do: it does not revoke the
grant. Grant Management ID1 §6.5's Note allows that, and it means a client that
signs a user out can reconnect without a second consent screen for an
authorization nobody withdrew.

What it does do, since `ast-m9c.13`, is honour RFC 7009 §2.1's other SHOULD —
"also invalidate all access tokens based on the same authorization grant". It
still cannot list those tokens, because RFC 9068 access tokens are stateless
and nothing wrote their `jti` down; what it writes instead is a cutoff on the
*grant*, in the same transaction that stamps the refresh token, and UserInfo
refuses any token of that grant minted at or before it. The grant stays live,
so an authorization nobody withdrew is still there to mint from — which is why
the mark had to be a line in time rather than a flag.

### Admin console (first-party, same-origin)

[ADR-0009](adr/0009-the-admin-console-is-a-first-party-same-origin-app.md)
decides that the console authenticates with the IdP's own session cookie rather
than as an OAuth client, because FAPI 2.0 SP §5.3.2.1 item 3 admits confidential
clients only and RFC 6749 §2.1 makes a browser bundle a public client. That
choice *moves* two risks rather than removing them, and those are the first two
rows. `ast-f7m.1` builds the API those controls live on — authentication in two
modes, RBAC, audit, the generated OpenAPI document, pagination, idempotency and
rate limits — and the rows below it are the risks that surface brings with it.
`ast-f7m.3` adds the console's own document and assets, and the three rows after it are the risks that shipping a script bundle from this origin brings. `ast-wr4` adds the way in — a first-party continuation of the interaction the login pages already drive — and the last two rows are what a login that ends somewhere other than a client's `redirect_uri` brings with it. `ast-f7m.7` puts the signing keys behind that surface, and the last three rows are what an administration API over *key material* brings: exfiltration, self-inflicted denial of service, and a rotation that outruns the verifiers it has to reach. `ast-f7m.6` puts *identities* behind it — the claims a relying party is told about a person, the credentials they sign in with, the sessions they hold and the authorizations they have given — and the last five rows are what an administration API over that brings: a forged subject, a trail that becomes a directory, an off-boarding that relying parties are never told about, a reset that is a way in rather than a way back, and a listing that is a way to read a tenant's people. `ast-3t8` then puts *authority itself* behind the same surface — two restricted roles, and a screen that appoints — and the last row is what delegating administration brings: the boundary a restricted role draws is only worth what the three places that enforce it are worth.

| Attacker | Goal | Attack it enables | Control | Bead |
|---|---|---|---|---|
| A1 | G1, G3 | CSRF against `/admin/api`: the console is authorised by an ambient `__Host-asterius_session` cookie, which the browser attaches to a cross-site request as it never would an `Authorization` header, so a page an administrator visits can create a client, rotate a key or delete a tenant on their behalf (RFC 9700 §4.7) | Three layers, none trusted alone. A synchroniser token bound to the session — not to an interaction row, which the existing `Interaction::issue_csrf` machinery needs and a JSON API does not have — compared in constant time on every non-`GET`. An `Origin` / `Sec-Fetch-Site` check, so a request whose browser says it came from elsewhere is refused before the token is read. `SameSite=Lax` on the cookie last of all, because `session.rs` documents why it is `Lax` and not `Strict`: it does not cover a top-level `GET`, which is why every state-changing `/admin/api` route refuses that verb — and that refusal is *structural*: `asterius_admin_api::operations::Mutating` has no `Get` variant, so a mutating `GET` is a program that does not compile rather than a rule a reviewer has to remember | `ast-f7m.2`, `ast-f7m.1` |
| A1 | G1, G2, G3 | XSS on the IdP's origin becomes an administrator session compromise, not a defacement: the console runs same-origin with the login and consent pages, so injected script cannot read the `HttpOnly` cookie but can issue `fetch` calls that carry it, and can read the CSRF token the page must contain to be usable at all | The nonce-based policy in `crates/web/src/csp.rs` is the primary control rather than a defence in depth: `default-src 'none'`, `script-src 'nonce-…' 'strict-dynamic'`, no `'unsafe-inline'` and no `'unsafe-eval'` — the workspace source audit fails the build if either appears. The console widens no directive: it is served from `'self'`, calls `'self'` under `connect-src`, and its entry document is rendered by the server so every script, stylesheet and modulepreload tag carries the per-response nonce, which a bundler's static `index.html` cannot. `frame-ancestors 'none'` and `base-uri 'none'` close the framing and base-tag variants. `ast-gore` put a component framework (shadcn/ui over Radix) inside that page and widened nothing: React writes inline styles through the CSSOM, which `style-src` does not govern, so the positioned layers need no `'unsafe-inline'`; the one dependency that injects a `<style>` element is handed the response's nonce, read back from the entry script's `element.nonce` so that nonce hiding is preserved; and Sonner, which injects a stylesheet it cannot nonce, was refused rather than paid for with a route-scoped `style-src 'unsafe-inline'` | `ast-f7m.2`, `ast-f7m.3`, `ast-jsq`, `ast-gore` |
| A1, A5 | G1, G3 | A route added to the admin API without an authorization check. The API grows a resource per console screen (`ast-f7m.3` to `.7`), and the failure is silent: the route works, and it works for everybody. `ast-k2o` is the same shape — four fuzz targets that compiled nothing because a second list had to be remembered | An `Operation` cannot be declared without an `Authority`: the field has no default and no `Option`, the struct's fields are private, and the two constructors are the only way to build one. The router is built by walking that registry and nothing else, and `AdminApi::operations` returns the same slice — so the table-driven test enumerates the *router's* routes rather than a list beside it, and asserts 401 for a credential-less request and 403 for an authenticated caller holding no role, route by route, the moment a route exists | `ast-f7m.1` |
| A5 | G4 | Reads the admin surface's own description: the OpenAPI document names every path and the exact authority each one requires, which is a map for whoever is looking for the one that is wrong | The document is an authenticated route like any other, so an anonymous request for it is a 401. It is also *generated* from the registry rather than maintained beside it, and a test fails the build when the checked-in copy is stale — `ast-iko` and `ast-bnc` are what a hand-maintained description costs, where discovery advertised what the server does not do | `ast-f7m.1` |
| A1 | G1 | A creation retried after a timeout runs twice — two tenants, two clients, two keys — because the caller cannot tell whether the first request landed | An `Idempotency-Key` is required on every `POST` and claimed through the same atomic single-use store the `jti` replay guard uses, so at-most-once holds across replicas rather than per replica. A repeat is answered 409 rather than executed, which also tells the caller its first request landed. The stored-response form is deliberately not built; see the module's own note | `ast-f7m.1` |
| A1, A2 | G1, G4 | The asset route serves whatever it is asked for: `GET /admin/assets/../../etc/passwd`, or a file returned under a type that makes it executable in the origin the session cookie belongs to | Nothing joins a request onto a filesystem path. The bundle is a `static` table built at compile time by `crates/admin-api/build.rs`, and a lookup is string equality against it — a traversal is a name no asset has, which is a 404 rather than a check that could be got wrong. Each entry's `Content-Type` comes from a closed list in that script, so a file with an extension nobody decided on is not embedded at all, and `nosniff` from the transport layer makes the declared type binding | `ast-f7m.3` |
| A1 | G1, G4 | A cached admin document: the entry page is served to the next person at a shared machine, or from the back button after a sign-out — the browser-history family RFC 9700 §4.3 names, arriving through the cache | `asterius_web::document::layer` puts `Cache-Control: no-store` on anything it recognises as a document, and the console's entry page is one. The *assets* are cached for a year as `immutable`, which is safe for exactly this reason: their names are content hashes, and the only thing that names them is a document nobody stores | `ast-f7m.3` |
| A5 | G4 | The console fetches from a third party — a CDN chunk, a web font, an analytics beacon — and every administrator's visit tells that party which deployment they administer and when | `connect-src 'self'`, `font-src 'self'` and `default-src 'none'` are unchanged: the console widens no directive, and one that needed to would be a new ADR rather than a patch (ADR-0009). The build ships no font and no runtime CDN reference, a unit test scans the embedded bundle for an absolute URL, and the browser sweep records every request the page makes and fails if one leaves the origin | `ast-f7m.3` |
| A1 | G1, G4 | Turns the console's sign-in into an open redirect: the login has to end *somewhere*, and the obvious shape is a `next=` or `return_to=` parameter the entry sets and the interaction replays. Whoever can put a URL in it can have this server send an authenticated administrator to a page of their choosing, with the IdP's own domain in the address bar — RFC 9700 §4.10.2's warning, arriving through the first-party surface rather than through `redirect_uri` | The destination is a **variant, not a value**: `Continuation::FirstParty(FirstPartyDestination::AdminConsole)`, a closed enum whose only inhabitants are compiled into the binary, and `http::console::location_of` maps it to a `&'static str`. There is no parameter to supply, no URL to validate and no allow-list to drift out of step with the router, so there is nothing to get wrong at the moment somebody adds a screen. A test submits `next`, `redirect_uri`, `destination` and a CRLF-bearing variant of each into the login form and requires the `Location` to be unchanged; the model half is enforced by the types — `Continuation::Client` holds a non-optional `ClientId` and its parameters, so "an authorization with no client" is not representable either | `ast-wr4`, ADR-0009 |
| A1 | G1, G3 | A second way to sign in. A console with its own login form is a second place for the rate limiter, the uniform failure message, the timing equalisation and the session-id rotation to be forgotten — and an authentication that produced no `acr`/`amr` would silently disarm "an administrative action requires a phishing-resistant authenticator" before it is written | There is no second path. `GET /t/{tenant}/admin/` without a usable session opens an interaction and hands the browser to the same `/interaction/{id}` pages every other login uses; the session is created by `interaction::sign_in` and by nothing else, so the throttle, the single message, the fresh session id and the recorded `amr` are the same code rather than the same intention. A test drives a console login and an authorization login through one entry point and asserts the sessions match in user, `acr` and `amr`, and that both cookies carry the same attributes and never the digest. The console under a tenant is ADR-0010's consequence: a session belongs to a tenant, so a session of tenant A meets a login page at tenant B's console rather than its shell | `ast-wr4`, ADR-0009, ADR-0010 |
| A1, A5 | G1, G2, G3 | Phishes the deployment admin. That account reaches every tenant, including ones that do not exist yet, and a password authenticates it to whoever is holding the page: a relay on a look-alike host collects it and replays it at the real console, which is exactly the verifier impersonation NIST SP 800-63B §5.2.5 asks a verifier to resist and which no amount of password entropy prevents | A session whose user holds a deployment-scoped role (ADR-0010) does not open the admin surface unless its `amr` records a **user-verified passkey** — a WebAuthn assertion is signed over the origin the browser actually reached, so a relay's signature names the relay. The rule is `asterius_domain::admin_access_policy`, applied in the two places a console session is turned into authority and nowhere else: `asterius_admin_api::auth::console`, which every `/admin/api` request passes through, and `http::console::enter`, which decides whether the shell is drawn. No migration: `Session` already carries `acr` and `amr`. A password-only admin is sent back through the ordinary login — the one flow that knows how to ask for a passkey — rather than shown an error, and their session is left intact because it is still a good session for everything that is not this surface. A store that cannot answer "what roles do they hold" refuses rather than admits | `ast-895`, ADR-0010 |
| A1, A5 | G1, G3 | **The bootstrap window, accepted deliberately.** `PgAdminSeed` can only create a password — a passkey is made by an authenticator in front of a person — so the rule above, applied without exception, would leave a fresh deployment with nobody able to enrol the credential it demands. Between first boot and first enrolment the deployment's most privileged account is therefore reachable with a phishable credential | The exception is the narrowest self-closing one available: an account with **no enabled passkey at all** is admitted on its password, and an account with one is not. It is not a flag, so it cannot ship enabled and be forgotten; it closes the moment the admin enrols, for sessions already open as well as for new ones; and a disabled passkey does not hold it shut, since a credential blocked for a counter regression cannot be presented. Every request admitted through it is logged at `warn` naming the tenant and the user, because what an operator has to be able to discover is that the window was still open three months later. What is *not* claimed is that the window is safe: a deployment that never enrols a passkey stays in it | `ast-895` |
| A1, A5 | G1, G2, G3 | Guesses the deployment admin's password. `bootstrap_admin` takes it from a file or an environment variable an operator writes, and the value operators write under time pressure is `changeme` or `admin123` — the first hundred guesses of any credential-stuffing run, against the one account that administers every tenant | The seeded password goes through `AcceptedPassword::accept_locally`, which is NIST SP 800-63B §5.1.1.2's floor — at least eight characters, NFKC-normalised, no composition rules — plus a deny list compiled into the binary and compared after case folding and trimming, so `Password123` is refused too. It fails the **boot**, like the Argon2 parameter floor, so the deployment stops while somebody is watching rather than running on a guessable admin. The list is hand-written and small: it is not a breach check, and the breach-check port that would be one is `ast-2vk.10`, unbuilt. Until it exists, a password that is merely uncommon still passes | `ast-895`, `ast-2vk.10` |
| A1, A5 | G1, G2 | Relaxes the profile from the console: an administrator — or anyone who has taken their session — sets the authorization code lifetime to an hour, or the access token lifetime to a day, and every code interception window the profile bounds opens with it. The form is not the control: a session and a CSRF token are enough to send the `PUT` with `curl` | The ceilings are in the domain, not in the screen. `TenantSettings` has private fields and one constructor, so a lifetime past FAPI 2.0 SP §5.3.2.1 item 11's sixty seconds, or past this server's fifteen-minute access-token cap, cannot be *built* — the admin handler, the storage adapter and the row reader all take the validated type. A refusal names the clause rather than saying "invalid", so the administrator stops instead of trying 300 seconds next. A stored document above a cap fails the read rather than being clamped, so a row edited during an incident is not a way round it either, and the parser is fuzzed against exactly that property | `ast-f7m.4` |
| A1 | G1, G2 | A tenant switches an optional feature off and the deployment goes on advertising it: the discovery document is cached in process and by every client for five minutes, so an operator who has just disabled a feature — perhaps in response to an incident — is looking at a document that says it is still there, and cannot tell whether the change landed | The admin API drops the process's settings cache in the same call that writes (`AdminBackend::tenant_directory_changed`), so the next request renders from the new settings; the thirty-second TTL is only the net for a write that happened in another replica. A tenant's flags may only *subtract* from the deployment's — `TenantSettings::effective_capabilities` has no way to enable anything — so a settings document cannot advertise a feature the binary does not run. A settings read that fails answers 503 rather than falling back to the deployment's capabilities, which would republish exactly what was switched off. The router is built once per process, so the per-tenant refusal is a guard on the request (`protocol::tenant_feature_guard`): it reads the same `Endpoint` registry and the same `effective_capabilities` the document is rendered from, and answers 404 — what the deployment answers for a feature it does not run — so a client that knows the URL learns nothing the metadata did not already say. The parity test in `crates/server/tests/discovery.rs` asserts both directions for every gated endpoint, per tenant | `ast-f7m.4`, `ast-edc` |
| A1, A5 | G1 | Uses the admin API as an amplifier: an unauthenticated flood costs a session lookup and a role query per request, and an authenticated one enumerates a tenant's people as fast as the database will answer | The fixed-window counters of `ast-2vk.9`, in their own `admin:ip:` bucket rather than sharing the login limit — so a burst of failed sign-ins cannot lock an operator out of the surface they would respond with. Counted before the credential is resolved, on the address resolved from the socket peer and the trusted proxy set, never a header at face value. An unreachable limiter refuses rather than admits | `ast-f7m.1`, `ast-2vk.9` |
| A1, A5 | G1, G2, G3 | Exfiltrates a signing key through the console. The key screen (`ast-f7m.7`) is the one admin surface whose subject *is* key material, and a private half that reached a browser — through a JSON field, a debug dump, a "download backup" affordance — is a total compromise: whoever holds it mints tokens for any subject, and no revocation reaches a resource server that only checks a signature | The API has no access to one. The handlers hold `asterius_domain::keys::KeyAdministration`, whose every method returns `PublicKeyRecord` — a public JWK and no other key bytes — and which has no method that yields a signing key at all; `PgKeyRepository::active_signing_key`, which does, is reachable only from the composition root's signer. So the property is a consequence of the port's return types rather than of a handler remembering to redact. Beneath that, rendering is an **allow-list** of the public JWK members RFC 7517 §4 and RFC 7518 §6 define, because `signing_keys.public_jwk` is a `jsonb` column an incident can `UPDATE`: a member nobody has thought about is dropped rather than published. A unit test feeds a row carrying `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth` and `k` through both key routes, and `admin_key_request` states the same property over arbitrary input | `ast-f7m.7`, `ast-mxc.3` |
| A1 | G1 | Takes a tenant's issuer offline from its own console: retiring the key an algorithm signs with leaves nothing to mint a token, so every login stops at the token endpoint — a denial of service that needs no attacker beyond a mis-click, and that an attacker who has reached the console will reach for deliberately | Retiring the active key is refused with a 409 naming rotation as the way to replace it, in the repository rather than in the screen — the console hides the button, and the server would refuse it if the console did not. Rotation puts a successor in place *before* the incumbent stops signing, so the two-step an operator would otherwise improvise is one atomic pass under the tenant's rotation advisory lock | `ast-f7m.7`, `ast-mxc.3` |
| A2 | G1 | Signature failures across every relying party after a console rotation: a key published and used in the same instant meets verifiers whose JWK Set cache has not turned over, and OIDC Core §10.1.1's staged rotation exists precisely to avoid it | The default is the wait. `Activation::OnSchedule` is the `Default` and the value an absent field parses to, so a rotation that does not ask gets the tenant's propagation period; a unit test asserts the default rather than trusting the field order. `Activation::Immediate` is opt-in per request and exists for the one case that justifies it — a key believed compromised must stop signing now — and even then the displaced key stays published in `retiring`, so tokens already issued keep verifying. The console labels the two buttons with that distinction rather than offering one "rotate" that quietly picks | `ast-f7m.7` |
| A1, A5 | G1, G2, G3 | **Writes a `sub` into somebody's claims.** The claims bag is a `jsonb` column and the console edits it, so a caller who can put `sub` — or `iss`, `aud`, `acr`, `amr` — into it decides what a relying party believes about *which person* is signing in. That is impersonation at every RP at once, and it needs no credential beyond an administrator's session, which is what an XSS on this origin buys | The name is a type: `ClaimName::parse` refuses every claim the authorization server mints for itself and every claim that lives in a column (`email`, `email_verified`, `updated_at`), so a bag able to hold a `sub` cannot be constructed — the route cannot store what the parser will not build. `Claim::new` refuses a `null` value (OIDC Core §5.3.2) and the `serde_json` sentinels. The count and each value's serialised size are bounded, because the body arrives from the network and every accepted claim is read on the `userinfo` path afterwards. `admin_user_claims` states all of it over arbitrary input rather than over a fixture | `ast-f7m.6`, `ast-1sk.4` |
| A5 | G4 | **The audit trail becomes a staff directory.** An account screen's events name people, and the trail is kept for years, copied into a SIEM and read by whoever is on call — so a record carrying a username or an address turns an evidence store into personal data at rest, which is FAPI 2.0 SP §7 and GDPR data minimisation pointing the same way | Every account event records the local `user_id` as its subject — the uuid, which is ADR-0009's identifier and never leaves the deployment — and its details carry counts and flags rather than values: how many claims before and after, whether the address changed, whether the flag is asserted. A `sid` goes in through `Detail::credential`, which stores a fingerprint, so two events about one session can be joined and neither can be read back out. Nothing on this path calls `Detail::text` with a name or an address | `ast-f7m.6`, `ast-83p.11` |
| A1 | G1, G3 | **An off-boarding nobody is told about.** Disabling an account stops it signing in *here*, but a relying party that issued its own session from an ID token goes on serving the person until that session expires — hours or days after an operator believes they have removed access. The mirror image is worse: telling the relying parties first and failing to mark the account leaves everybody signed out of an account that can immediately sign back in | One implementation, one order: the account is marked, then its sessions are revoked, then the relying parties that took part are queued a logout token (OIDC Back-Channel Logout 1.0 §2.5). It lives below the port in `DeploymentUsers::terminate_sessions`, not in a handler, so the ordering is not three statements a future edit may reorder — and the tokens are minted by the same `backchannel::Notifier` RP-initiated logout uses, so a session ended from the console and one ended by the person are indistinguishable to a relying party. The receipt the API returns counts tokens **queued**, never delivered: delivery is the outbox's and may dead-letter, and an operator told "3 relying parties notified" would believe more than this server can stand behind. The RISC `account-disabled` signal is `account.disabled` in the trail and a named seam; the transmitter is `ast-0ju` | `ast-f7m.6`, `ast-o4u.2`, `ast-0ju` |
| A1, A5 | G1, G2 | **A support path that is a way in.** "Reset this person's password" is the oldest social-engineering target there is, and the obvious implementation — an administrator types a new password and reads it out — makes a credential that two people know and that NIST SP 800-63B §5.1.1.2 has nothing good to say about. The variant that is worse: an operator who has taken an administrator's session sets a password on the account they want and signs in as it | There is no field for a password on this route, so there is nothing to type. Forcing a reset **invalidates** the credential — the row is disabled, not overwritten, so it does not read as a working password afterwards — invalidates every outstanding recovery token, ends every session with `SessionRevocation::CredentialChange`, and hands a single-use fifteen-minute link to the notification port for the *account's own address*. Whoever forces the reset therefore ends up with no way in: they need the mailbox, which is the boundary `docs/threat-model.md`'s account-recovery section already names. An account with no address gets no link and the response says so, rather than reporting a reset that went nowhere | `ast-f7m.6`, `ast-2vk.10` |
| A1, A5 | G4 | **Reads a tenant's people.** A directory endpoint is an enumeration tool by construction, and an unbounded one is also a way to make this server materialise every account in memory on request | The route is `Reach::Tenant` and the tenant is the issuer the request arrived at rather than a parameter, so a tenant administrator can only enumerate their own tenant — the same rule the client listing follows, checked by the table-driven authorization test rather than by this file. The filtering and the cut happen **in the database**: a bounded, cursor-paginated range scan over `(tenant_id, username)`, with the search term bound as a parameter and never interpolated, so a page costs one index scan whatever the tenant holds. The cursor is opaque and versioned. Sessions and grants carry their own scopes (`admin.sessions:*`, `admin.grants:*`) so that a deployment can grant "end this person's session" without granting "read the claims that describe them" — the distinction `ast-4jy`'s support role is for | `ast-f7m.6`, `ast-cts`, `ast-4jy` |
| A1, A5 | G1, G2, G3 | **Delegated authority becomes full authority.** `ast-3t8` adds two restricted roles — `user_support`, which reads accounts and acts on their sessions and grants, and `security_auditor`, which writes nothing — so an operator can hand the console to a support desk or to a reviewer. Each is a *boundary*, and a boundary is only real if it holds in three places at once: a role that satisfied a reach without being asked which scope it holds would make `user_support` a tenant admin with a different name; a console that hid the claims editor without the server refusing it would be a decoration; and a route added later with an authority nobody mapped would be held by everybody or by nobody. The sharper case is the one that turns a restricted role back into an unrestricted one: whoever may appoint administrators may appoint themselves | The mapping is one closed function in the domain, `asterius_domain::Role::grants`, and `rbac::roles_satisfy` asks *both* halves of it — reach and scope — of the **same** role, so a caller holding a restricted role in their tenant cannot borrow "may write" from one role and "reaches here" from another. It fails closed on the scope grammar: anything that is not `admin.<resource>:<action>` is granted to no role, and `security_auditor` holds every `read` action and no `write` action, including on routes that do not exist yet — so the direction it widens in is the harmless one. The table-driven authorization test walks the whole registry for each restricted role and asserts the refusal is exactly what the mapping says, which is what makes a route added later a test failure rather than a silent grant. Appointing is its own scope, `admin.roles:*`, separate from `admin.users:*`: delegating account administration does not delegate the power to appoint administrators. Nobody may edit their own roles, and a deployment-scoped role may only be granted or revoked by a caller who already reaches the deployment — so the console cannot be used to promote oneself, and every grant and every revocation is a record of its own (`role.granted`, `role.revoked`) naming the account, the role and the administrator behind it. What is **not** claimed: a `user_support` can still end anybody's session and withdraw anybody's grant, which is disruption on demand, and an account holding it is worth the same protection as any other administrator's | `ast-3t8`, ADR-0010 |
| A1, A5 | G1, G2 | **Suspends a tenant, or creates one nobody asked for.** `ast-l5bl` puts the deployment's own tenant list behind the console: creating a tenant mints its signing keys in the same step, and suspending one stops it answering at every endpoint it serves — every client fails to obtain a token, every user fails to sign in, and that tenant's own administrators are locked out along with them. It is the largest outage a single request to this API can cause, and the caller who can cause it is whoever holds — or has taken — a deployment administrator's session | The route reaches the **deployment** and nothing less (`TENANT_STATUS_UPDATE`, `admin.tenants:write`), so the tenant/deployment boundary here is the same one every other route draws: a tenant admin cannot suspend their own tenant, which would otherwise be a way to lock every administrator of it out with one click. `enabled` is a required member rather than one defaulting to `false`, so a truncated or empty body is a 400 and not a suspension. The **reserved tenant cannot be suspended at all**, because disabling it would refuse the sessions of everybody who could restore it (ADR-0010); restoring it is still permitted, since that direction only undoes damage. The console confirms the act in a dialog that names the consequence rather than asking "are you sure", and the change is recorded as `ADMIN_CHANGED` against the administrator's own tenant, naming the operation, the tenant and the new status. It is reversible from the same screen, and nothing is deleted: this API has no route that deletes a tenant | `ast-l5bl`, ADR-0010 |

### Audit query API and export (`ast-lh3.9`)

`ast-83p.11` made the trail append-only and hash-chained, and `ast-lh3.2` made
every token exchange leave a record with the RFC 8693 §4.1 `act` chain in it.
`ast-lh3.9` is the read side: `GET /audit/events` (filtered, cursor-paged) and
`GET /audit/events/export` (NDJSON, streamed), so that "everything done under
user U — by U, by U's agent A, and by agent B holding a token A delegated" is
one query with the chain intact rather than a join an investigator writes at
2 a.m. The read side of a trail is also its exfiltration side, and the rows
below are what a query API over *the most sensitive thing a read scope
reaches* brings with it. RFC 7662 introspection is not mounted in this build
(`ast-1sk.1`), so the trail holds issuance and exchange; the query will hold
introspection the day it is recorded.

| Attacker | Goal | Attack it enables | Control | Bead |
|---|---|---|---|---|
| A1, A5 | G4 | **Mass exfiltration through a read scope.** Every other `admin.*:read` describes a deployment; the trail describes its people — who signed in when, from which address, which agent acted for whom, under which authorization. An export endpoint turns "may see that delivery is failing" or "may look up an account" into "may download everything everyone did" if it shares their scope, and an unbounded one turns a stolen auditor session into the whole history in one request | Its own scope, `admin.audit:read`, held by `security_auditor` and the administrators through the role mapping's grammar and by `user_support` not at all; the export is a second `operationId`, not a `format=` parameter, so a token grant or a policy can say "list, but do not export" without parsing a query string. One export is at most `EXPORT_MAX_RECORDS` (100 000) lines, walked from the database a page of 1 000 at a time as the client drains the body, so a slow reader costs one page of memory and no connection across the read; a purpose that needs more has a database client and a change-control record. Both routes sit in the admin API's per-address and per-operation fixed-window buckets (`ast-f7m.1`), so a script cannot page the trail faster than the limiter allows. `Reach::Tenant`, with the tenant taken from the issuer the request arrived at and the first `where` predicate — a tenant administrator exports their own tenant and nothing else, and the table-driven authorization test checks both routes the moment they exist | `ast-lh3.9`, `ast-3t8`, `ast-f7m.1` |
| A5 | G4 | **The export un-minimises what the trail minimised.** A record's IP address and user agent go in through `Detail::pii` as digests; an export that rendered them helpfully — resolving, decoding, joining against the session table — would hand a SIEM the directory the trail refuses to be | Nothing is added on the way out. The rendering (`asterius_admin_api::audit::render`) is a projection of the stored columns: a fingerprint is `sha256:…` on the line as it is in the row, a subject is the local id, and the `authorization_details` entry is the summary of *types* the writer stored — never the details, which hold the payment. There is no join, because the port (`AuditQuery`) reads one table. A handler test seeds an address and a user agent through `pii` and asserts neither appears in the export body | `ast-lh3.9`, `ast-83p.11` |
| A1 | G1, G4 | **A filter that is a query.** The query string decides which rows are shown, and it is text somebody typed: a fragment that reached SQL would be an injection; a misspelled parameter that was ignored (`agnet=c.a`) would return the whole trail to a caller who thought they had asked for one agent's; an unbounded `type=` list or a megabyte of `owner=` is a request for the server to work on the caller's behalf | `parse_filter` turns the string into `AuditFilter`, a closed set of typed members, and is fuzzed as `admin_audit_filter`: an unknown parameter is a 400 rather than a no-op, a value is bounded to 256 bytes and refused on a control character, `grant` must be a UUID, `type` must be one of `EventType::ALL`, a window must be ordered, and a refusal is one of a closed set of sentences that names a documented parameter and never echoes the value. What reaches PostgreSQL is `QueryBuilder` fragments this crate wrote with every value a bound parameter, and the SQL predicates are the spelling of `AuditFilter::matches` — a database test seeds the delegation chain and checks the two agree for every member | `ast-lh3.9` |
| A3a | G1 | **A record dropped on the way out.** An export that skipped a row this build cannot read — one written before `ast-ju2`, or by a newer schema — would be evidence with a hole nobody was told about, and a storage failure half-way through a stream that ended cleanly would look like the end of the trail | An unreadable row is on the page as `{"id", "hash", "opaque"}` and counts against the page like any other (`ast-1p1`); every readable line carries the record's stored hash, so an export can be checked against the chain later by whoever holds both. A storage failure mid-stream ends the body with an error after the headers have gone — the client sees a response that did not complete, never a `200` that looks whole and is not. Nothing here writes: the port has no method that appends, so no admin route built on it can be one that rewrites the table the database refuses to let anything rewrite | `ast-lh3.9`, `ast-1p1` |
| A5 | G4 | **A scan per question.** "What did agent A do" over a tenant with years of trail is a sequential scan of that tenant's rows if nothing indexes the actor, the owner, the subject or the chain — a denial of service an auditor commits by accident, and one an attacker with the scope commits on purpose | Migration `0035` adds partial indexes on `(tenant_id, actor->>'id')` and `(tenant_id, actor->>'on_behalf_of')` for agent actors, on `(tenant_id, subject)`, on `(tenant_id, event_type)` and a `jsonb_path_ops` GIN on `actor_chain` for the containment the chain filter uses; each ends with `event_id desc` so a filtered page is one range scan from wherever the last one stopped. No column was added: a new field on `AuditEvent` would change `canonical_bytes` and turn every earlier record into a tampering report, so the agent view is read out of the columns the trail already has. A database test `explain`s the owner and chain questions against a filled table and requires the indexes by name | `ast-lh3.9` |

### Console: SSF streams, dead letters and the audit explorer (`ast-f7m.8`)

`ast-lh3.9` above is the read side of the trail; `ast-f7m.8` puts a screen in
front of it and, beside it, gives an operator three things nothing but SQL
could do before: re-enable a stream the push worker paused (`ast-0ju.6`),
send a stream SSF 1.0 §8.1.4's verification event, and put an abandoned SET
back on the outbox or drop it. Each is a button that makes this server *do*
something to a third party or to its own delivery trail, so each is a route
with a write scope of its own, an audit record with the operator's name on
it, and a rule about what it will not touch.

| Attacker | Goal | Attack it enables | Control | Bead |
|---|---|---|---|---|
| A1, A5 | G2, G3 | **Requeue as a replay engine, or a way to reorder.** A retry makes this server post a signed statement about a person to a receiver again; a retry of a `notification.account_recovery` re-sends a reset link nobody asked for twice; and a row put back behind the rows that overtook it while it was abandoned arrives out of the order its ordering key promised | The two routes accept `ssf.*` rows and answer 409 for any other family (`asterius_admin_api::outbox::is_retryable`; the listing reports `retryable` so the console cannot offer what the server refuses). An SSF receiver deduplicates on `jti` (RFC 8417 §1.2) and orders on `event_timestamp`, so a late SET is a late signal and not a wrong one — which is the property the family rule is stated on, and why extending it to another family is a decision and not an edit. `admin.outbox:write` is a scope of its own beside the read the dead-letter screen is granted on, and each retry or drop is `outbox.retried` / `outbox.dropped` with the row, its kind, its attempt count and the receiver's last word under the operator's name; the drop's record is the only trace of the row once it is gone. The retry raises the budget rather than resetting the attempt counter, so the attempts trail keyed on `(row, attempt)` keeps the first run's history beside the second's | `ast-f7m.8`, `ast-0ju.9` |
| A1, A3 | G2 | **Verification as a signal flood.** §8.1.4's event is a signed SET posted to a receiver; a button that sends one per click, from a session an attacker holds, is a way to make this server post to a receiver at will | `admin.ssf:write`, held by the administrators and not by the auditor or support; a `POST` with an `Idempotency-Key`, so a retried click is one SET; the admin API's per-address and per-operation fixed-window buckets (`ast-f7m.1`); and the SET goes on the stream's own queue, where the push worker's attempt budget, backoff and pause rule bound what one stream costs (`ast-0ju.6`). `min_verification_interval` is enforced at the receiver's own endpoint (`ast-0ju.5`) and deliberately not against the operator: the operator is the party the interval protects, and an operator's verification does not consume the receiver's. Recorded as `ssf.verification_requested` with the stream fingerprinted and whether a `state` was given — never the `state`, which is a correlation value the receiver compares against | `ast-f7m.8`, `ast-0ju.6` |
| A1 | G1 | **A `state` or a reason as an injection.** Both are operator-typed text; `state` is copied verbatim into a signed token a receiver parses, and a reason is written to the stream row, shown on the console and read back by the receiver when `ast-0ju.4` lands | `VerificationState::parse` and `parse_status_request` are the only ways in, both fuzzed (`ssf_verification_state`, `admin_stream_status`): bounded to 256 characters, refused on a control character, a status other than `enabled` or `paused` refused — `disabled` is the receiver's state (§8.1.2) and an operator does not write it — and every refusal names the rule without echoing the value. The rendered stream document has no endpoint and no credential member at all (a test asserts on the serialized member set), because a push endpoint may carry a token in its query string and the credential is sealed for a reason | `ast-f7m.8` |
| A1, A5 | G4 | **Export from a screen that shows it to everybody.** The console draws an "Export as NDJSON" link; a link the wrong session can follow is a download prompt for the whole trail | The link is a same-origin anchor and not a fetch — the browser's downloader streams it, so the tab never holds a hundred thousand lines — and it is drawn only for a session whose `GET /session` scopes carry `admin.audit:read`, which is also what the screen opens with. None of that is the control: `GET /audit/events/export` answers 403 to a support agent's session and 401 to no session, asserted in the admin API's handler tests and in the browser sweep, and the export's own bounds and rendering are unchanged from `ast-lh3.9` above | `ast-f7m.8`, `ast-lh3.9` |

**A choice made here: an operator's pause and enable overwrite the worker's
reason.** `PgSsfStreams::pause` never un-pauses and never overwrites, so that
the reason on a row is the one that stopped the stream. The operator's
`set_status` does both, because an operator re-enabling a stream is stating
that the worker's reason no longer holds and a stream paused by hand carries
the hand's reason; `enabled` clears it, so a delivering stream never shows a
stale refusal beside it. The worker's rule still holds against the operator's
row: a stream an operator paused stays paused with the operator's reason if a
delivery later fails, because `pause` only moves `enabled` to `paused`.

**Residual, stated rather than closed:** a requeued SET goes out after the
SETs that overtook it, which for a `session-revoked` behind a later
`credential-change` about the same person is the order the receiver's
`event_timestamp` restores and the ordering key no longer can; the
verification event is triggered by an operator only, until `ast-0ju.4` gives
the receiver §8.1.4's endpoint; and the console's browser sweep asserts the
screens against a tenant with no receiver, so a stream's buttons are
exercised by the handler tests and the database tests rather than in a
browser.

### mTLS client authentication (RFC 8705 §2)

`ast-m9c.3` adds the second of FAPI 2.0 SP §5.3.2.1 item 6's two methods, and
with it **two new roots of trust**. Both are off unless `[features] mtls` is on:
without the flag the methods cannot be registered, no certificate is collected
at the door, and the discovery document does not name them.

The change is that a client can now be authenticated by something this server
did not verify a signature from. `private_key_jwt` needs the client's private
key; mTLS needs a certificate somebody else vouched for, or one the client
published. Who that somebody is, is the whole of the risk.

| Attacker | Goal | Attack it enables | Control | Bead |
|---|---|---|---|---|
| A1 | G1, G3 | Authenticates as any client by claiming a certificate: in `behind_proxy` mode the certificate arrives in a header, and a header is something any caller can set. `X-Client-Cert: <a certificate for the billing client>` from the open internet would be a complete client impersonation with no credential at all | The header is read only when the immediate socket peer is inside `[server.proxy] trusted_cidrs` — the same set, and the same rule, that decides whether `X-Forwarded-For` is believed, resolved once in `tenancy::layer` rather than per handler. From any other peer it is dropped **without being parsed**, so the X.509 reader is not even reachable from an untrusted address. `trusted_cidrs` is empty by default, which means an unconfigured deployment believes nobody. A unit test presents a valid certificate from an address outside the set and requires it to be ignored | `ast-m9c.3` |
| A4 | G1, G2, G3 | The reverse proxy authenticates clients. In `behind_proxy` mode it decides which certificate this server sees, so it can present any client's and be believed | Accepted and recorded rather than mitigated: this is the same trust already extended to that proxy for the client's address and its `Host`, and terminating mTLS somewhere means trusting whoever terminates it. What is bounded is the blast radius — the proxy cannot mint a *token*, only assert a client — and the alternative posture, `[server] mode = "terminate_tls"`, removes it entirely. An operator forwarding the header must strip an inbound one; the configuration reference says so where the key is documented | `ast-m9c.3` |
| A5 | G1, G3 | A CA one tenant trusts issues a certificate naming another tenant's client, and one process serves both. Or the deployment's outbound roots — the Mozilla programme, for fetching clients' `jwks_uri` — are reused for client certificates, at which point any public CA can mint a client for anybody | Trust anchors are **per tenant** and loaded from that tenant's own PEM file; `TenantTrustAnchors::for_tenant` is the only way to reach them and takes a `TenantId`. There is no global fallback and no default set: a tenant with no anchors configured refuses every `tls_client_auth` client rather than reaching for somebody else's roots. The outbound roots are a separate value used by a separate path and are never offered here | `ast-m9c.3` |
| A5 | G1, G3 | A certificate the tenant's CA issued for a *server* — an HTTPS host under the same corporate CA — is presented as a client credential | `KeyUsage::client_auth` is passed to `webpki::EndEntityCert::verify_for_usage` rather than assumed. A certificate whose extended key usage does not admit client authentication does not chain, whoever issued it | `ast-m9c.3` |
| A1, A5 | G1, G3 | Matches a registered name that was never meant to match: `RP.example` for `rp.example`, `rp.example.attacker.test` for a suffix rule, a re-ordered DN, a wildcard | The comparison is byte-exact, in the one field the client registered, with no normalisation, case folding or wildcard anywhere in the path (RFC 8705 §2.1). RFC 8705 §2.1.2's "exactly one" is a closed enum rather than five optional fields, so a client cannot register two names and leave the server choosing. The DN rendering is a deterministic function of the certificate's bytes — same bytes, same string, or no string at all — and a table of near misses is asserted not to match | `ast-m9c.3` |
| A1, A2 | G1, G3 | Feeds the new X.509 parser: the certificate arrives before anything about the caller is known, and a parser that panics takes the process down while a parser that guesses authenticates the wrong client | Written for exactly this input: a size bound checked before anything is decoded, definite-length DER only, minimal length encodings only, no recursion at all, a cap on entries at each level, and `None` for anything it does not understand — a certificate it cannot read authenticates nobody. `#![forbid(unsafe_code)]` as everywhere else. Two fuzz targets, `client_certificate` over the DER and `client_certificate_header` over the proxy header, assert totality and that the rendering is a function of the bytes | `ast-m9c.3` |
| A1 | G1, G3 | A self-signed client is authenticated by a certificate it never published — one carrying the same public key, or the same subject, or an issuer from its `x5c` chain | RFC 8705 §2.2 is implemented as a SHA-256 thumbprint over the **whole DER**, compared against the *first* entry of each `x5c` in the client's JWK Set (RFC 7517 §4.7 makes that the leaf; the rest are issuers, and matching one would authenticate every client that CA issued). Nothing inside the certificate is read on this path — not the subject, not the validity, not the key — because in this method the certificate authenticates only by being the one the client published | `ast-m9c.3` |

**Not yet built, and listed in §5:** certificate revocation is not checked — no
CRL and no OCSP — so a certificate a tenant's CA has revoked keeps
authenticating until it expires. A deployment that needs revocation configures
it at the proxy, which is where a fetch on the authentication path belongs.

### Certificate-bound access tokens (RFC 8705 §3)

`ast-a05.7` adds the **second sender-constraining mode**. Until it, every access
token this server issued carried a `cnf.jkt` and was held by a DPoP key; a
client registered with `tls_client_certificate_bound_access_tokens: true` and
presenting a certificate now gets a token carrying `cnf.x5t#S256` instead, held
by that certificate. Both are off unless `[features] mtls` is on: without the
flag the member cannot be registered and the discovery document does not name
it.

Two properties bound the change.

**A client registers exactly one method.** `TokenBinding` has two variants and
no `Both`, so `dpop_bound_access_tokens: true` beside
`tls_client_certificate_bound_access_tokens: true` is refused at registration,
and a token request that presents a certificate *and* a DPoP proof is
`invalid_request` rather than a token this server chose a binding for. The
reason is that RFC 8705 §3.1 and RFC 9449 §6.1 each define their own `cnf`
member and neither says what a resource server must do when both are present:
a doubly-bound token would be as strong as the weaker reading of it, chosen by
the verifier rather than stated by the issuer.

**Binding is a property of the client, never of the request.** The one place
the decision is made is `issuance::SenderConstraint::confirmation`, which reads
the registration; all three grants mint through it, so a grant added later
cannot arrive at a different reading, and neither the presence of a proof nor
the presence of a certificate can change what a client's tokens are bound to.

| Attacker | Goal | Attack it enables | Control | Bead |
|---|---|---|---|---|
| A2, A5 | G1, G2 | Steals a certificate-bound access token — from an RS log, a crash dump, a TLS-intercepting proxy — and presents it at UserInfo over their own connection | The `cnf` decides: a token carrying `x5t#S256` is answered only when the certificate this request arrived with hashes to that value, over the same trusted-proxy path the token endpoint's certificate takes. No certificate is the same answer as the wrong certificate — `invalid_token` — because "could not check the binding" and "the binding does not hold" have the same consequence. Two certificates and one token are asserted not to be interchangeable | `ast-a05.7`, `ast-1sk.3` |
| A1, A5 | G1 | Presents a certificate-bound token under the `DPoP` scheme, or a DPoP-bound token as a bearer token over an mTLS connection, hoping the endpoint checks whichever half the caller can satisfy | The token's `cnf` holds exactly one member and selects exactly one check. `x5t#S256` is refused under `DPoP`; `jkt` is refused under `Bearer` however good the certificate on the connection is; a token carrying both members — which no registration can produce — is refused outright rather than resolved in the caller's favour | `ast-a05.7` |
| A1, A2 | G1 | Steals a certificate-bound refresh token and redeems it under another certificate, or under none, since the client authenticates by other means | The refresh row records the binding it was issued under (`refresh_tokens.cert_thumbprint`, the schema's `(dpop_jkt is null) <> (cert_thumbprint is null)`), and a certificate-bound row is redeemable only by the certificate it names — always, unlike the DPoP binding, which the tenant's `bind_to_dpop_key` may leave unenforced so that a confidential client can roll its key (RFC 9449 §5). One `invalid_grant` for a wrong certificate, an unknown token and a revoked grant alike | `ast-a05.7`, `ast-a05.5` |
| A1 | G1 | Registers for certificate binding to escape sender-constraining altogether, or authenticates with mTLS and sends no DPoP proof in the belief that the certificate stands in for one | Neither is reachable. `TokenBinding` has no unbound variant, so the pair `false, false` is refused at registration; and a client registered for DPoP that presents a certificate still owes a proof (FAPI 2.0 SP §5.3.2.1 item 5) — presenting a certificate is client *authentication*, and authentication is not a binding | `ast-a05.7`, `ast-m9c.1` |

**Accepted, and recorded here:** a certificate-bound client that rotates its
certificate cannot redeem the refresh tokens issued under the old one and has
to be re-authorized. This is the mirror of the freedom `bind_to_dpop_key` gives
a DPoP client, and it is deliberate — a `cnf` this server declines to check is
a bearer token carrying a claim about itself. A deployment that rotates
certificates often should bind its clients by DPoP.

### Grant Management request parameters (Grant Management ID1 §5)

`ast-uwv.4` lets a client name an existing grant in an authorization request and
say what to do with it — `grant_id` plus `grant_management_action` of `create`,
`merge` or `replace`. Both parameters are off unless `[features]
grant_management` is on: with the flag off they are ignored, the discovery
document names neither `grant_management_actions_supported` nor
`grant_management_action_required`, and there is no grant store wired into the
pushed-request endpoint to look an id up in. The specification is an
Implementer's Draft, which is why the whole vocabulary sits behind one module
(`asterius_oidc::grant_management`) and one port
(`asterius_domain::GrantAmendments`).

What is new here is that **a client can now name somebody else's
authorization**. Everything below follows from that.

**The three ownership checks, and when each can be made.** A `grant_id` is
attacker-chosen input from an authenticated client. Whether the grant exists and
whether it belongs to *this client* are decided at the push, where the client is
on the connection and a refusal is a JSON error. Whether it belongs to *the
person who signs in* cannot be decided there — nobody has signed in — so it is
checked where the flow completes and reported as an RFC 6749 §4.1.2.1 error
redirect. A revoked or lapsed grant is refused at both moments, because the
ninety seconds a `request_uri` lives is a window a revocation can land in.

**One code for every refusal.** §5.4 registers `invalid_grant_id` and this
server returns it for "no such grant", "another client's grant", "another
person's grant" and "revoked" alike. A client that could tell them apart would
have an oracle for whether an id it guessed was ever real, and for what happened
to an authorization it was never party to. A store that cannot be read answers
`temporarily_unavailable` instead, so an outage does not read as a withdrawal.

| Attacker | Goal | Attack it enables | Control | Bead |
|---|---|---|---|---|
| A1 | G1 | An authenticated client guesses or replays a `grant_id` — from a log, from another tenant, from a token it once held — and merges its own request into somebody else's authorization | Three checks with one answer: the grant is this tenant's (the repository is tenant-scoped), this client's (checked at the push), and this person's (checked after the sign-in, because it cannot be checked before). A v4 UUID minted by `Grant::new` is the only shape accepted, and the shape is checked before the database is touched | `ast-uwv.4` |
| A1 | G1, G2 | Uses `merge` to widen a grant quietly — the person consented to a narrow request, and the grant they already had is widened by the union | The consent screen is shown for the request as pushed, and the union is taken over what the person has *already* approved for this client: a merge can only re-affirm scopes an earlier screen carried. Nothing is added that nobody ever agreed to, and `replace` is the action that narrows | `ast-uwv.4`, `ast-uwv.3` |
| A2, A5 | G1 | Holds a refresh or access token from before the amendment and keeps using the privileges the amendment withdrew — a `replace` that narrows three scopes to one leaves stateless JWTs (RFC 9068) claiming all three | §5.2's "shall invalidate existing refresh tokens" and the access-token cutoff are one transaction with the write of the new permissions (`PgGrantRepository::amend`). The cutoff is the same mechanism revocation uses (`ast-m9c.13`) and not a second path, so introspection cannot disagree with it. Access tokens are withdrawn too, which §5.2 does not require and silence does not forbid: the alternative is a live token describing an authorization that no longer exists | `ast-uwv.4`, `ast-m9c.13` |
| A1 | G3 | Sends a `grant_id` to a deployment that never advertised Grant Management, hoping an unadvertised code path is less carefully guarded | With the flag off `grant_management::parse` returns "nothing was asked for" whatever the input, so the parameters cannot reach a lookup, a grant or a store. The fuzz target asserts exactly that over arbitrary input, and the same flag decides what the discovery document says | `ast-uwv.4` |
| A1 | G3 | Uses the parameters as a public client, where §5.1 forbids them | Unreachable: ADR-0002 makes the pushed authorization request the only way to start a flow and FAPI 2.0 SP §5.3.2.2 item 4 refuses one without client authentication, so a public client never reaches the validator. Every client this server registers is confidential for the same reason | `ast-uwv.4` |

**Accepted, and recorded here:** a `merge` accumulates
`authorization_details` elements across authorizations, so a client that merges
repeatedly can reach the sixteen-element bound and be refused. The refusal is
`invalid_request` after the person has consented, which is a poor place to learn
it; the alternative — silently dropping elements — would leave the client
believing it holds an authorization nobody recorded.

### Self-registration and `prompt=create` (`ast-2vk.8`)

**The boundary moved, and this section exists to say where it moved to.**

Before self-registration, every row in `users` was put there by an
administrator, a seed or an import: creating an account required an
authenticated caller with a role. With `features.self_registration` on for a
tenant, anybody who can reach that tenant's authorization endpoint can create
one, by pushing a request with `prompt=create` (OpenID Connect Prompt Create
1.0 §3) and filling in a form.

> **For a tenant that switches this on, the directory becomes attacker-writable
> within the limits below.** Row count, usernames, display names and the set of
> addresses this server will send mail to are all chosen by strangers. A
> deployment whose access control asks "is there an account?" rather than "what
> is this account allowed to do?" is a deployment this flag breaks.

That is why the flag is off by default and why it is a *feature*, read in one
place and used in three: the discovery document advertises `create` from it,
the pushed-request validator accepts `create` from it, and the registrar behind
the page is absent without it. A tenant may subtract it like any other feature,
so a tenant that registers nobody neither advertises the value nor answers the
form.

| Attacker | Goal | Attack it enables | Control |
|---|---|---|---|
| **A1** | **G3** | **Filling the directory.** An unauthenticated form that writes a row and can be posted in a loop. | Every submission — accepted or refused — is counted against the per-address and per-account buckets of `ast-2vk.9`, the same limiter the login form uses. A full bucket refuses before the form is parsed; a limiter that cannot be read fails closed. The submission also needs a live interaction and its synchroniser token, so it cannot be posted without first pushing an authorization request as a registered client. |
| **A1** | **G1** | **Registering over somebody.** A sign-up that *replaced* an existing row would hand over the account under a username the attacker typed. | A creation is never a replacement: the username and the address are read first and a match refuses, and the unique indexes close the race the two reads cannot — a conflicting insert is the same refusal. The same guard `crate::admin` puts in front of an administrator's creation. |
| **A1** | **G3** | **Enumerating accounts through the sign-up form.** The mirror of the reset-form oracle. | A sign-up page cannot avoid disclosing that *something* on the form is in use — it has to refuse a duplicate to work at all — so this discloses more than `/recovery` does and the file says so rather than claiming otherwise. What it does not do is say *which*: a taken username and a taken address are one refusal with one sentence, so the form is not an address checker, and the limiter bounds sweeping it. |
| **A1** | **G4** | **Asserting an identity by typing it.** A `preferred_username`, a display name or an address the attacker chose, rendered by every relying party that reads the claim. | The claim is stored with `ClaimSource::Local` and **no** `verified_at`: it is a preference the account asserted about itself, and OIDC Core §5.1 already tells RPs it is neither unique nor stable. `email_verified` is `false` at creation whatever was typed — §5.1 makes that claim an assertion *the provider* verified the address, and nothing has. The login identifier is never projected into `preferred_username`; the two are separate fields for exactly this reason (`ast-pew`). |
| **A1** | **G4** | **Reordering what a person reads.** A right-to-left override in a username or display name renders on the consent screen as somebody else's name. Escaping does not touch it — it is legal text that survives every encoder. | Both names refuse control characters and the UAX #9 bidirectional set, in the domain parser every door into `users` goes through, and the property is fuzzed (`registration_form`). |
| **A1** | **G1** | **Creating an account nobody can hold.** A weak or breached password chosen at sign-up. | The same `AcceptedPassword::accept_locally` a recovery uses: NIST SP 800-63B §5.1.1.2 normalisation, the length floor, the deny list, no composition rules. There is no constructor that skips it. |
| **A1** | **G3** | **Using the sign-up form as a mail cannon**, once the verification half is wired. | The limiter above counts against the address bucket, so the address an attacker chose is the address that runs out of budget. |

**Residual, and deliberately so:** an account created here starts with an
unverified address and is nonetheless authenticated for the interaction that
created it — Prompt Create §3 asks the OP to treat the creation as an
authentication, and a flow that blocked on a mailbox would strand the client's
authorization on something no browser can finish. A relying party that needs a
proven address must read `email_verified`, which is what it is for.

**Since `ast-vae`:** the verification link and the "unverified users cannot
complete a login where the tenant requires it" rule are built — see *Email
verification* below. A tenant that switches self-registration on and leaves
`require_verified_email` off is still accepting unverified addresses in its
directory, which is the documented default and is why `email_verified` says so.

**Not built yet:** the account self-service pages. Until they land, an address
is changed only by an administrator, so the only route that has to retire an
outstanding confirmation link is the one that already does.

### The "forgot your password?" link on the sign-in page (`ast-ndk.4`)

The sign-in page now links to `/recovery`. The question the ticket left open
was whether it should: a link makes the function discoverable, and a link is
also an invitation to a page that sends mail.

It is there, and the reason it is safe to put it there is a property the
recovery page already has rather than a judgement about how many people will
click it. **`/recovery` is not an oracle.** `POST /recovery` renders one page,
byte for byte, for an address with an account, an address with a disabled
account and an address nobody has; the page type has no field that could
differ, and the audit trail records every request identically. So a visitor who
follows the link learns exactly what a visitor who typed the URL learns, which
is nothing about anybody.

What the link does change is traffic: more people reach a form that sends mail.
That is bounded by the limiter above, which counts every request against the
per-address and per-account buckets whether or not it matched an account, and
which fails closed. And it is weighed against the cost of the alternative — a
recovery function reachable only by typing a URL is a recovery function
answered by a support desk, which is the weakest identity-proofing channel any
deployment has.

The link is rendered only where there is something to recover: a deployment
with no password method configured gets no link, because `/recovery` would
refuse everybody and a link to a page that cannot work is worse than none.

### Account recovery (`ast-2vk.10`)

**The boundary moved, and this section exists to say where it moved to.**

Before account recovery, taking an account over required a credential: a
password, or a passkey's private key. With it, control of the mailbox on the
account is enough. That is not a defect — it is what recovery *is*, and NIST
SP 800-63B §6.1.2.3 treats it as a binding to an out-of-band channel rather
than as a weaker form of the same authenticator — but it has a consequence
worth writing down plainly:

> **The mail provider of every account with an address on it is now inside the
> trust boundary for that account.** It was not before. So is anything on the
> path to it: a corporate mail gateway that expands links to preview them, an
> archive, a shared inbox, a forwarding rule nobody remembers setting.

An operator who cannot accept that should not enable a password method at all;
passkeys are primary here, and an account with no address recovers nothing.

| Attacker | Goal | Attack it enables | Control |
|---|---|---|---|
| **A1** | **G1** | **Guessing a reset link.** A token short or structured enough to be searched is an account per guess. | 256 bits from the OS CSPRNG, unpadded `base64url`, twice the FAPI 2.0 SP §5.4.1 item 4 floor the ticket asked for. The parser accepts exactly the 43 characters this server issues, with no trimming, padding tolerance or case folding, and it runs before any database work — so a malformed token costs a length check, not an index probe. Fuzzed (`recovery_token`). |
| **A2**, and anyone with a database copy | **G1** | **Reading live reset links out of storage.** A table of tokens is a table of account takeovers. | Rows hold the SHA-256 digest and nothing else; there is no plaintext column anywhere and a test asserts the whole row does not contain the token. Unsalted rather than Argon2id on purpose: the input already carries 256 bits, so there is nothing to brute force and a slow hash would only make the lookup slow. |
| **A1** | **G1** | **Racing one link.** Somebody who obtained a link once uses it at the same moment as its owner, and both succeed. | `spend` is a single `update … returning` whose predicates — unspent, unexpired — are inside the statement. Whichever request wins gets the reset; the other updates nothing and is told nothing. |
| **A1** | **G1** | **Using a link that has been sitting in a mailbox.** | Fifteen minutes, enforced in SQL against a clock the caller does not choose, and tested against that predicate rather than a Rust-side copy of it. |
| **A1** | **G1** | **Collecting links.** Somebody asks for three, uses one, and keeps two live takeovers for later — the two nobody will notice being used. | Issuing a token consumes every earlier one for that account in the same transaction. One mailbox, one live link. |
| **A1** | **G1** | **Surviving the change.** An attacker quietly requests a link, the owner changes their password, and the attacker's link still works. | Any credential change invalidates every outstanding token for that user, and the recovery path calls that hook itself. |
| **A1** | **G1** | **Keeping the session.** An attacker who got in first stays in after the owner recovers. | A completed recovery revokes **every** session the account had, with reason `credential_change`. The mirror case is covered by the same line: an owner recovering while an attacker holds a session ends it. |
| **A1** | **G3** | **Enumerating accounts through the reset form.** The textbook oracle (RFC 9700 §4, OWASP Forgot Password Cheat Sheet). | `POST /recovery` renders one page, byte for byte, for an address with an account, an address with a *disabled* account, and an address with none — the page type has no field that could differ, so the absence is structural rather than conditional, and a test compares the two responses byte for byte. A mail-delivery failure does not change it either: "we could not send mail" is only sayable about an address that has an account. The audit trail records **every** request with `Success`, matching or not, so the oracle does not reappear in the database. |
| **A1** | **G3** | **Using this server as a mail cannon.** An unauthenticated form that sends mail to an address the caller chooses, as often as they like. | Every request is counted against the per-account and per-address buckets of `ast-2vk.9` — the same limiter the login form uses, not a second one with its own opinions — and a full bucket refuses before any lookup. A limiter that cannot be read fails closed. |
| **A1** | **G3** | **Burning somebody's link cross-site.** A page on the internet POSTs to `/recovery/new` and spends a link, denying its owner for fifteen minutes. | A `__Host-` prefixed, `SameSite=Lax`, `HttpOnly` synchroniser cookie double-submitted with a hidden field: a cross-site POST carries no cookie, so no match is possible, and the `__Host-` prefix stops a sibling subdomain writing one. A failed check re-renders the form **without spending the token**. |
| **A1** | **G4** | **Taking an account quietly.** | The account is mailed a credential-change notice with nothing in it to click — a link in a message about a password is a phishing lesson — and the change is recorded as `credential.changed`, which is the trail half of the CAEP `credential-change` signal. |

**Residual, and deliberately so:** this repository ships no real mail sender.
The journal adapter writes the message to the transactional outbox and logs
that it delivered nothing. An operator who wires a sender should treat the
outbox as a credential store — an `account_recovery` row contains a live link
until the token behind it expires — and keep its retention short. See
`docs/configuration.md`.

**Not built yet:** passkey re-enrolment after a recovery. Today a recovery sets
a password, which means an account whose only credential was a passkey is
recovered onto a weaker method. The enrolment page (`/passkeys`) exists and is
reachable from the session that follows a sign-in, so the path is a redirect
rather than a mechanism — but until it is wired here, that downgrade is real
and is the reason a deployment may prefer to leave passwords off entirely.

### Email verification (`ast-vae`)

**The boundary moved, and this section exists to say where it moved to.**

Two things changed. The first is that OIDC Core §5.1's `email_verified` can now
become `true` without an administrator: a stranger following a link sets a claim
that relying parties act on, and some of them provision accounts from it. The
second is that a tenant may put a mailbox in the path of every sign-in
(`require_verified_email`), which makes the mail provider a *availability*
dependency for that tenant on top of the confidentiality one recovery already
created.

> **A confirmation link is a proof about a mailbox, and it must never become a
> proof about a person.** Following one signs nobody in, sets no credential and
> starts no session. The moment it did any of those, it would be a second
> recovery flow with no password step, reachable from a sign-up form — and
> "prove you can read this mailbox" would have become "take this account".

| Attacker | Goal | Attack it enables | Control |
|---|---|---|---|
| **A1** | **G1** | **Turning a confirmation into a session.** The whole class above. | The confirm handler writes one column and renders one page. It has no session repository, no credential verifier and no code issuer in its context, so the escalation is absent by construction rather than by a check somebody remembered. |
| **A1** | **G4** | **Moving a proof onto somebody else's mailbox.** Sign up as `attacker@evil.test`, ask for a link, change the address on the account to `victim@bank.test`, then follow the link — and `email_verified` lands on a mailbox nobody proved. | The address the message went to is a column on the token row, not something recomputed at spend time. `spend` returns it, the handler compares it with the address the account holds now, and the write itself carries `lower(email) = lower($3)` as a predicate so an address that moves between the read and the write loses the race rather than winning it. Drawing a new link also supersedes every outstanding one, which closes the same door from the other side. |
| **A1** | **G1** | **Guessing a confirmation link.** | 256 bits from the OS CSPRNG, unpadded `base64url`, twice the FAPI 2.0 SP §5.4.1 item 4 floor. The parser accepts exactly the 43 characters this server issues, with no trimming, padding tolerance or case folding, and runs before any database work. Fuzzed (`email_verification_token`). |
| **A2**, and anyone with a database copy | **G3** | **Reading live links — and a list of addresses — out of storage.** | Rows hold the SHA-256 digest and never the token, asserted against the whole row. The address column is swept the moment the link expires (`retention.rs`), so the table holds a mailbox only as long as the link it belongs to can do anything. |
| **A1** | **G1** | **Racing one link**, or replaying it. | `spend` is a single `update … returning` whose predicates — unspent, unexpired — are inside the statement. Fifteen minutes, enforced in SQL against a clock the caller does not choose. |
| **A1** | **G3** | **Using the resend as a mail cannon**, or as an address checker. | `POST /verify-email` renders one page for an address with an unconfirmed account, one with a *confirmed* account, one with a disabled account and one nobody has; the four are one code path with one answer. Every request is counted against the per-address and per-account buckets of `ast-2vk.9` — the same limiter the login form uses — and a limiter that cannot be read fails closed. The POST is behind the same `__Host-`, `SameSite=Lax`, `HttpOnly` double-submit synchroniser the recovery pages use, so it cannot be fired from a page on the internet. |
| **A1** | **G2** | **Locking a tenant out.** With `require_verified_email` on, an account whose mailbox stops working can no longer sign in at all. | Off by default, documented as a decision rather than an oversight, and narrowed: an account with **no** address is not blocked, because the setting is about proving an address rather than requiring one. A tenant that provisioned passkey-only accounts therefore does not lock them all out by switching it on. |
| **A1** | **G3** | **Learning that an account exists from the gate.** The gate is reached only after a credential was accepted, so it discloses nothing the sign-in did not — but the page it renders names an address. | The address it names is the one on the account that has just authenticated, echoed to the person who just proved a credential for it. It is escaped like every other value, and the page is reachable no other way: a visitor who has not authenticated cannot make this server render it. |

**A GET that writes, on purpose.** `GET /verify-email?token=…` consumes a
single-use token. A mail client follows this link as a top-level navigation
with no form and no script, and the alternative — an interstitial with a
*Confirm* button — is the pattern that trains people to press buttons on pages
that arrived from a message. It is safe here because the write is harmless when
unintended and moves no other state: a link prefetched by a mail scanner
confirms the address slightly earlier than the person would have. CSRF has
nothing to protect, because an attacker who can make a browser issue this
request is an attacker holding the token, and holding the token is the whole of
the authorisation. The resend, which *sends mail*, is a POST for exactly the
opposite reason.

**Residual, and deliberately so:** this repository still ships no real mail
sender, so the same warning the recovery section gives applies to the
`email_verification` rows in the outbox — they contain a live link until the
token behind them expires.

**Not built yet:** no CAEP signal is emitted when an address is proved. A
confirmed address is recorded as `email_verification.verified` in the audit
trail and nothing more; it is deliberately *not* a `credential-change`, which
would tell every receiver to end sessions over an event that ended no
credential. When `crates/ssf` grows an assurance signal, that is where this
goes.

### Tenant string overrides and `ui_locales` (`ast-ndk.5`)

**A tenant supplies no markup — and now it supplies strings, which is the same
sentence read carefully.** The pages of the authorization journey take their
words from a message catalogue, and a tenant may substitute wording for any key
in it. Those strings are written by a tenant administrator and rendered to
somebody else's browser, on a page reached before authentication. That is stored
cross-site scripting with the parties relabelled.

The language a page is written in is chosen from three inputs, two of which are
attacker-influenced: the client's `ui_locales` (OIDC Core §3.1.2.1), the
browser's `Accept-Language` (RFC 9110 §12.5.4), and the tenant's configured
default, in that order.

| Attacker | Goal | Attack it enables | Control |
|---|---|---|---|
| **A2** (a tenant administrator, against that tenant's own users) | **G1** | **Script through an override.** A wording change containing `<script>`, or an attribute-breaking fragment, executes on the sign-in page — where the password is typed. | Two independent defences, deliberately not one. Askama autoescapes every interpolation and `crates/web/src/source_audit.rs` fails the build on a second `\|safe` in the tree; and `MessageOverrides::from_json` refuses `<` and `>` outright at the moment the value is accepted, so the string never reaches a row. The second holds for consumers that are not templates — a mail body, an admin API response — and the first holds if a key is ever rendered somewhere new. Fuzzed (`tenant_message_overrides`), with a test that tries `<script>alert(1)</script>` at both layers. |
| **A2** | **G1** | **Reversing a consent sentence.** `U+202E RIGHT-TO-LEFT OVERRIDE` in an override changes what a person reads without changing what is stored — Trojan Source (CVE-2021-42574) pointed at a human decision instead of at a compiler. | Control characters and the bidirectional overrides `U+202A–U+202E` and `U+2066–U+2069` are refused. Newline and tab are the only exceptions. |
| **A2** | **G1** | **Emptying a decision.** An override that blanks `consent.allow`, or drops the `{0}` that names the client in `consent.calls-itself`, leaves a person agreeing to a sentence that names nobody. | Blank values are refused. A message that names something must keep its placeholder: `asterius_web::i18n::validate_overrides` refuses an override that drops it, and the render path ignores such an override rather than rendering a nameless page. |
| **A1** | **G3** | **`ui_locales` as an injection or oracle.** The parameter is stored on the pushed request and read back on the sign-in path; a value that is not a language tag becomes text in a `jsonb` column that decides what a person is shown. | `UiLocales::parse` keeps only RFC 5646 §2.1-shaped tags, at most eight of them, at most 64 bytes each — on the way in *and* on the way back out of the row. Fuzzed (`ui_locales_parse`). The value never reaches a page: it selects a catalogue entry, and there is no path that renders it. |
| **A1** | **G2** | **Failing a sign-in with a language.** A request that names an unsupported language, or a settings row with an unreadable overrides document, becomes an error page instead of a sign-in. | OIDC Core §3.1.2.1 forbids an error for an unsupported `ui_locales`, and the negotiation has no error type at all: every layer falls through to the next and the last is the tenant's default. A settings read that fails costs the tenant its wording, not its availability. The one place a language *is* refused is a stored `default_locale` this build has no catalogue for, which fails a settings read rather than a request. |

**Residual, and named:** an override is bounded text, but it is still text a
tenant chose, and a tenant that wants to write "Allow" on the Deny button can.
Nothing here defends a user against the operator whose sign-in page they are
already typing a password into; the boundary this table describes is markup and
non-printing characters, not intent.

### Outbox delivery worker (`ast-0ju.9`)

**Why this needs a section: the server now makes outbound requests on a
schedule, to addresses other people chose.** Everything before it dereferenced
a client-supplied URL *during a request*, bounded by that request's own
lifetime and provoked by a caller who was standing there. A delivery worker
does it in the background, repeatedly, with a body, for as long as the backoff
schedule says — which is a different exposure even though the URLs come from
the same place.

The rule is unchanged and it is ADR-0006's: there is one outbound path.
`asterius_server::outbound::post` is a body attached to the existing one — it
borrows the SSRF guard, the resolution, the address checks, the trust anchors
and the connect from `outbound::jwks` rather than repeating them — so a gap
closed for a `jwks_uri` is closed for a `backchannel_logout_uri` on the same
line of code.

| Attacker | Goal | Attack it enables | Control |
|---|---|---|---|
| **A1** | **G3** | **Turning the worker into an SSRF engine.** A client registers a delivery endpoint pointing at cloud metadata, an internal admin API or a loopback port, and the server posts a body to it — from inside the network, unattended, and retried nine more times. | Every delivery goes through `outbound::post`, which calls the same `ssrf::check_url` and the same per-address `why_refused` as a JWK Set fetch, connects to the vetted address rather than re-resolving the name, and refuses every 3xx. A `POST` is strictly worse than a `GET` here, so the guard is the same guard rather than a second one written for this caller. |
| **A1** | **G3** | **Holding a worker open.** A registered endpoint accepts the connection and then answers one byte a minute, occupying the worker for as long as it likes. | One timeout over the whole exchange, resolution included (five seconds), and a bounded drain of the response — which is discarded regardless, because no specification riding this outbox defines anything a receiver may say back that changes what the transmitter does. |
| **A1** | **G3** | **Amplification.** A client registers an endpoint and provokes the server into posting a large body to somebody else's server. | The body is built by this server, not by the caller, and is refused above 128 KiB before a socket is opened. The rows this ships carry a JWT. |
| **A1**, **A5** | **G1** | **Reading somebody else's message out of the dead-letter screen.** `GET /outbox/dead-letters` is reached with a read scope; an abandoned `notification.account_recovery` row's payload is a live password-reset link. | The document renders the row id, the kind, the attempt count, the timestamps and the deliverer's error — and has no payload, destination or ordering-key field at all. A test asserts on the serialized field list, so adding one is a change somebody has to make on purpose. The `last_error` string is written by a deliverer that names a host and a status and never a URL or a response body. |
| **A2** | **G1** | **Reading the messages out of storage instead.** | Unchanged from `ast-2vk.10` and stated again because the outbox is now a queue with a worker rather than a table nobody reads: the row holds the live link until the token expires, and `retention::POLICY` ages delivered and abandoned rows on a stated schedule. `claimed` rows are deliberately *not* swept — a claimed row is work still owed — which means a wedged claim keeps a payload alive for the length of its lease and no longer. |
| **A1** | **G2** | **Replaying a delivery.** Delivery is at-least-once by design, so a receiver can see the same event twice. | Duplicates arrive under the same `outbox_id`, and every payload format riding this carries its own `jti` for a receiver to deduplicate on. The alternative — acking before delivering — loses a back-channel logout every time a process is evicted, and a logout that never arrives is a session a relying party keeps after this server ended it. Losing one is a security failure; sending one twice is not. |
| **A3** | **G3** | **Wedging the queue.** One receiver that never answers holds up everybody's deliveries. | Ordering is per key, not global: a row is blocked only by an earlier row with the *same* ordering key. A stuck `(client, session)` holds that session's queue and nothing else's, and the attempt budget ends it at the dead-letter screen. Claims are `for update skip locked`, so a worker never waits on another worker's row. |

**Residual:** a worker killed between the claim and the ack leaves the row
unavailable until its lease lapses — sixty seconds by default. That is a
delivery delay, not a loss, and it is the price of at-least-once; shortening
the lease trades it for more duplicate deliveries, which is the wrong side of
the trade.

### SSF transmitter configuration (`ast-0ju.1`)

**The transmitter's `jwks_uri` is the OP's.** A SET is signed through the same
`Signer` port and the same tenant key as an ID token (`ast-0ju.2`), so
`/.well-known/ssf-configuration` names the OP's key set rather than one of its
own: a second set would publish the same material at a second URL and give a
receiver a second place to be told about a rotation. The cost is that a
receiver holding the transmitter's keys can also verify an ID token this
tenant issued — it cannot mint one, and the set is public — and the day a
tenant wants SET signing separated from token signing, that is a dedicated key
in the same `KeyStore` and one changed member in this document, not a new
trust path. The document itself is public, per-tenant and constant: it is
served only behind `Feature::Ssf`, deployment-wide and per tenant, so a tenant
that runs no transmitter answers 404 rather than publishing an issuer a
receiver could try to configure a stream against.

### SSF stream configuration (`ast-0ju.3`)

**Why this needs a section: a stream is a standing subscription to signals
about a tenant's users, arranged by a third party over an API that no human
ever sees.** A receiver creates one with a `client_credentials` token, and from
then on this server intends to tell it when a session is revoked or an account
is disabled. The question the endpoint has to answer on every request is not
"is this a valid token" but "whose streams may this caller touch".

**The frontier: a receiver reaches its own streams and nothing else.** The
`client_id` from the verified token is in the `WHERE` clause of every read and
every write (`asterius_store_pg::ssf_streams`), so another receiver's
`stream_id` is not a row that comes back and gets refused — it is a row that
does not exist. The 404 of SSF 1.0 §8.1.1.2 is therefore the truthful answer
rather than a chosen one, and there is no code path in which a `PATCH` or a
`DELETE` could reach a stream belonging to somebody else. The identifier is
128 bits from the OS CSPRNG on top of that, so it is not an enumeration space
either.

| Attacker | Goal | Attack it enables | Control |
|---|---|---|---|
| **A1** | **G1** | **Redirecting a stream at itself.** A receiver changes `aud`, or the push `endpoint_url`, on a stream it does not own, and starts receiving another receiver's signals about people it has never seen. | The stream is fetched by `(tenant, client_id, stream_id)` before anything is changed, so there is no stream to edit. `aud` is settled at creation and immutable afterwards (§8.1.1): a request naming a different one is a 400, not a change, and the comparison is over the set so a re-ordering is not a rewrite. |
| **A1** | **G1** | **Reaching the management API with a token minted for something else.** A receiver's token for the tenant's business API, or any client's token at all, is presented at the stream endpoint. | `aud` must be this tenant's stream configuration endpoint, and the token must carry `ssf.manage` — a scope that exists only on that implicit resource server (`issuance::ImplicitResources`), so a token for `payments` cannot carry it. The token is sender-constrained: `client_credentials` here issues nothing unbound, and the DPoP proof is checked over a `htu` built from the tenant's issuer rather than from the request. Only `client_credentials` may be audienced here — a user-delegated token never is, so no person's authorization can stand behind a stream they were never asked about. |
| **A1**, **A3** | **G3** | **Using `delivery.endpoint_url` as an SSRF target, or as an amplifier.** | A push endpoint must be `https`, must have a host and may carry neither fragment nor userinfo, checked before it is stored. Nothing is sent to it by this story — push delivery is `ast-0ju.6` — and when it is, it goes through ADR-0006's one outbound path like every other client-supplied URL. |
| **A2** | **G2** | **Keeping the signals flowing after the stream is gone.** A deleted stream whose queued SETs are still in the outbox delivers events about people to a receiver that has been withdrawn. | §8.1.1.5 is one transaction: whatever the stream still owed is abandoned first, the row is removed last. A crash between the two leaves a stream whose events are already stopped, which is the safe half. |
| **A5** | **G1** | **Configuring a stream and leaving no trace.** | Every creation, update and deletion is an audit event of its own (`ssf.stream_created`, `ssf.stream_updated`, `ssf.stream_deleted`), with the receiver as the actor and the stream recorded as a fingerprint rather than as its identifier — enough to correlate entries, not enough to act on if the trail leaks. |

**A credential this server keeps, and the conditions it keeps it under.**
RFC 8935 §2.2 lets a receiver hand the transmitter an `authorization_header` to
present on every push. `ast-0ju.3` refused the member with a 400 and named the
three things that had to land together before it could be accepted;
`ast-0ju.6` landed them. It is sealed under the tenant's KEK with the
`stream_id` as additional authenticated data
(`asterius_jose::RowSecret::SsfPushAuthorization`), the rotation sweep
(`asterius_store_pg::rewrap`) moves it with everything else the KEK seals, and
the endpoint validates it as an HTTP field value before it is stored — a value
carrying `\r\n` is a second header in every request this server would then make
to that receiver. It is never rendered back: see the push delivery section
below.

**Residual, stated rather than closed:** one stream per receiver per audience is
a unique index rather than a tenant setting, so a tenant that legitimately
wants several gets a 409 until that setting exists; and `events_supported` is
empty until an emitter lands (`ast-0ju.5`, `ast-0ju.8`), so a receiver that
configures a stream today is told, in `events_delivered`, that it will receive
nothing. The second is deliberate: the alternative is a receiver believing it
has continuous-access coverage it has not got.

### SSF poll delivery (`ast-0ju.7`)

**Why this needs a section: this is where the signals actually leave the
building.** Stream configuration arranges a subscription; poll delivery is the
endpoint that hands a third party a batch of SETs about a tenant's users, on
request, with no human anywhere in the loop. Three new things exist because of
it: a URL per stream (RFC 8936; SSF 1.0 §6.1.2), a queue of signed tokens
waiting to be collected (`ssf_poll_queue`), and a request body a receiver
writes that this server parses (§2.1).

**The frontier: the URL names the stream, the token names the receiver, and the
row is read under both.** `POST /ssf/poll/{stream_id}` looks the stream up by
`(tenant, client_id, stream_id)` — the same `WHERE` clause the management API
uses, for the same reason — so another receiver's stream is not a queue this
endpoint drains and then refuses to return; it is a stream that does not come
back, and the 404 is truthful. The identifier is 128 CSPRNG bits, so the URL
space is not enumerable, but nothing rests on that: a receiver that somehow
learned another's URL still gets a 404.

| Attacker | Goal | Attack it enables | Control |
|---|---|---|---|
| **A1** | **G1** | **Polling somebody else's stream.** A receiver with a valid token calls another stream's polling URL and collects signals about users it has never seen. | The stream is resolved under the token's `client_id` before a single row of the queue is read, so the attacker's own token is what makes the stream invisible. A `stream_id` that is not one this server issues is a 404 before the token is even looked at. |
| **A1** | **G1** | **Polling with a token minted for something else.** A management token, or a business-API token, presented at the polling endpoint. | `aud` must be this tenant's *polling* endpoint and the token must carry `ssf.poll` — a second implicit resource server with a scope of its own (`issuance::ssf_poll_resource`), deliberately not the same one the management API uses. A receiver's event consumer therefore cannot delete the stream it reads, and its stream administrator cannot read its events (RFC 8707 §2). The token is sender-constrained, and the DPoP `htu` is rebuilt from the tenant's issuer and the identifier this server recognised — so a proof made for one stream's URL does not authorize a poll of another. |
| **A1** | **G2** | **Silencing a stream by acknowledging what it never received.** An `ack` naming every plausible `jti`, or a `setErrs` report for SETs the receiver never saw, to make signals disappear before anyone acts on them. | Acknowledgement and error reports are scoped to the stream in the URL, which is already scoped to the caller, so this is a receiver silencing *its own* stream — which it may already do by deleting the stream. Both are bounded (`MAX_ACK`, `MAX_SET_ERRS`) and a rejection is written to the trail before the row goes. |
| **A2** | **G2** | **Losing a signal to a crash.** A receiver reads a response and dies before processing it; a transmitter that had already deleted the rows has lost the events. | Delivery removes nothing. §2.4's acknowledgement is the only thing that does, so an unacknowledged SET is handed over again on the next poll — at-least-once, as everywhere else in this server, with the receiver deduplicating on `jti`. |
| **A1**, **A3** | **G3** | **Holding connections open.** A receiver opens long polls (`returnImmediately: false`) and never closes them, or asks for an unbounded `maxEvents` to make one request read a whole backlog into memory. | The wait is capped at `MAX_LONG_POLL` (30 s) and then answers with an empty `sets`; the batch is capped at `MAX_EVENTS` (100) whatever `maxEvents` asks for, with `moreAvailable` telling the receiver to come back. The request body is bounded before it is parsed, and every member is bounded after. |
| **A5** | **G1** | **Collecting signals and leaving no trace.** | Every poll that carried SETs, every acknowledgement and every rejection is an audit event (`ssf.sets_delivered`, `ssf.sets_acknowledged`, `ssf.set_rejected`), with the receiver as the actor and the stream as a fingerprint. The queue also counts deliveries per SET, so a receiver being handed the same token forty times is visible to an operator. |

**A choice §2.4 leaves open, made here: a reported SET is retired, not
redelivered.** A receiver that reports `setErrs` for a SET will not be given it
again. The alternative — redeliver until acknowledged — is a queue that never
drains behind a SET the receiver cannot verify, and every later signal stuck
behind it. The cost is that a receiver whose verifier was briefly
misconfigured loses those events, so the report is written to the audit trail,
with the receiver's own error code, *before* the row is removed: that entry is
the only record left that the signal existed.

**Residual, stated rather than closed:** nothing queues a SET yet — the
emitters are `ast-0ju.8` — so today this endpoint is a correct, tested and
permanently empty queue; and a receiver that never polls leaves its SETs in
`ssf_poll_queue` for ever, because §8.1.1's `inactivity_timeout` is stored but
nothing sweeps on it yet.

### SSF push delivery (`ast-0ju.6`)

**Why this needs a section: this is the one path where this server dials out
carrying a secret, about a person, to an address a third party chose.** Poll
delivery waits to be asked; push delivery is an outbound `POST` from inside the
deployment's network to a URL a receiver registered, with the receiver's own
credential on it and a signed statement about a user in the body. Three
capabilities meet in one request: SSRF, credential handling, and a decision
taken on the strength of what an outsider says back (RFC 8935 §2.3).

**The frontier: the stream is the authority, and the outbound path is the same
one.** The outbox row names a `stream_id` this server wrote; the endpoint, the
credential and the "is this stream still delivering" question all come from
that row at delivery time, so a receiver that changed its endpoint is not
posted to at the old one and a deleted stream (§8.1.1.5) is not posted to at
all. The request itself goes through ADR-0006's single outbound path
(`asterius_server::outbound::post`), which is the same SSRF guard, the same
trust anchors, the same refusal to follow a redirect and the same 10-second
timeout as every other dereference of a client-supplied URL.

| Attacker | Goal | Attack it enables | Control |
|---|---|---|---|
| **A1**, **A3** | **G3** | **Using a push endpoint as an SSRF probe or an amplifier.** A receiver registers `https://169.254.169.254/…`, or a name that resolves into the cluster, and has the transmitter deliver to it from inside the network. | The endpoint must be `https` with a host and no userinfo or fragment at registration, and every delivery goes through `outbound::ssrf` — which refuses loopback, link-local, private and unique-local addresses *after* resolution, so a DNS answer that changes between registration and delivery is refused too. No redirect is followed: a 3xx is a failure, never a hop to an origin that has not been through the guard. |
| **A1** | **G1** | **Smuggling a second header into every request the transmitter makes.** A receiver registers an `authorization_header` containing `\r\n`, turning each delivery into two requests of its choosing. | `asterius_ssf::push::AuthorizationHeader` accepts only visible ASCII with spaces and tabs, at registration and again when the row is read back, and the outbound path refuses a header value HTTP cannot carry rather than reporting it as a transport failure. |
| **A2** | **G1** | **Reading another receiver's credential out of a database dump, or moving one between streams.** | The value is sealed under the tenant's KEK, never stored or logged in the clear, and the `stream_id` is in the additional authenticated data: a ciphertext pasted into another stream's row does not decrypt, so the delivery fails loudly instead of presenting one receiver's credential to another's endpoint. It is also never echoed by the management API — §8.1.1.2 is authorized by a token, not by holding the secret, so returning it would put a credential in a response body and a log for a caller that already had it. |
| **A3** | **G2** | **Making the transmitter shout.** A receiver answers 503 to everything, or hangs, so that the worker spends itself retrying one stream while every other delivery waits. | One timeout over the whole exchange, a bounded attempt budget per row with exponential backoff (`ast-0ju.9`), and a stream whose delivery exhausts that budget is **paused** (§8.1.2) with the reason recorded — so a broken receiver costs a bounded number of attempts rather than an unbounded stream of dead letters. Deliveries within a batch run concurrently and are already ordering-disjoint, so one slow receiver does not serialise the others. |
| **A3** | **G2** | **Steering the transmitter with the response body.** §2.3 gives the receiver a JSON object the transmitter acts on; a receiver could try to put a credential-looking string, a terminal escape or a megabyte of text into an operator's screen — or claim `invalid_key` to make the transmitter roll its signing keys. | The body is read to a bound and parsed by one total parser (`push::ReceiverError::parse`, fuzzed) that maps `err` onto §2.3's closed set and reduces `description` to bounded, control-character-free text. `invalid_key` records a *hint* in the audit trail and nothing else: no key is rotated, refreshed or withdrawn on a receiver's say-so, because that would be a denial of service by 400. |
| **A5** | **G1** | **Signals leaving the building with no record.** | Every accepted SET is `ssf.set_pushed`, every §2.3 refusal is `ssf.push_refused` with the code and the key-refresh hint, and a stream that stops is `ssf.stream_paused` with its reason. The stream row also counts deliveries and failures, which is what a console shows per stream beside the queue depth. |

**A choice RFC 8935 leaves open, made here: a refusal pauses the stream.**
§2.4 bounds the retries of *one* SET and says nothing about the tenth in a row.
A transmitter that keeps posting to an endpoint that has answered 400 all
morning is manufacturing dead letters, so the first non-retryable refusal — and
the last retry of a receiver that never recovered — stops the stream and
records why. Events go on being queued: §8.1.2 makes `paused` a state a stream
is expected to leave, and nothing here ever writes `disabled`.

**Residual, stated rather than closed:** nothing queues a SET yet (the emitters
are `ast-0ju.8`), so this path is exercised by its tests and by nothing else in
a running deployment; a paused stream's backlog dead-letters as each row spends
its own budget rather than waiting for the stream to be resumed; resuming a
paused stream is the receiver's own `POST` at the status endpoint
(`ast-0ju.4`, §8.1.2.2) or an operator's `UPDATE` until the console screen
lands; and the push deliverer cannot be tested against a real
socket, because the SSRF guard refuses every address a test could bind — the
fake receiver sits at the transport port instead, and what the socket itself
does is tested in `outbound::post`.

### SSF event emitters (`ast-0ju.8`)

**Why this needs a section: a security signal about a person now leaves this
server unbidden, and the identifier in it is the one thing that must be right.**
A session revoked, a passkey added, an account disabled — each maps to a CAEP
or RISC Security Event Token and is queued for every stream that subscribed
(`crates/server/src/ssf.rs`). The delivery is the previous two sections'
(`ast-0ju.6` push, `ast-0ju.7` poll) and adds nothing; what is new is the
*minting*, and it meets the same problem the back-channel logout token does one
section down, plus one of its own — a SET is about a subject who is not present.

| Attacker | Goal | Attack it enables | Control |
|---|---|---|---|
| **A1** | **G1** | **Handing a receiver a correlation handle it never had.** A SET's `sub_id` names a person; a public `sub`, or one from another sector, sent to a pairwise receiver would join that receiver's logs to everyone else's in a back channel the user never sees. | `SsfTransmitter` derives the `sub` per receiver through `SubjectResolver` under that receiver's own sector (OIDC Core §8.1) — the same value it saw in its ID token — so a receiver is told the identifier it already holds and no other. A session's `sid` is an `opaque` identifier, not a `sub`, and is not derived. The one place this decision lives is unit-tested against a resolver that stamps the sector into the subject. |
| **A1** | **G1** | **A signal that says more than the event allows.** A CAEP event value a receiver dispatches on — `credential_type`, `change_type`, `initiating_entity`, `change_direction`, RISC's `reason` — spelled wrong, or a free-text `reason_admin` carrying a log-injection newline or an unbounded blob. | Every dispatched value is a closed Rust enum in `asterius_ssf::caep`; there is no constructor taking a string for any of them. Every free-text member goes through one validator (`caep::text`, fuzzed) that refuses empty, over-length and control-character values, and the whole SET is bounded at `MAX_SET_CLAIMS_BYTES`. `event_timestamp` is structurally present — the builder cannot render a SET without it — so a receiver always has the instant the event happened, not just the `iat` of a retried token. |
| **A1** | **G1** | **Cross-token confusion.** A SET read where an ID token is expected, or the reverse. | The token is signed `typ: secevent+jwt` (SSF 1.0 §4.1.1), a constant this crate never parameterises; it carries no `sub` (§4.1.2) and no `exp` (§4.1.7), and its `sub_id` (§3.1) is structural — a SET without one does not typecheck. The whole envelope is `ast-0ju.2`'s and unchanged here. |
| **A5** | **G2** | **A signal lost to a crash between the effect and the queue.** The SET is queued *after* the session is revoked, not in the same transaction. | Deliberate, and the same trade the back-channel logout token makes below: revoking is the session repository's statement, and the other order would announce a session that is still live. A crash under-notifies — a receiver is not told — rather than lying. The poll SETs of one cause share one transaction so a stream's backlog never gains half a cause, and every SET of one cause shares one `txn` (§4.1.9) so an operator sees them as one thing. |

**Residual, stated rather than closed:** the console self-service paths do not
emit yet — a passkey a user adds themselves (CAEP `credential-change` create),
an RP-initiated logout, and a step-up (`assurance-level-change`) are recorded in
the audit trail but not yet turned into SETs, because wiring the transmitter
into those handlers threads a new dependency through the request context and its
fixtures; the emitters and their goldens exist and the admin-API paths (session
revoke, account disable/enable, admin passkey removal, forced password reset)
are wired. Grant revocation has no CAEP event type and stays audit-only, by the
spec. And, as one section up, a paused or deleted stream's already-queued SETs
follow that section's rules.

### SSF stream status and subjects (`ast-0ju.4`)

**Why this needs a section: the add-subject endpoint answers the question
"does this person have an account here", and the status endpoint decides
whether a tenant's security signals are delivered at all.** Stream
configuration arranges a subscription and poll delivery hands the signals over;
this pair decides *whose* signals those are and *whether* they move. Three new
things exist because of it: two request bodies this server parses (§8.1.2.2,
§8.1.3.2), a table of subject identifiers held for third parties
(`ssf_stream_subjects`), and a status column the enqueue guard and the poll
read both obey.

**The frontier: the stream is read under the receiver's `client_id`, the
subject is never confirmed or denied.** Every statement a receiver can reach
goes through `(tenant, client_id, stream_id)` — the same `WHERE` clause the
management API uses — so another receiver's stream is a stream that does not
come back. About a *subject*, by contrast, the endpoint says nothing at all:
SSF 1.0 §9.1 recommends answering 200 or 204 whether or not the transmitter
recognises it, and that is what this does, byte for byte.

| Attacker | Goal | Attack it enables | Control |
|---|---|---|---|
| **A1** | **G1** | **Probing for accounts.** A receiver walks a list of email addresses through `subjects:add`, reading the difference between "added" and "no such subject" as a membership oracle for the tenant's directory. | The response is identical either way — same status, same headers, same empty body — and both paths make the same directory lookup, so there is no difference in work either. What differs is invisible: an address that belongs to nobody here is answered for and *not* recorded, because no event will ever be about it and a row naming a stranger is a personal identifier kept for no purpose. The remaining channel is volume, and it is bounded: `LimitedEndpoint::SsfSubjects`, per address *and* per authenticated receiver, answering 429 with `Retry-After`. |
| **A1** | **G1** | **Subscribing to somebody else's users.** A receiver adds subjects it was never given — the whole directory, one identifier at a time — and waits for the events to arrive. | Adding a subject creates a membership, not an entitlement to it: the subject a receiver adds is matched against the events this tenant emits (§8.1.3.1), and a receiver only ever learns an identifier it was already given. `verified` is parsed and grants nothing: an assertion by the caller cannot decide what the caller receives. The membership is bounded per stream (`MAX_SUBJECTS`), so the table cannot be used as storage. |
| **A1** | **G2** | **Silencing a stream.** A receiver — or anything holding its token — pauses or disables the stream so that a revocation never reaches the security team relying on it. | This is a receiver silencing *its own* stream, which it may already do by deleting it (§8.1.1.5); the token is audienced at the status endpoint and sender-constrained like every other SSF call. What the design adds is that it cannot be silent: every change is `ssf.stream_status_changed` in the trail, with the receiver as the actor and the reason it gave, and `status_changed_at` says how long a stream has been stopped. |
| **A3** | **G3** | **Filling the database through a paused stream.** A receiver pauses a stream and lets the tenant's events pile up in the queue behind it for ever. | "SHOULD hold" is bounded: `MAX_HELD_WHILE_PAUSED` events per stream, after which the *newest* is dropped rather than the oldest — so the held prefix stays an ordered, truthful record of what happened after the pause — and the drop is reported to the emitter rather than silent. A `disabled` stream holds nothing at all, which is §8.1.2's own rule. |
| **A5** | **G1** | **Changing who is watched, and leaving no trace.** | Every membership change is an audit event (`ssf.subject_added`, `ssf.subject_removed`) with the receiver as the actor, the stream as a fingerprint, and — for an add — whether the request was recorded, which is the only way to tell §9.1's two identical answers apart afterwards. The subject identifier itself is deliberately *not* in the entry: it is the personal data the endpoint exists to be careful with, and an operator reads the stream's membership instead. |

**A choice §9.1 leaves open, made here: an identifier this server cannot
resolve is recorded.** An `email` and an `iss_sub` naming this issuer are
questions the directory can answer — the second through `subject_identifiers`,
so a pairwise `sub` resolves as well as a public one. An `opaque` identifier, a
`uri` or a complex subject naming a session is not: "we hold nobody by that
name" and "we cannot answer that question" are different facts, and treating
the second as the first would silently drop a legitimate subscription.
Recording them leaks nothing, because the response did not change; what it
costs is a bounded number of rows naming identifiers no event will match.

**Residual, stated rather than closed:** nothing emits an event yet
(`ast-0ju.8`), so a membership is today a subscription to a stream that is
correct, tested and permanently empty; the status of a stream is not yet
something *this server* changes on its own, so §8.1.1's `inactivity_timeout`
still leads to no automatic pause; the stream-updated event that announces a
pause is the section below.

### SSF verification and stream-updated events (`ast-0ju.5`)

**Why this needs a section: a receiver can now make this server sign a token
on demand, and this server now tells a receiver when it stops delivering.**
§8.1.4.2 adds an endpoint whose whole effect is "mint a signed SET and queue
it", which is a signing oracle unless it is rated; §8.1.5 adds a SET this
server sends *about the stream itself*, which is the one signal a receiver
must get even when it has subscribed to nothing.

**The frontier: both SETs are about a stream, never about a person.** The
`sub_id` of each is the stream as an `opaque` identifier (§8.1.4, §8.1.5), so
no subject is derived, no receiver sector is consulted, and neither event can
carry a personal identifier to anybody. That is also why both bypass
`events_requested` and the subject membership without widening anything: there
is nothing in them a receiver was not already entitled to know.

| Attacker | Goal | Attack it enables | Control |
|---|---|---|---|
| **A1**, **A3** | **G3** | **Verification as a signing oracle.** A receiver posts to the verification endpoint in a loop, making the tenant's key sign a token per request and filling the stream's queue. | §8.1.4.2's `min_verification_interval` is enforced per *stream*, in one `UPDATE` that both checks and records the instant (`PgSsfStreams::claim_verification`), so two concurrent requests cannot both be admitted — and the interval is claimed **before** anything is signed, so a refused request costs a statement rather than a signature. Over the interval the answer is 429 with `Retry-After`. The column survives a restart, which a window in process memory would not. |
| **A1** | **G1** | **Verifying somebody else's stream.** A receiver names another receiver's `stream_id` to learn that it exists, or to make this server post to it. | The `client_id` is in the `WHERE` clause of the claiming statement, so another receiver's stream is not a row it can reach: the answer is 404, the same as for a stream that never existed, and nothing is written. The token is audienced at the verification endpoint itself and sender-constrained like every other management call. |
| **A1** | **G1** | **`state` as an injection into a signed token.** The `state` a receiver sends is echoed verbatim into a SET a third party parses and logs. | `VerificationRequest::parse` is the only way in, fuzzed (`ssf_verification_request`) on top of `ssf_verification_state`: bounded to 256 characters, refused on a control character, refused before anything is queued, and every refusal names the rule without echoing the value. The trail records *whether* a `state` was given, never which — it is the receiver's correlation value. |
| **A2** | **G2** | **A silent stop.** The transmitter pauses a stream — an operator in the console, or the delivery worker after a receiver has spent its retries — and the receiver keeps assuming it is being told about revocations that are in fact piling up. | §8.1.5's event is queued **before** the status change takes effect, in both paths, so it is enqueued while the stream still accepts events; a re-enable announces after the write, so the announcement leaves rather than joining the backlog it ends. Neither announcement is filtered by `events_requested`. An announcement that cannot be queued is logged and never blocks the pause: a receiver that cannot be told is usually the reason the stream is stopping. |
| **A5** | **G1** | **Verifying a stream and leaving no trace.** | Each admitted request is `ssf.verification_requested` with the receiver as the actor and the stream as a fingerprint, the same event the console's route writes — so an operator reading the trail cannot tell a flood apart from a schedule only by who asked, which is the distinction that matters. |

**Residual, stated rather than closed:** a stream-updated event announcing a
*pause* is queued, then held by the pause it announces (§8.1.2's "SHOULD
hold"), so a receiver that polls learns of the pause when the stream is
enabled again rather than at the moment it stops. Delivering it ahead of the
pause would mean a synchronous push from a status change, which is the
coupling `ast-0ju.6` exists to avoid; the honest reading is that a paused
stream's receiver learns from its own verification request (§8.1.4.2), which
is what that endpoint is for. A receiver-initiated status change (§8.1.2.2)
emits nothing: the receiver already knows what it just asked for, and §8.1.5's
MUST is about the transmitter's own decisions.

### AuthZEN policy engine and its rules (`ast-pj0.4`)

**Why this needs a section: a tenant's administrator now writes something the
server evaluates on every authorization question, and the evaluation happens in
the process that holds every tenant's signing keys.** [ADR-0011] chose a
declarative rule model over Cedar and over an external OPA, and the choice is a
security one as much as a product one: whatever an administrator writes here
has to be *data*, because anything else is a tenant running code in a shared
process.

**The frontier: rules are data, and the vocabulary is closed.** A document is
`asterius_domain::policy::RuleSet::parse` or it is a 400 naming the path that
failed. The condition set is eight named forms and nothing else — no
arithmetic, no string manipulation, no loops, no reference to a second request
— so there is no expression whose cost is a function of what a tenant wrote.
Every bound (128 rules, 64 condition nodes per rule, depth 8, 256-byte strings,
a 64 KiB document) is applied at parse time, which is what lets
`RuleSet::evaluate` be total: it returns a decision for every input and has no
error path at all, so no authorization outcome is ever produced by a failure.
The parser and the evaluator each have a fuzz target (`policy_document`,
`policy_evaluation`).

**The second frontier: a PEP asks questions, it does not state facts.**
Authorization API 1.0 §5 lets a PEP send `properties` on the subject, the
action and the resource, and this server takes them as exactly that — the
requester's own description of what it is protecting. The facts that decide
*authority* are resolved here and carried in fields a request cannot reach:
`Subject::groups`, `Subject::roles` (`ast-095`), `Subject::grants`
(`ast-uwv.2`, filtered to `GrantStatus::Active` by `ActiveGrant::of`) and the
session's `acr` with the tenant's ladder. A rule written over `group`, `role`,
`grant` or `acr_at_least` therefore cannot be satisfied by anything a PEP
says; one written over `attribute` can be, and that is the tenant's own
decision about a PEP it chose to trust. `policy_evaluation` asserts the split
by feeding an arbitrary request to a catalogue with those facts empty.

| Attacker | Goal | Attack it enables | Control |
|---|---|---|---|
| **A1** | **G1** | **Claiming an attribute that decides authority.** A PEP sends `subject.properties.groups = ["finance"]`, or a `context.acr` of its choosing, and is permitted what the tenant reserved for its finance group. | Group, role, grant and `acr` are separate fields on the resolved request with no constructor that reads a request body, and the conditions that read them read nothing else. `acr_at_least` is a rank comparison against the tenant's ladder (`AcrPolicy`), and a value off the ladder is *false* rather than an error — so a PEP naming a context this tenant does not publish satisfies nothing. |
| **A1** | **G1** | **Overturning a deny with an appended permit.** A tenant's operator, or somebody who reached the admin API, adds an exception below a rule that withdraws access. | Explicit deny wins over permit whatever the order (`RuleSet::evaluate` scans every rule, and the first matching deny is the decision). A request matching nothing is denied, and a tenant with no document denies everything — so the failure modes of "empty", "unparseable" and "not yet written" all point the same way. |
| **A1**, **A3** | **G3** | **A tenant's document as a denial of service against the deployment.** A rule catalogue that costs seconds to evaluate, or that recurses until the stack ends, would take the process down for every tenant. | The condition set has no construct whose cost is not linear in the document, and the document is bounded at parse time. Nesting depth is checked *as the parser descends*, so the evaluator's recursion is bounded by a constant of the code rather than by the input, and a 64 KiB body limit sits in front of it at the admin API. |
| **A2**, **A5** | **G2** | **Reading the tenant's authorization model with an unrelated scope.** | `admin.policies:read` and `admin.policies:write` are their own scopes, deliberately not the tenant-settings ones: "may read the tenant's lifetimes" must not be "may read which of its people reach which of its resources". `security_auditor` holds the read by definition (`Role::grants`) and no write; every edit, including a clearing, is one `policy.updated` record naming the operator and the rule count. |
| **A1** | **G1** | **Reading the policy out of the refusals.** A caller probes the endpoint and reconstructs the rule catalogue — the groups that exist, the attributes that matter — from what each denial says. | The decision context carries two reasons and they are not the same thing (§5.5.1). `reason_admin` may name the rule and is for whoever administers the policy; `reason_user` is a sentence *the administrator wrote*, never derived from the request or from the rule that fired, and a default deny carries none at all. Nothing the engine emits is composed from the caller's own input, which `policy_evaluation` asserts by comparing every decision's explanation against the rule that produced it. |

| **A2**, **A5** | **G2** | **The console's test bench as a policy oracle.** `POST /admin/api/v1/policies/try` (`ast-f7m.9`) answers "what would this tenant's rules decide" for anybody with an admin session, so a stolen one can enumerate the catalogue's behaviour without reading it. | It declares `admin.policies:read`, which is the scope for *reading the document in full* — an oracle over a catalogue the same caller may `GET` verbatim adds no authority. The facts are resolved server-side exactly as the PDP resolves them, so no body can assert a group, a role, a grant or an `acr` and no answer describes a subject the caller could not already look up. It is a probe: CSRF-checked like a mutation, on the admin API's own limiter rather than `LimitedEndpoint::AccessEvaluation`, so a bench cannot spend an enforcement point's budget; and it writes no `access.evaluated` record, because nothing enforced its answer — the edits stay audited as `policy.updated`. |

**A document the server cannot read is a failure, not a subset.** A stored
policy that this build refuses — a `version` from a newer schema, a condition
it does not know — fails the read with `DomainError::Invalid` rather than being
evaluated as the rules it happened to understand. The alternative is the one
failure nobody would notice: a policy whose *deny* rules disappear in an
upgrade looks exactly like a deployment that works.

**Residual, stated rather than closed:** `reason_user` is free text an
administrator writes, and this server cannot tell a helpful sentence from a
disclosure — a tenant that writes "you are not in the finance group" has told
every refused caller that the group exists. The bound on it is length and
control characters, not meaning. The console editor (`ast-f7m.9`) is where a
warning belongs. Nothing in this story is reachable without an admin
credential: the evaluation endpoint is the section below, and every other
route into the engine is the admin API.

[ADR-0011]: adr/0011-a-declarative-rule-model-for-the-built-in-pdp.md

### The Access Evaluation endpoints (`ast-pj0.1`, `ast-pj0.2`)

**Why this needs a section: `POST /access/v1/evaluation` is the first route by
which somebody outside the admin API can make this server walk a tenant's
authorization model, once per API call their application serves.** Everything
in the section above is about what a rule may say; this is about who may ask,
how often, and what an answer discloses.

**Who may ask.** Authorization API 1.0 §11.2 says only that the PDP *SHOULD*
authenticate the PEP. This endpoint applies the same five checks the Grant
Management API does, from the same functions: the access token verifies against
the keys `/jwks` publishes; the caller proves it holds it (DPoP, RFC 9449 §7.1,
over this method and this URL, or a certificate under RFC 8705 §3); `aud` is
*this tenant's* evaluation endpoint, built from the same registry entry the
metadata advertises, so a PEP's token for a business API is not one the PDP
answers; the `jti` is not denylisted and the token post-dates every withdrawal
of its principal; and it carries `authzen.evaluate`. Nothing is parsed and no
policy is loaded before all five pass.

**What an answer says.** A decision is 200 whatever it decided (§10.1.2), and a
decision this server could not take is *also* 200 with `decision: false` and an
`error` in the context — fail closed. The alternative, a 500, hands the PEP a
condition it has no rule for and invites it to invent one; the two it would
invent are "fail open" and "let this one through". The audit record is what
tells an operator the difference between a tightened policy and an unreachable
replica.

| Attacker | Goal | Attack it enables | Control |
|---|---|---|---|
| **A1** | **G1** | **Asking about somebody else.** A PEP holding a valid token asks for decisions about every subject in the tenant, learning who is in which group from which requests are permitted. | The answer is a boolean about the subject *the PEP named*, and nothing in it enumerates: a deny carries only `reason_user`, which an administrator wrote, and a rule id. What bounds the probing is volume — `LimitedEndpoint::AccessEvaluation`, both buckets, charged to the authenticated PEP after the credential checks — and the fact that every request is one `access.evaluated` record naming the PEP, so a client walking a directory is visible in the trail rather than in an alert nobody set up. |
| **A1** | **G1** | **Asserting the facts that decide.** The request claims `subject.properties.groups`, a role, an active grant or an `acr`. | The parser produces a subject with those fields *empty* (`authzen_request` asserts it on arbitrary input), and the endpoint fills them from this tenant's own rows keyed by the `sub` the PEP named. A PEP can influence `attribute` conditions and nothing else. |
| **A3** | **G3** | **Spending the PDP's CPU.** A megabyte of nested JSON, or an evaluation per packet. | 64 KiB and 16 levels, checked on the body before the members are read; the per-property bounds of the engine behind them; and the endpoint limiter in front of the policy load. A request that fails the credential checks costs no policy walk at all. |
| **A1**, **A4** | **G2** | **Reading a decision out of a shared cache, or out of the trail.** | Every response is `no-store`. The trail records a *summary* — subject type, action, resource type, the rule and the latency — with the subject's and the resource's identifiers fingerprinted (an AuthZEN `id` is routinely an email address) and the PEP's `properties` not recorded at all: they are one application's data, arriving once per API call, and this table is kept for years. |
| **A3** | **G3** | **Boxcarring for amplification.** §7's `evaluations` array turns one request — one rate-limiter token — into N policy walks, and §7.1.1's defaults make a hundred of them cheap to write. | The array is capped at `MAX_EVALUATIONS` (100, a constant and not a setting, so the limiter's budget cannot be silently divided by a config change), the evaluations are decided `MAX_CONCURRENT` (8) at a time so one request cannot own the connection pool, and the subject each one names is resolved once per distinct subject rather than once per item. The amplification a PEP can buy with one token is therefore bounded and known: 100 policy reads, 8 in flight. A short circuit (§7.1.2.1) stops evaluating at the decision that settled the answer, so it costs less, never more. |
| **A4** | **G2** | **Hiding a refusal in a crowd.** A boxcar's decisions are recorded as one `access.evaluated` entry, so a deny among ninety-nine permits could pass unnoticed. | The entry's outcome is `Failure` unless *every* decided evaluation permitted, and it carries the semantic and the counts (asked, decided, permits, denies, failures): an operator filtering for refusals still finds the request. What the entry does not carry is the array's individual resources — the same trade the single endpoint makes with `properties`, and the PEP is the party that chose the list. |
| **A1** | **G3** | **Poisoning a correlation header.** §10.1.3 requires the PDP to echo the caller's `X-Request-ID`, which is a caller-chosen string on a response header. | The echoed value is bounded at 128 bytes and must be a valid header value, or it is dropped. It is deliberately *not* the identifier the audit trail records: that one is this server's own, drawn from the CSPRNG, so a caller cannot collide with another caller's entries. |

**Residual, stated rather than closed:** the `acr` a rule reads is taken from
the authentications recorded on the subject's live grants — the weakest of
them — because this endpoint is given no session to read. A step-up rule
(`acr_at_least`) therefore reasons about what the subject's standing
authorizations were proved with, not about a browser session that may have been
strengthened since. That is the conservative direction, and it is the reason
`ast-lh3.10`'s pre-issuance port, which *does* hold the authentication it is
about, is the better home for a step-up decision.

### The Search APIs (`ast-pj0.6`)

**Why this needs a section: an evaluation answers a question about an entity
the caller already named; a search hands the caller the entities.** Everything
the section above says about who may ask applies unchanged — the same five
credential checks, the same `authzen.evaluate` scope, the same
`LimitedEndpoint::AccessEvaluation` budget, with the audience narrowed to the
URL of the search that was called (§9.1.1 makes each one its own endpoint). The
new exposure is the *shape* of the answer, and it is deliberate: §8 exists to
let a PEP render a list.

**Off unless asked for.** `[authzen] search` is false by default and derives
`Feature::AuthzenSearch`, which gates the routes and the metadata members
together; a tenant that switched AuthZEN off loses the searches with it. A
deployment whose PEPs never need a list does not serve one.

**Enumeration is the feature, and the scope is the control.** A subject search
returns the subject identifiers of this tenant's accounts that a policy admits.
That is a disclosure, and it is the same one a patient PEP could already have
assembled one evaluation at a time — every candidate is put through the
ordinary evaluator with facts resolved from this server's rows, so a search
never returns an access the same credential could not have confirmed by
evaluating. What it changes is the *cost* of doing so, which is why the answer
is capped at a page, charged to the evaluation budget and recorded as its own
event type.

| Attacker | Goal | Attack it enables | Control |
|---|---|---|---|
| **A1** | **G1** | **Walking a tenant's directory.** A PEP whose credential leaked enumerates every account, then every action each of them may take. | The credential is a DPoP-bound token carrying `authzen.evaluate` and audienced at this endpoint; the page is capped at `MAX_PAGE` (100, the same number §7's boxcar is bounded at) and charged one token per request to the shared PDP budget; and every request is one `access.searched` record naming the PEP, which is a *different event type* from an evaluation precisely so that "who listed this tenant" is a filter rather than a scan of detail maps. The entities returned are not written to the trail: the shape of the disclosure is recorded, not a second copy of the directory. |
| **A1** | **G1** | **Reading a policy by probing.** A caller varies the fixed entities to learn which rules exist. | A search answers only with entities that *permit*; there is no `context` on a successful search, so nothing reports why a candidate was dropped. A denied candidate is indistinguishable from one that was never a candidate. |
| **A3** | **G3** | **Buying an unbounded walk.** `page.limit` of a million, or a search of a tenant with a hundred thousand accounts. | `limit` is clamped to `MAX_PAGE` and refused if it is not a count; candidates are produced *by the page* — the directory is walked with a cursor and a limit, the finite sets are sliced before anything is evaluated — so the work of one request is one page of evaluations whatever the tenant holds. |
| **A1** | **G1** | **Forging or replaying a page token to reach another query's results.** | The token carries a digest of the query it was minted for, and a token presented against a request that differs outside `page` is a 400 (§8.2's "identical parameters"). It carries no authority of its own: the page it names is still authenticated by the caller's own token and every entity in it is evaluated at that instant, so a forged token reaches exactly what asking for the first page reaches. That is why the binding is a digest rather than a MAC — a MAC would mean a new symmetric secret shared across every replica, held for a property that grants nothing. |
| **A4** | **G2** | **Mistaking an outage for an empty tenant.** A PEP renders "nobody may do this" because the policy store was unreachable. | A search that could not be performed answers an empty `results` *with* an `error` context (status 500), the same shape a fail-closed evaluation carries, and is recorded as a `Failure`. A candidate that could not be decided is dropped from the page and counted in the record. |

**Residual, stated rather than closed.** A resource search is **not** a
catalogue: this server holds no table of a tenant's documents, so §8.5 answers
with the identifiers the rules name literally and the ones the subject's live
authorizations name, and nothing else. A PEP that treated the answer as
complete would under-report access rather than over-report it — the safe
direction — but it would be wrong, and the endpoint's module documentation says
so where an integrator reads it. Clients and agents are not enumerable as
subjects for the same kind of reason: the rule language has no notion of a
client as a principal.

### PDP metadata (`ast-pj0.3`)

**The PDP identifier is the tenant issuer; the token audience is the endpoint
URL.** `/.well-known/authzen-configuration` publishes both, and they are
deliberately not the same string. Authorization API 1.0 §9.2.3 has a PEP
compare `policy_decision_point` against the identifier it derived the URL from,
which is the tenant issuer — the one identity a tenant has here, shared with
`iss` and with the SSF transmitter document. The credential check at
`ast-pj0.1` stays narrower: `aud` must be `access_evaluation_endpoint`, so a
PEP's token cannot be replayed at another endpoint of the same tenant. The
document is what tells a PEP which of the two to ask its authorization server
for, and both values come from the endpoint registry rather than from a
configuration key, so neither can be pointed somewhere else by an operator or
drift from the route that answers.

**The document is public, and says only what is mounted.** It is served behind
`Feature::Authzen`, deployment-wide and per tenant, so a tenant that runs no
PDP answers 404 rather than publishing an evaluation endpoint somebody could
start sending subjects to. The three `search_*` members appear only where
`[authzen] search` is on — `Feature::AuthzenSearch`, which is also what mounts
the routes — and no `capabilities` array is emitted, on the same rule: a member
here is a promise a PEP acts on without being able to check it.

**`signed_metadata` (§9.1.3) is off unless asked for.** With `[authzen]
signed_metadata` on, the document carries a JWT signed by the tenant's active
key, typed `authzen-metadata+jwt` so a verifier with a loose policy cannot take
it for an access token, carrying `iss` and no `exp`. It adds integrity for a
copy that outlives the TLS connection it arrived on; it adds no confidentiality
— the document is public — and it costs one signature per request, which is
why it is a key rather than the default. A tenant with no active key serves the
document unsigned and logs, rather than failing: an unsigned public document is
the state every PEP already handles.

### Back-channel logout (`ast-o4u.2`)

**Why this needs a section: the server now signs a JWT it sends to somebody
else's endpoint, and that JWT is not a credential.** Everything else this
server signs is presented back to it or to a resource server by the party that
was given it. A logout token is pushed, unsolicited, to a URL a client
registered — so the questions are what it says about a person, what else it
could be mistaken for, and what happens when the endpoint is hostile.

The delivery itself adds nothing new: it is the outbox's HTTP deliverer and
therefore ADR-0006's one outbound path, with the section above's guard,
timeout, size bound and refusal of every 3xx. What is new is the token.

| Attacker | Goal | Attack it enables | Control |
|---|---|---|---|
| **A1** | **G1** | **Cross-JWT confusion.** A relying party is fed a logout token where it expects an ID token — or the reverse — so that "this session ended" is read as "this person is signed in". | The token is signed with `typ: logout+jwt` (Back-Channel Logout §2.4, §4.1, RFC 8725 §3.11), a constant this crate never takes as a parameter, and its claim set is built from a fixed list of names. It cannot carry a `nonce` — §2.4's MUST NOT, the claim an RP's authentication path binds to — and it carries none of `at_hash`, `acr`, `amr` or `auth_time`. A test asserts on the whole rendered claim list rather than on `nonce` alone, because a token that grew an ID token's claims would be an ID token in all but `typ`. |
| **A1** | **G1** | **Correlating a person across relying parties.** Every RP taking part in one session receives a token at the same instant; a `sub` common to all of them would join their logs. | The `sub` is resolved per client through `SubjectResolver`, so a pairwise client receives the identifier from *its own* sector and never the local user id — the same value it was issued in its ID token (OIDC Core §8.1). A pairwise client that registered `backchannel_logout_session_required` receives `sid` and no `sub` at all, which §2.4 permits and which is the minimum that identifies the session. |
| **A1** | **G2** | **Replaying a captured logout token.** A token taken off the wire, or read from a dead-letter row, is posted again to log the session out later — or at an RP that has since started a new session for the same person. | `exp` is capped at two minutes, `jti` carries 128 bits from the OS CSPRNG for the deduplication §2.6 step 11 allows, `aud` is the one client the token was minted for, and `sid` names the session that ended rather than "this person". A retry that outlives the expiry delivers a token the receiver refuses, which is the honest outcome: an RP unreachable for two minutes needs a fresh statement, not a stale one it cannot tell from a replay. |
| **A1**, **A3** | **G3** | **Using the registered endpoint as an SSRF or amplification target.** | `backchannel_logout_uri` passes the same admissibility gate as an authorization callback — `https`, no fragment, no userinfo, no re-spelling — at registration, *and* the schema constrains the column, *and* the delivery goes through `outbound::post`. The `native` loopback exception is deliberately not extended to this member: an RP whose back end is `127.0.0.1` is this deployment's own loopback. |
| **A3** | **G3** | **Stalling the whole logout by refusing to answer.** | The browser is never held for a delivery. The end-session handler queues rows and returns; the worker delivers, retries 5xx and timeouts on the backoff schedule, gives up immediately on a 4xx (§2.5's "retransmit only on potentially recoverable errors"), and dead-letters what never lands. One wedged receiver holds its own `(session, client)` ordering key and nobody else's. |

**Residual, stated rather than closed:** the outbox row is written *after* the
session is revoked, not in the same transaction — revoking a session is the
session repository's statement, not the outbox's. A crash between the two
leaves a session that is ended and relying parties that were not told, which
is a logout that under-notifies. The other order would announce a session that
is still live, and that is worse. `revoke_refresh_on_logout` is off by default,
so on a deployment that has not turned it on a relying party holding a refresh
token can still mint an access token after the browser session has ended; that
is a grant surviving a session, which is what a grant is, and the setting is
there for the deployments that mean otherwise.

### Backchannel authentication requests (CIBA, `ast-lh3.4`, `ast-lh3.5`)

**Why this needs a section: a hint resolves a person without that person being
present.** Every other flow in this server starts with a user at a browser.
`POST /bc-authorize` starts with an authenticated client asserting an identity
— an address, a username, an ID token — and this server turning it into an
account and a pending approval. The person's first involvement is a
notification they did not ask for.

| Attacker | Goal | Attack it enables | Control |
|---|---|---|---|
| **A1** | **G1** | **Asking about somebody else.** A client sends a `login_hint` naming a person it has no relationship with, and an approval lands on their device. | The request is *pending* and produces nothing on its own: no token, no session, no claim. It is answered only by the person, in the approvals inbox (`ast-lh3.6`), where the client and the scopes are named. The row records which client asked about whom (`backchannel.requested`), so an unexpected approval is traceable to a client rather than to a hint somebody typed. |
| **A1** | **G2** | **Approval fatigue: repeating the request until it is approved by reflex.** | `expires_in` is five minutes at most and a `requested_expiry` may only shorten it, so an unanswered request stops being answerable quickly rather than accumulating on a lock screen. The endpoint is client-authenticated (`private_key_jwt` or mTLS), so every repetition is attributable to a client holding a private key and is one `backchannel.requested` row. It **is** in `LimitedEndpoint` (`ast-5lw`), with three buckets: the address, the authenticated client, and the person the hint resolved to — the last of which is what a repetition actually spends, since a budget spread over a directory is ordinary traffic and the same budget aimed at one account is this attack. Above any of them the answer is a `429` with `Retry-After`, identical whichever bucket was full. Beyond the windows, at most `ciba::MAX_PENDING_PER_USER` (five) requests may be waiting for one person at once; the sixth is refused with `invalid_request` and nothing already waiting is replaced. |
| **A1** | **G1** | **Substituting the transaction between the two screens.** The consumption device shows one payment; the authentication device is asked to approve another. | §7.1's `binding_message` is recorded in the clear and rendered on both. It is at most 64 characters of letters, digits, spaces and hyphens — refused otherwise with `invalid_binding_message` — so a message carrying newlines, bidirectional overrides or combining marks cannot be made to display one way on one screen and another way on the other. |
| **A1** | **G2** | **Reading a `client_notification_token` out of a database copy and forging a §10.2 notification.** | Its digest is stored for comparison, and in ping mode the token and the `auth_req_id` the notification must carry are *also* kept — because a digest cannot be posted — sealed under the tenant's KEK (`0034_ciba_ping_credentials.sql`, `RowSecret::CibaPing`), bound to the tenant and the request's digest so a ciphertext copied over another row does not open, re-sealed by `asterius rewrap-kek`, and opened by the delivery worker for the width of one `POST`. The envelope is required in ping mode and refused in poll mode (schema constraint), so no row holds a credential nothing will ever present. |
| **A1** | **G2** | **Guessing an `auth_req_id` and polling for somebody else's tokens.** | 256 bits from the OS CSPRNG — above §7.3's floor — stored as a digest, and the presented value is shape-checked against §7.3's charset before any query (`ciba::token_request`, fuzzed as `ciba_token_request`). |
| **A1** | **G1, G2** | **Polling with another client's `auth_req_id`** (`ast-lh3.5`). A second authenticated client of the tenant presents a value it obtained from a log or a shared machine, to redeem it or to watch whether the person approved. | §10.1: the OP "MUST check whether the `auth_req_id` was issued to this Client". The store returns the issuing client with *every* state and the handler compares it before the state is read, so a stranger learns `invalid_grant` and nothing more — not pending, not approved, not whose — and the owner's own poll is not judged against the stranger's. The comparison is repeated after the spend, so a bug that approved a row for the wrong client cannot mint for it. |
| **A1** | **G3** | **Hammering the token endpoint with a pending `auth_req_id`.** | §11's `slow_down` raises the row's interval by five seconds, in the same statement that stamps the poll, so two racing polls cannot both escape it; after `ciba::MAX_SLOW_DOWNS` raises a poll inside the interval is `invalid_request` and the client "MUST stop polling". The interval stops at `POLL_CEILING`, so a client cannot be told to wait longer than twenty seconds for a decision. `/token` itself sits behind `ast-p2l.3`'s per-client limit. |
| **A1** | **G2** | **Redeeming an approval twice, or on a request that lost its proof.** | `PgCibaRequestRepository::redeem` checks and spends in one `UPDATE … WHERE redeemed_at IS NULL … RETURNING`, so two token requests carrying one `auth_req_id` cannot both be served (§10.1.1). The DPoP/mTLS confirmation is decided *before* the spend, so a poll that arrived without its proof is refused with the request intact rather than burned — a FAPI 2.0 SP §5.3.2.1 refusal must not cost the client its one redemption. |
| **A1** | **G2** | **Pointing `backchannel_client_notification_endpoint` at something inside the deployment, or at a redirector.** | The ping is queued into the outbox and posted through ADR-0006's one outbound path (`outbound::post`): SSRF guard, pinned trust anchors, no redirects followed (§10.2), five-second total timeout, request and response size caps. The row carries the endpoint and the request's digest; the credentials are opened from the seal at delivery. A 4xx dead-letters at once; anything else is retried on the worker's backoff, and the moment this server gives up is a failed `backchannel.notified` in the trail. |
| **A1** | **G1** | **A ping that arrives twice, or for a request that expired.** | `notified_at` is stamped when the client accepts, and a redelivery after a lost ack finds it and posts nothing. Only the two decisions §10.2 names — approval and refusal — queue a row; expiry queues nothing, and a row whose request retention has since swept is a permanent failure rather than a late notification. |
| **A1** | **G1** | **Driving a request with an ID token issued to another client.** | An `id_token_hint` must verify against *this tenant's* keys and name *this* client in `aud`/`azp` before its `sub` is resolved; the check is `id_token_hint::names_client`, shared with the pushed-request endpoint. A `login_hint_token` (§14) is refused outright: §14 requires the OP to know which issuers it accepts one from, this deployment configures none, and reading an unverified assertion about who somebody is would be the alternative. |
| **A1** | **G2** | **Replaying an assertion minted for another endpoint.** | §7.1 obliges this endpoint to accept three `aud` values where FAPI 2.0 SP §5.3.2.1 item 8 allows one. The widening is `Audiences::ciba_backchannel`, reachable from this handler alone and from no other; the *form* rule is untouched, so `aud` is a string and never an array, and an assertion naming this server and somebody else is still refused. |

**Residual, stated rather than closed — the `unknown_user_id` oracle.** §13
requires this endpoint to answer `unknown_user_id` when a hint resolves to
nobody, which makes it an existence oracle: a client can learn whether an
address has an account here. We keep the specified code rather than
collapsing it into `access_denied`, and the reasoning is that the oracle is
*already* bounded to a party we have identified. Reaching it requires a
registered client holding a private key, with the CIBA grant, on a tenant
with the flag on — and every probe is one `backchannel.refused` row naming
that client — though not yet behind an endpoint rate limit; see the row
above. A client in that position can also enumerate through any of half a
dozen other surfaces. What we would buy
by deviating is a client that cannot tell "wrong address" from "this server
will not ask", which turns every integration mistake into a support ticket;
what we would pay is a documented departure from a Final specification that
a conformance suite tests. If a deployment's threat model puts enumeration
above that, the honest control is a tenant that does not enable CIBA for
clients it does not trust with its user list — not a code that lies.

**Residual — user codes.** §7.1.2's `user_code` is a secret "known only to the
user but verifiable by the OP". This deployment has no per-user code to verify
one against, so `backchannel_user_code_parameter_supported` is `false` in every
document and a presented code is refused with `invalid_user_code` rather than
dropped: a client that sent one believes the person will be challenged, and a
server that silently ignored it would put an unchallenged approval in front of
them.

### Approvals inbox (`ast-lh3.6`)

**Why this needs a section: this is the page where a person gives somebody
else a credential on their account.** `/account/approvals` lists the pending
backchannel requests CIBA Core 1.0 §7.2 resolved to this person and carries RFC
8628 §3.3's code entry beside them. Everything else in the browser tree either
authenticates the person or authorises a client the person navigated to; here
the request arrived from somewhere they cannot see, and the only evidence that
it is theirs is what the page renders.

| Attacker | Goal | Attack it enables | Control |
|---|---|---|---|
| **A1** | **G1** | **Phishing through the `binding_message`.** The string is chosen by the client and rendered large, so it is the obvious place to write "Ignore the amount below" or to spoof another transaction. | It is not free text: at most 64 characters of letters, digits, spaces and hyphens (`ciba::MAX_BINDING_MESSAGE_CHARS`, refused with `invalid_binding_message`), so no newline, bidirectional override or combining mark can make one string display two ways. It is escaped like every other value — askama autoescaping, with `crates/web/src/source_audit.rs` failing the build on a second `\|safe` — and it is rendered as a *comparison*: the page says to check it against the device the flow was started on, which is what §7.1 has it for. The page also states RFC 8628 §5.3's warning plainly: a request you did not start is a request somebody else started. |
| **A1** | **G1, G2** | **Cross-site forgery of a decision.** A page on another origin makes the browser post an approval; the session cookie rides along. | Both forms carry a synchroniser token derived from the session's *digest* — a value the browser never holds, so a cross-site page can cause the cookie to be sent but cannot compute the token — compared in constant time. The decision route is `POST` only and is never reachable by a top-level navigation, which is ADR-0009's rule for first-party state changes. The two forms carry *different* tokens, under different domain separators, so a token lifted from the device form cannot decide an approval. |
| **A1** | **G1** | **Deciding somebody else's request.** The form names a request; a guessed or stolen reference would let one account answer another's. | The reference is the `auth_req_id`'s digest, never the identifier (so a rendering of this page is not a rendering of anything redeemable), and `user_id` is in the predicate of every statement behind the page — the list, the read, and the `UPDATE` that decides. A reference belonging to somebody else is not "refused", it simply matches no row, and the page says the one sentence it says about every request that is not waiting. |
| **A1** | **G1** | **Approving from a session somebody walked away from.** A browser left open, or one an attacker reached hours after the person authenticated. | An approval requires an authentication within `approvals::FRESHNESS` (two minutes). A stale session is not refused with an error: it is sent back through the interaction pages and returns having authenticated, so the approval and the authentication are one act. Refusing needs no freshness — saying no grants nothing, and a person shown a request they did not start must be able to stop it with what they have. |
| **A1** | **G1** | **Approving a request that asked for more than this authentication is worth.** §7.1's `acr_values` is the client's statement about the class it needs. | It is enforced here, at the only moment a person is present: `AcrPolicy::strongest_met` against the session's `amr`, and a session reaching none of the requested classes is told to sign in again with the method that is asked for. On the default ladder that makes `urn:asterius:acr:passkey` answerable by a passkey and by nothing else. A session this tenant cannot classify at all does not reach the page. |
| **A2** | **G1** | **Replaying a decision, or double-clicking one.** | The decision is one `UPDATE … WHERE status = 'pending' AND expires_at > now`, and the §10.2 ping is queued in the same transaction. A second submission moves no row and is answered `409` with the same sentence, so a request cannot be approved twice and a client cannot be pinged twice for one decision. An expired request disappears from the list by the clock rather than by a sweep. |
| **A1** | **G2** | **Reading the inbox out of a cache or a shared browser.** | Every response is `no-store`: the page carries a countdown, a synchroniser token and a list of who is asking about this person. |
| **A2** | **G1, G3** | **Posting decisions in a loop from a session somebody obtained** (`ast-5lw`), to answer everything that arrives before the person sees it, or simply to make this page do work. | The decision form has a budget of its own: `approvals::DECISIONS_PER_WINDOW` (twenty) per `approvals::DECISION_WINDOW` (ten minutes), counted in the same `rate_limits` table every other limiter here uses and keyed by the *session* — not the address, because a household is one address and several approvers. It is charged before the body is read, so a malformed flood costs what a well-formed one does, and a counter that cannot be read refuses rather than admits. Past it the inbox comes back with `429`, `Retry-After` and one sentence; the refusal is audited once per window as `request.throttled`. |

**Residual — approval under coercion.** Nothing on this page distinguishes a
person who approves because they want to from one approving because somebody is
standing over them, and no control here can. What the page does is make the
decision *legible and attributable*: the client is named, the scopes and the
RFC 9396 elements are listed, the binding message is shown for comparison, and
both outcomes are written to the audit trail with the approval's fingerprint
(`approval_id`) and the deciding session, so a coerced approval is visible
afterwards to the person and to an operator. The five-minute ceiling on a
request bounds how long a coerced decision stays possible.

**Residual — the notification is a journal, not a delivery.** The person is
told through `MailSender`, and the adapter this repository ships writes an
outbox row and a log line: nothing arrives in anybody's inbox until an operator
wires a real sender (`docs/configuration.md`). Push notification is out of
scope for `ast-lh3.6`. An account with no address is not notified at all, and
the client is not told so — §7.3's acknowledgement says nothing about the
person, and it must not start saying whether they are reachable.

**Residual — agent scope elevation is not listed.** The bead names three kinds
of pending request; this server has a CIBA row and a device code, and no agent
step-up mechanism to list. When one exists it belongs on this page, under the
same freshness and `acr` rules.

### Grants dashboard (`ast-uwv.6`)

**Why this needs a section: this is the page where a person reads what stands
open in their name, and closes it.** `/account/grants` lists the standing
authorizations Grant Management ID1 §3 says a person must be able to see and
revoke, with the scopes, the RFC 9396 elements, the RFC 8707 resources, the
last use and the delegations minted from each (RFC 8693 §4.1). The button
beside each row makes the same revocation call `DELETE /grants/{id}` makes, in
the same transaction.

| Attacker | Goal | Attack it enables | Control |
|---|---|---|---|
| **A1** | **G2** | **Enumerating grants, or reading somebody else's.** A guessed `grant_id` in the withdrawal form, or a hope that the list is keyed by something a caller supplies. | The list comes from `PgGrantRepository::list_for_user` with the session's account in the predicate and the repository scoped to the tenant; nothing about which rows are listed comes from the request. A withdrawal re-reads the row and compares `grant.user` against the signed-in account before it writes, and a grant belonging to somebody else is answered *exactly* as one that does not exist — §6.6's reasoning, because distinguishing them is an oracle over identifiers this server mints. The shape check (`account_grants::withdrawal`, fuzzed) means an identifier that could never name a row never reaches a query. |
| **A1** | **G3** | **Cross-site forgery of a withdrawal.** A page on another origin makes the browser post a revocation; the session cookie rides along, and somebody's integrations stop working. | The form carries a synchroniser token derived from the session's *digest* — a value the browser never holds — compared in constant time, under a domain separator of this page's own, so a token lifted from the approvals inbox or the device form is not one this endpoint accepts. The route is `POST` only and unreachable by top-level navigation (ADR-0009). |
| **A1** | **G3** | **Withdrawing from a session somebody walked away from.** A browser left open, or one an attacker reached hours after the person authenticated. | A withdrawal requires an authentication within `account_grants::FRESHNESS` (two minutes), checked before the row is read, so a stale session also learns nothing about whether the id it submitted names anything. It is not refused with an error: it is sent through the interaction pages and comes back, so the authentication and the withdrawal are one act. A session this tenant's ladder cannot classify does not reach the page at all. |
| **A1** | **G2** | **Reading the dashboard out of a cache or a shared browser.** | Every response is `no-store`: the page carries a synchroniser token and a list of every application and agent this person has authorised. |
| **A1** | **G1** | **Misreading who is asking.** Client names and agent identities are chosen at registration. | Every name is rendered as a claim, escaped like any other value (FAPI 2.0 SP §7), and an agent's row names the *account* it acts for, read from the profile's owner rather than from anything the agent said at the token endpoint. `authorization_details` are rendered as the operator's sentence for the type and never as the client's JSON (RFC 9396 §12); an `act` chain entry this server cannot read as an identifier is dropped rather than displayed. |

**Residual — revocation under coercion, and the absent `acr` floor.** A person
withdrawing access under duress is indistinguishable from one doing it freely,
and the reverse case decided the design: this page deliberately does *not*
require the session to reach the `acr` the grant was made at. Such a rule reads
as prudent and fails in one direction only — somebody whose passkey has been
lost or stolen is exactly the person who most needs to withdraw everything and
would be the one locked out of doing it. Revocation is the safe direction, so
the tenant's ladder is applied as admission and freshness as a bound on how
stale a session may be, and nothing else stands between a person and closing
their own door. Every withdrawal is written to the trail as `grant.revoked`
with the deciding session and `reason=account_grants_page`, so one made under
coercion is visible afterwards to the person and to an operator.

**Residual — a withdrawal does not reach a resource server on its own.** An
access token minted from a withdrawn grant is a signed JWT that still verifies;
what refuses it is the cutoff the revocation writes, read on the resource path
(`ast-m9c.13`). A resource server that does not consult this server sees
nothing until the token expires. The transmitter that would tell it is
`ast-0ju.8`, and the seam this page calls is named for whoever builds it.

### Self-service account pages (`ast-1xd`)

**Why this needs a section: these pages move a boundary.** Before them, a
stolen session could read this server's pages and authorise clients; it could
not take the account. `/account/passkeys`, `/account/password` and
`/account/sessions` change that — the same session can now remove the owner's
credential, set a password, and close the sessions they would have noticed it
from. The pages exist because the alternative is worse: until this bead the
person whose passkey was stolen could not remove it, and the person looking at
a session they did not start could not close it, without an administrator.

| Attacker | Goal | Attack it enables | Control |
|---|---|---|---|
| **A1** | **G1** | **Account takeover from a session somebody walked away from.** A browser left open in a café, or one an attacker reached hours after the person authenticated: remove the passkey, set a password, sign the owner out. | Every write requires an authentication within `account::FRESHNESS` (two minutes), the approvals inbox's rule and its mechanism — the stale session is not refused, it is sent through the interaction pages with a `FirstPartyDestination` (never a redirect parameter, ADR-0009) and comes back, so the authentication and the change are one act. Freshness is decided *before* any row is read, so a stale session also learns nothing about whether the identifier it submitted names anything. |
| **A1** | **G1** | **Removing the last way in.** The one step on these pages that cannot be undone: the credential the real owner would use to come back. | Removing the last *usable* passkey needs the account's password as well as the fresh authentication — a different factor from the one a stolen session may have re-presented. An account that has no password cannot remove its last passkey at all: the page offers `/account/password` instead of a button that could only refuse, and the handler refuses it independently, so the rule is not enforced in markup. A blocked credential does not count as a way in, which is the case the rule exists for. |
| **A1** | **G1** | **Changing the password with the session alone.** | An account that has a password must present it. Freshness says somebody authenticated two minutes ago; it does not say *with what*, and a stolen session that re-authenticated with a stolen passkey is fresh. The current password is the second, different thing, and it is the credential being replaced — NIST SP 800-63B §5.1.1.2's change flow. A refusal is audited as a `credential.changed` failure, because somebody trying passwords against that field is somebody trying passwords. |
| **A1** | **G2** | **Enumerating credentials or sessions.** A guessed credential id, or a `sid` obtained from somewhere else — a relying party holds these. | Every statement carries the signed-in account in its predicate, and a row belonging to somebody else is answered *exactly* as one that does not exist: the same sentence, and `404` rather than `403`, because `403` is the answer that says "this exists and is not yours". The shape checks (`account_passkeys::change`, `account_sessions::revocation`, both fuzzed) mean an identifier that could never name a row never reaches a query. |
| **A1** | **G1, G3** | **Cross-site forgery.** A page on another origin makes the browser post a removal or a revocation; the session cookie rides along. | Every form carries a synchroniser token derived from the session's *digest* — a value the browser never holds — compared in constant time, under a separator of each page's own (`account::csrf_for`), so a token lifted from the inbox, the dashboard or another account page is not one this page accepts. Each route is `POST` only and unreachable by a top-level navigation. |
| **A1** | **G3** | **Aiming "close every other session".** A body that named which sessions to close would be a button an attacker can point. | It takes no argument at all: the parser drops a `session` field on that verb, and the server computes the set from the cookie it is holding. The one thing the person is asking for — "everything except this browser" — is the one thing the request can express. |
| **A1** | **G2** | **Reading a page out of a cache or a shared browser.** | Every response is `no-store`: these pages carry a synchroniser token, the list of a person's credentials, and the list of where they are signed in. |
| **A1** | **G1** | **A name that lies.** A passkey label is text its owner types and this page renders back. | Escaped like every other value (askama autoescaping, with `crates/web/src/source_audit.rs` failing the build on a second `\|safe`), bounded at `account_passkeys::MAX_LABEL_CHARS`, and not otherwise sanitised — a parser that stripped characters would be the one place a reviewer later believed the escaping had happened. The trail records *that* a name changed and never what it says. |

**Residual — a closed session is not closed everywhere at once.** Revoking one
queues a back-channel logout token per participating relying party (§2.2) and a
CAEP `session-revoked` per subscribed stream; both are best-effort and after
the revocation, because the session is already over and a receiver that cannot
be reached must not undo it. An application that ignores back-channel logout
and holds an unexpired access token keeps it until the access-token cutoff
reaches it (`ast-m9c.13`).

**Residual — a password change does not end the other sessions unless asked.**
The page says so before it is submitted and offers a box. A voluntary change is
not a recovery: the recovery path ends every session because the person there
may be locked out by somebody who is signed in, and this page has no such
reason to sign somebody out of four devices they are holding. An attacker who
has changed a password has, by then, already had to present the old one or the
last passkey.

**Residual — no user agent and no address on the session list.** "Which of
these is me" is answered by marking the current browser and by the timestamps;
the `sessions` table records neither a user agent nor an address, and a page
cannot show a fact nobody stored. Until it does, a person recognising an
unfamiliar session is relying on when it started and when it was last used.

**Residual — no notification when a passkey is removed.** Setting or changing a
password sends the account's own "this changed" message
(`Notification::credential_changed`); removing a credential does not, because
the adapter this repository ships writes an outbox row and a log line and the
message would be one more thing nobody receives. The audit trail records every
removal with the deciding session.

### Load, and the token endpoint as a denial-of-service surface (`ast-p2l.8`)

**Why this needs a section: FAPI 2.0 SP §6.1 moves the load onto this
server on purpose.** Short-lived access tokens are a security property —
they bound what a stolen token is worth — and their price is that every
client comes back to `/token` once per lifetime. The endpoint that
authenticates a client is therefore also the endpoint an attacker can make
this server work hardest at, and the work is not cheap: two signature
verifications before anything is looked up, two replay inserts, an audit
record under a per-tenant lock. [`docs/performance.md`](performance.md) has
the measured cost (about 430 token responses per second per process on the
machine it names, saturating on CPU); this table has what bounds an attacker
who tries to spend it.

| Attacker | Goal | Attack it enables | Control |
|---|---|---|---|
| **A5** | **G3** | **Signature-verification exhaustion.** An unauthenticated caller posts token requests with well-formed but invalid assertions and proofs, each of which costs an ECDSA or RSA verification before it is refused. | `limits.token_per_address` (120 per minute by default) and `par_per_address` charge every request that does not end in a token to the address it came from, before the assertion is parsed; the bucket lives in the database so every replica sees the same count. The verification itself is bounded: `request_body_limit_bytes` (64 KiB) caps the assertion, and a client's `jwks_uri` is fetched through the cached, rate-limited outbound path rather than per request. |
| **A1** | **G3** | **Spending another client's budget.** A caller names a competitor's `client_id` in requests that fail, to have that client throttled. | A failing request is charged to the address, never to the `client_id` it names; only a *successful* response is charged to the authenticated client (`limits.token_per_client`, 1200 per minute). A client can be throttled only by its own successes. |
| **A5** | **G3** | **Filling a table.** Every accepted PAR stores a row; every accepted token request stores two replay rows and an audit event. | The per-address limits above bound the unauthenticated rate; `retention::POLICY` ages `auth_requests`, `jti_replay`, `rate_limits` and the codes on a stated schedule, and every one of those sweeps seeks on an `*_expiring` index (migration 0032 added the two that did not). The audit trail is append-only by design and grows with legitimate use; it is the one table sizing has to plan for. |
| **A5** | **G3** | **Argon2 exhaustion at sign-in.** A caller posts passwords to the interaction endpoint; each costs an Argon2id verification at 19 MiB and two passes, by design (about 100 ms of one core here). | `[login]` counts failures per address (100 per window) and per typed identifier (10), in the database, and refuses with a retry hint before the hash is computed once a limit is reached. A single address therefore buys at most 100 verifications per window; the cost of a *successful* sign-in is paid by a person who holds the password. |
| **A5** | **G3** | **Tight-loop polling.** An SSF receiver polls with `returnImmediately: true` as fast as it can. | Each poll costs one token verification and one indexed read (measured at 1 000 per second per process, 8 ms p95). The receiver is an authenticated client presenting a DPoP-bound token, so the cost is attributable and the stream can be paused or the client disabled; there is no unauthenticated poll. |
| **A2** | **G3** | **Serialising a tenant on its audit lock.** Every state change writes an audit event under `pg_advisory_xact_lock(hashtext(tenant_id))`, so a tenant's audit writes are serial and their rate is bounded by the database's commit latency. | This is a ceiling, not an exploit: nothing lets a caller hold the lock beyond one insert, and the lock is per tenant so a busy tenant does not slow the others. It is recorded here because it is the number that bounds a single-tenant deployment before the pool or the CPU does, and a capacity plan that does not know it will be surprised. |

**Residual:** the per-address limits are only as good as the address, which
behind a proxy is whatever `[server.proxy] trusted_cidrs` allows a peer to
assert (tls-and-proxy.md §1). A misconfigured proxy that forwards a spoofable
`X-Forwarded-For` turns every per-address bucket into a per-request one. That
is the proxy configuration's threat, stated there, and it applies to every
row above.

### 4. Agent-specific threats (G4)

FAPI's attacker model has no notion of a principal acting for another principal.
These rows are ours. They are the index; §4.1 is the same threats written out
with the attacker capability, the file the control lives in, the test that holds
it and the risk that is left.

| ID | Threat | Control | Bead |
|---|---|---|---|
| **T-A1** | **Delegation-chain widening.** An agent exchanges a narrow token for a broader one, or forges an `act` chain to impersonate the human. | Token exchange is narrowing-only and in force (`ast-lh3.2`): scope is intersected with the subject token's, the client's registration and the agent profile's allow-list; `audience`/`resource` go through the same RFC 8707 resolution every other grant uses, with the subject token's own resources as the authorized set, so a target it never had is `invalid_target`; the issued token's lifetime is the minimum of the tenant's, the agent's cap and what is left of the subject token, so exchanging in a loop cannot extend a credential. `act` is built by the AS from the authenticated client and never read from the request — `actor_token` is refused outright — and the depth is bounded by `max_delegation_depth`. `requested_token_type` other than an access token is refused, and no refresh token is issued. | `ast-lh3.2`, `ast-lh3.1` |
| **T-A2** | **Confused-deputy MCP server.** An MCP server holding a user's token is induced by a malicious tool description to call a resource on the attacker's behalf. | Resource indicators make every token audience-specific, so an MCP server cannot reuse a token outside its own audience; MCP clients are confidential; a pre-issuance policy decision gates each mint. | `ast-gxh.7`, `ast-lh3.8`, `ast-lh3.10` |
| **T-A3** | **Approval fatigue.** An agent issues repeated CIBA/device approvals until the human accepts one out of habit. | Approval requests are rate-limited per client *and* per person at `/bc-authorize`, and at most five may be waiting for one person at once (`ast-5lw`); decisions at `/account/approvals/decide` are limited per session; the approvals inbox names the client and the scopes; standing consents are explicit, listed and revocable through Grant Management. | `ast-5lw`, `ast-lh3.6`, `ast-p2l.3`, `ast-uwv.5` |
| **T-A4** | **Agent key compromise with no blast-radius limit.** | Every agent is a confidential client with its own key; grants are per-agent and individually revocable; the per-agent audit trail reconstructs everything a compromised agent did, including the delegation chains it used. | `ast-lh3.1`, `ast-lh3.9`, `ast-83p.11` |
| **T-A6** | **Ownership forgery.** An agent registers naming somebody else as its owner, or keeps acting after that person is gone, and its actions are attributed to a human who never authorised it. | The owner is a row in `users` in the same tenant, not a string: a composite foreign key refuses an owner from another tenant or one that does not exist, and deleting the account disables every agent it owned (`clients_disable_ownerless_agent`, migration `0021`). An agent whose owner column is null does not load at all, so there is no window in which an ownerless agent is issued a token. Registration of agents happens only under a tenant policy that says so, and only with an initial access token. | `ast-lh3.1` |
| **T-A7** | **Agent-as-subject confusion.** An agent's `client_id` is read as an end-user subject identifier — in an audit trail, a log line or a resource server's authorisation decision — and the agent is treated as the person it acts for (FAPI 2.0 SP §6.7). | A `client_id` is minted by this server and cannot be influenced by the registrant. Every one carries the prefix `c.`, which occurs in neither spelling of a `sub` this server issues — a UUID or 43 `base64url` symbols — and a test asserts the two populations do not overlap against subjects drawn by the real generators. Every issuance to an agent is recorded as `Actor::Agent`, which names the agent *and* the owner, so a reader is never left to infer a principal from an identifier. | `ast-lh3.1` |
| **T-A8** | **Unattended escalation.** An agent takes a scope or an `authorization_details` type that a person would have been asked about, through a grant that has no person in it. | Those scopes and types are named in the tenant's agent profile, and a `client_credentials` request that asks for one is refused with `invalid_scope` rather than narrowed. The profile also caps an agent's token lifetime — bounding, never lengthening, the tenant's own — and bounds the grants an agent may register for to the non-redirecting set. `max_delegation_depth` is **in force at the token exchange endpoint** (`ast-lh3.2`): a chain deeper than the profile permits is `invalid_request`, and the default of one hop means a tenant that never thought about delegation has not permitted a second one. It still binds nothing in CIBA (`ast-lh3.5`): a backchannel authorization is a person's own grant to the client that asked and carries no chain, so there is no depth to bound. The human-approval rule applies to a delegation as well as to `client_credentials`: the person approved that scope for the client their token was minted for, which is not a decision about the agent asking to be delegated it. | `ast-lh3.1`, `ast-lh3.2` |
| **T-A9** | **Impersonation mistaken for delegation.** An agent obtains a token that a resource server cannot tell apart from one minted for the human — no `act`, the person's `sub` — and every decision and every log line downstream attributes the agent's actions to somebody who was not there. | RFC 8693 §5's two modes are a client policy, not a request parameter: delegation is what an agent gets when nobody decided, and the issued token always carries `act`. Impersonation happens only for a client whose agent profile carries `impersonation: true`, which is a tenant document an operator writes and an administrator can read back, and the audit entry for such an exchange is labelled `delegation: impersonation` — so the trail keeps the distinction the token deliberately loses. A profile member that is not a boolean does not load, so a truthy string from a templating language cannot become permission. | `ast-lh3.2`, `ast-lh3.1` |
| **T-A10** | **A token for a user who is not there.** Token exchange is the one endpoint where a credential naming a person is minted with nobody present to object. An agent that could exchange any token it came across would turn every leaked or forwarded access token into a delegation. | The subject token must be one this tenant signed, inside its `exp`, with its `jti` off the revocation denylist and the grant behind it still `active` — so revoking the authorization ends the exchanges too, and a token that names no grant cannot be exchanged at all. Possession is proved the way the token itself states it: the DPoP key on the request must be the `cnf.jkt` of the subject token. A token minted for one client and presented by another is refused unless that client's own profile carries `exchangeable`, which is an operator's decision recorded on the client it is about. `may_act` (§4.4), when the subject token carries it, decides — and anything in it this build cannot fully evaluate is a refusal, never a condition assumed satisfied. Every one of these failures is the same `invalid_grant` with the same wording, so the endpoint is not an oracle for whether a stolen token has been revoked yet. | `ast-lh3.2` |
| **T-A5** | **Silent divergence after human access ends.** A human is off-boarded but their agents keep working. | CAEP `session-revoked` / `credential-change` / `assurance-level-change` events over SSF; grant revocation cascades to every token minted from it. | `ast-0ju.8`, `ast-o4u.3` |
| **A1**, **A3a** | **G1** | **Replaying a captured client assertion.** An assertion is a bearer credential: anything that reads one off the wire, out of a log, or from a proxy can present it as the client until `exp`. | `jti` is required and single-use, enforced by one `insert … on conflict do nothing` so the check and the record are the same statement and no window exists between them. Namespaced per client (RFC 7523 §3 item 7), so one client cannot burn another's identifiers. Consumed *last*, so a rejected assertion does not spend a `jti` the client may legitimately retry. Assertion lifetime is capped at 10 minutes, which bounds both the replay window and the store. | `ast-m9c.2` |
| **A1**, **A5** | **G1** | **Cross-audience assertion forwarding.** A client mints one assertion naming this server *and* a second, hostile audience; that audience forwards it here and is authenticated as the client. | `aud` must be a JSON **string** and must equal the issuer identifier — FAPI 2.0 SP §5.3.2.1 item 8. The array form is refused however it is spelled, including a single-element array holding exactly the right issuer, which removes the possibility rather than checking for it. The token endpoint URL that OIDC Core §9 allowed is refused too. | `ast-m9c.2` |
| **A1** | **G1** | **Cross-tenant authentication.** A client registered in tenant A presents its assertion at tenant B, where the same `client_id` exists. | Every tenant has its own issuer identifier, and `aud` must be *that* issuer as a string. An assertion minted for A fails at B on the audience, before B's registry is consulted for a key. | `ast-m9c.2`, `ast-83p.10` |
| **A5** | **G4** | **Client enumeration by timing.** An unauthenticated caller probes `client_id` values and distinguishes "no such client" from "wrong key" by how quickly it is refused. | Unknown, disabled and wrong-method clients all return one error, after a signature verification against a throwaway key so the cryptographic work is comparable. | `ast-m9c.2` |
| **A3a**, **A5** | **G1**, **G3** | **Tampering with an authorization request in the browser.** Scope, `redirect_uri`, `state` or PKCE altered between the client and the authorization endpoint. | PAR is the only way to start a flow (ADR-0002, FAPI 2.0 SP §5.3.2.2 items 2–3). Every parameter is fixed while an authenticated client is on the connection, and the user agent carries only an opaque reference. There is no query string to modify. | `ast-gxh.1` |
| **A5** | **G4** | **Reading an authorization request out of a URL.** `login_hint`, `claims` and `scope` in a browser history entry, a `Referer`, a proxy log or a screenshot. | The same: the reference carries no information. What a URL would have exposed is in a row keyed by a digest. | `ast-gxh.1` |
| **A1**, **A5** | **G1** | **Guessing or replaying a `request_uri`.** A reference is a bearer credential: whoever holds one can begin a flow as that client. | 256 bits of entropy (RFC 9126 §7.1 via RFC 9101 §10.2(d)); stored only as a SHA-256 digest, so a leaked row is not usable; shape checked before any query, so guesses cost a comparison; consumed atomically in one `update … where consumed_at is null`, so two submissions of one consent screen produce one code. Lifetime is capped below 600 seconds (FAPI 2.0 SP §5.3.2.2 item 12). | `ast-gxh.1` |
| **A5** | **G1** | **Using the PAR endpoint as an open redirector.** An unauthenticated caller induces a redirect to a URI of their choosing. | Nothing at this endpoint ever redirects. An unregistered `redirect_uri` is a 400 with a JSON body and no `Location`, per RFC 6749 §4.1.2.1 — a redirect there would be the open redirector the rule exists to close. Pinned by a test that asserts the absence of the header. | `ast-gxh.1` |
| **A5** | **G1** | **Parameter pollution.** A request carries a parameter twice so that two intermediaries disagree about which copy counts, and it is validated as one request and executed as another. | RFC 6749 §3.1 is enforced literally: a repeated parameter is refused rather than resolved. The form is parsed into pairs, not a map, so the duplicate is still visible when the rule is applied. | `ast-gxh.1` |
| **A5** | **G4** | **Client misidentification at consent.** A client registers as "Example Bank" and the user, seeing a familiar name, approves a request that sends their code somewhere else. | FAPI 2.0 SP §7 names this. The consent screen shows the *host* the user will be returned to alongside the name: the name is chosen by whoever registered, the host is not — it was validated at push time against the client's registered set, so it is one the client actually controls. | `ast-uwv.1` |
| **A5** | **G4** | **Consent-screen tracking.** A client learns exactly when its consent screen was shown, and to whom by IP, by having the page fetch its logo. | No page loads anything from anywhere else — no `img`, `iframe`, `link` or remote `url()`, asserted by a test over the rendered output, and `img-src 'self' data:` in the policy behind it. A client logo would have to be uploaded to this server before it could be shown. | `ast-uwv.1`, `ast-ndk.3` |
| **A3a** | **G1** | **Granting more than the user agreed to.** A forged or altered consent form claims scopes the user never saw. | The submitted form is checked against the offer this server rendered, not trusted: a scope that was not displayed is refused outright, and a required scope that was dropped is refused too. What the grant records is what was ticked, which may be less than the client asked for. | `ast-uwv.1` |
| **A1** | **G4** | **Writing on this server's sign-in page through `login_hint`.** A client puts a line of prose, a line break or a bidirectional override in the parameter, and the user reads instructions — or an address at a domain they trust — that the server appears to be giving them. | The value is bounded to 128 bytes and refused outright if it carries a control character or a UAX #9 bidirectional formatting character, at the push, while the client is on the connection. Templates escape every interpolation on top of that, so the two defences are independent: escaping stops markup, this stops the value *being* a message. Same reasoning as the logout confirmation page, which refuses any field an unidentified relying party could fill. | `ast-gxh.8`, `ast-o4u.1` |
| **A1** | **G1**, **G4** | **Driving an authorization with somebody else's ID token.** A client sends an `id_token_hint` it did not receive — one issued to another client, or one this server never signed — to make a decision be taken about a subject it has no relationship with. | The hint is verified at the push against this tenant's own keys, retired ones included, with `iss` pinned to the tenant. Unlike the logout endpoint, which reads the client *out* of the hint, `aud` is pinned to the authenticated client and `azp`, when present, must be that client. A hint that fails any of this makes the whole request `invalid_request`; it is never dropped and continued without, because that would answer a request about a named person using whoever happened to be signed in. Only the `sub` is stored, never the token. | `ast-gxh.8`, `ast-o4u.1` |
| **A1** | **G4** | **Silent authorization the user never saw.** A client sends `prompt=none` in a hidden frame and receives a code without any interface being displayed, or — the mirror image — a server refuses a request it could have answered and pushes the user through a login they did not need. | One decision function over (session, `prompt`, `max_age`, hinted subject, `acr`), with every row of the table under test, and it runs at `/authorize` *before* an interaction row exists — so a `prompt=none` request that cannot be answered is refused without anything having been rendered. `prompt=none` combined with any other value is refused at the push (OIDC Core §3.1.2.1). A requirement the tenant can never meet is `unmet_authentication_requirements` rather than a login the user would complete for nothing. | `ast-gxh.8` |
| **A3a**, **A5** | **G1**, **G4** | **Step-up as a session takeover.** A step-up is the one moment this server writes an *existing* session on the strength of a credential presented now. An attacker who could reach that write — with their own passkey, in a browser holding somebody else's interaction — would attach their authentication to another person's session and inherit it at a higher assurance than the victim ever reached. | Three gates, none of them optional. The interaction must already be at `Stage::StepUp`, which only `/authorize` sets and only after the decision function asked for it; the session named by the interaction must belong to the **same user** as the credential that just verified, and anything else — expired, revoked, somebody else's — starts a fresh session instead of rotating; and the write itself is `SessionRepository::rotate`, one statement, so the browser leaves with an identifier it has never held and the old one stops resolving at the same instant. `crates/server/src/http/step_up.rs` states all three beside the code, and a test drives a step-up onto another user's session and requires a second session rather than a rotation. | `ast-2vk.7` |
| **A1** | **G1**, **G4** | **Claiming an authentication context nobody reached.** `acr` is what a relying party reads to decide whether an authentication was strong enough to move money. A server that reported a class it did not perform — because the value was requested, because a discovery document advertised it, or because a stale label survived a re-authentication — would be lying in the one claim that exists to be trusted. | A class is a *set of authentication methods*, and a session reaches it only when its `amr` contains all of them; nothing assigns an `acr` from a request. The ladder is the only source of `acr_values_supported`, so the document cannot advertise a class the endpoint would refuse — it previously advertised `urn:mace:incommon:iap:silver`, from the specification's example, which this server has never been able to produce. A rotation overwrites `acr` rather than leaving it, so a step-up cannot keep a label its new `amr` no longer supports. `phrh` is not offered at all: enrolment attests nothing, so hardware protection is not a fact this server holds. A fuzz target asserts over arbitrary ladders and method sets that an assigned value is on the ladder and reached by the methods. | `ast-2vk.7` |
| **A3a**, **A5** | **G1**, **G4** | **Application-role widening (`ast-095`).** Application roles are authority this server *delegates* to somebody else's code: an application reads `roles` or `resource_access` out of an access token and authorises money movement on the strength of a string. Three ways that goes wrong. A name that splits — `read write` — becomes two roles at any resource server that splits on whitespace. A name that folds — `Admin` beside `admin` — is two catalogue entries here and one authority there. And a role assigned through a route that does not check the catalogue is authority somebody invented at assignment time. | The name is a parsed type, not a string: `RoleName::parse` admits `[a-z0-9]` plus `-_.:`, first character alphanumeric, at most 64 characters, and **refuses uppercase rather than folding it** — a parser that rewrites its input produces a name nobody predicted. It is fuzzed (`fuzz/fuzz_targets/role_name.rs`) against the properties that matter downstream: no whitespace, no control or bidirectional character, no JSON escaping needed, and `parse(x).as_str() == x`. The same alphabet is a check constraint in migration `0023`, so it is a fact about the stored rows rather than about the code path that wrote them. Assignment is a foreign key onto the catalogue, so a role that was never created cannot be given to anybody; deleting a held role is refused by `on delete restrict` rather than cascaded, so authority is never withdrawn from an unbounded number of people by one request. Dynamic client registration has no field for a role, so a client cannot arrive naming its own. Every definition, deletion, assignment and withdrawal is its own audit event (`app_role.defined`, `app_role.removed`, `app_role.assigned`, `app_role.withdrawn` — spelled apart from `ast-3t8`'s `role.granted`/`role.revoked`, which are the authority to administer this server). | `ast-095` |
| **A5** | **G4** | **Cross-application role disclosure.** A resource server receives a token carrying the roles somebody holds in an unrelated application, and learns — or authorises on — authority that has nothing to do with it (`ast-gxh.7`). | `resource_access` names exactly one client: the one the token was issued to. The narrowing is inside `AccessToken::with_roles` and inside `userinfo::with_roles`, not at their call sites, so there is no caller that could widen it; the access-token fuzz target asserts over arbitrary role sets that the rendered object has exactly one member and that it is the token's own `client_id`. Roles shared across a tenant's applications are a *tenant* role, which is the deliberate way to say "everyone may see this". | `ast-095`, `ast-gxh.7` |

### 4.1 Agent threats in detail (`ast-p2l.6`)

The table above is the index; this is the long form an external reviewer reads.
Each entry names the attacker capability the attack needs (§2), the control **as
it exists in this tree today** with the file that holds it, the test or fuzz
target that keeps the control honest, the bead, and what is left over. A control
whose bead is still open is written as open — a threat model that describes
intentions is worth nothing to a reviewer.

#### T-A11 — A prompt-injected agent asks for a scope it was never delegated

- **Attacker: A1.** No network and no browser needed: a document, a tool
  description or a web page the agent reads is enough. The agent itself is
  honest and authenticates correctly — which is the point. Every credential it
  presents is valid; the request it makes is the attacker's.
- **Threat.** The agent is instructed to ask for `payments:write` instead of
  `inventory:read`, to name a resource server it has never called, or to keep
  its token alive past the task.
- **Control.** The server treats an agent's request as attacker-controlled by
  construction, so a widened request is refused by the same rules whatever made
  the agent send it:
  - *scope* — `TokenExchange::scopes` in
    [`crates/server/src/http/token_exchange.rs`](../crates/server/src/http/token_exchange.rs)
    intersects the request with three sets the agent cannot influence: the
    subject token's scopes, the client's registered scopes, and the agent
    profile's allow-list (`AgentLimits::scopes`). `NOT_DELEGATED_SCOPES`
    (`openid`, `offline_access`) is dropped even when all three permit it;
  - *human-gated scope* — `AgentProfile::scope_needing_human_approval` in
    [`crates/domain/src/entities/agent.rs`](../crates/domain/src/entities/agent.rs)
    marks the scopes a person must approve. A delegation has no person in it, so
    the exchange refuses them with `invalid_scope`, and so does
    `client_credentials`
    ([`crates/server/src/http/client_credentials.rs`](../crates/server/src/http/client_credentials.rs));
  - *audience* — `TokenExchange::targeting` resolves `audience`/`resource`
    through the RFC 8707 path every other grant uses, against the subject
    token's own authorized set and the tenant's registry
    ([`crates/domain/src/entities/resource_server.rs`](../crates/domain/src/entities/resource_server.rs));
    a target the subject token never had is `invalid_target`;
  - *lifetime* — `TokenExchange::lifetime` takes the minimum of the tenant's
    lifetime, the agent's own cap and what is left of the subject token, so an
    injected "keep this alive" loop extends nothing;
  - *the limits are the tenant's, never the client's* — `AgentLimits` comes from
    the registration policy preset (`ast-m9c.6`), so an agent told to re-register
    itself with wider limits is refused at registration.
- **Tests.** `crates/oidc/src/token_exchange.rs`:
  `an_actor_token_is_refused_rather_than_ignored`,
  `a_chain_deeper_than_the_policy_is_refused`,
  `a_target_that_is_not_a_resource_identifier_is_invalid_target`,
  `asking_for_anything_but_an_access_token_is_refused`.
  `crates/domain/src/entities/agent.rs`: the `scope_needing_human_approval`
  tests. Fuzz:
  [`fuzz/fuzz_targets/token_exchange_form.rs`](../fuzz/fuzz_targets/token_exchange_form.rs),
  [`fuzz/fuzz_targets/agent_profile.rs`](../fuzz/fuzz_targets/agent_profile.rs).
- **Beads.** `ast-lh3.1` (closed), `ast-lh3.2` (closed), `ast-m9c.6` (closed).
- **Residual risk.** The server bounds what an agent *may* hold; it cannot tell
  a task the owner wanted from a task an attacker wrote into the agent's
  context. Everything inside the delegated envelope — reading the inventory the
  injected prompt chose, at the moment it chose — is authorized and will be
  authorized. The mitigations are therefore envelope size (narrow profiles,
  short lifetimes) and after-the-fact legibility (the per-agent audit trail,
  `ast-lh3.9`), not prevention. A reviewer should read `AgentLimits::scopes`
  being absent — "no allow-list" — as the dangerous default it is: it falls
  back to the client's registered scopes alone.

#### T-A1 — Delegation-chain abuse (detail of the row above)

- **Attacker: A1**, and **A5** for the variant where the chain is read off a
  TLS-intercepting proxy at the resource server.
- **Threat.** An agent forges or extends an `act` chain to look like the human,
  or chains delegations until nobody can say who acted.
- **Control.** `act` is built by the authorization server from the
  *authenticated* client and is never read from the request: `actor_token` is
  refused outright rather than ignored
  ([`crates/oidc/src/token_exchange.rs`](../crates/oidc/src/token_exchange.rs)).
  The current actor is the first element of the chain; a stored chain that is
  not a chain of actors is refused; depth is bounded by
  `AgentLimits::max_delegation_depth`; a `may_act` naming somebody else refuses
  the actor, and a `may_act` this build cannot fully check refuses it too — the
  fail-closed direction. No refresh token is issued from an exchange, so a chain
  cannot outlive the token it came from.
- **Tests.** `the_current_actor_is_the_first_element_of_the_chain`,
  `the_first_delegation_is_a_chain_of_one`,
  `a_chain_deeper_than_the_policy_is_refused`,
  `a_stored_chain_that_is_not_a_chain_of_actors_is_refused`,
  `a_may_act_naming_the_actor_authorizes_it`,
  `a_may_act_naming_somebody_else_refuses_the_actor`,
  `a_may_act_this_build_cannot_fully_check_refuses_the_actor`; and
  `the_audit_chain_holds_the_actors_the_token_does_in_the_same_order`
  in `crates/server/src/http/token_exchange.rs`.
- **Beads.** `ast-lh3.2` (closed), `ast-lh3.9` (closed).
- **Residual risk.** A resource server still has to *read* `act`. Nothing this
  server emits forces it to, and a resource server that authorises on `sub`
  alone sees the human. That is FAPI 2.0 SP §6.7's confusion in its delegated
  form, and it is a property of the deployment rather than of the token.

#### T-A12 — Replay of an agent's DPoP proof

- **Attacker: A2 or A5.** The proof has to be captured, so this needs the
  network or a log at the endpoint. An agent makes it worth doing: it runs
  unattended, so a replay nobody is watching has a longer practical window than
  one aimed at a human flow.
- **Control.** [`crates/server/src/http/dpop.rs`](../crates/server/src/http/dpop.rs)
  spends the `jti` once, in one statement over the shared replay store, and
  binds every proof to its method (`htm`), its URL (`htu`, and therefore its
  tenant), its key and its `iat` window. `jti` uniqueness is scoped per key, so
  two agents choosing the same `jti` neither collide nor deny each other
  service. A replay store that is unavailable **refuses** rather than accepting.
  Where the deployment turns nonces on, a proof without one is never accepted
  and a foreign nonce is refused with a usable replacement. The token itself is
  bound to the key (`cnf.jkt`,
  [`crates/oidc/src/tokens/access.rs`](../crates/oidc/src/tokens/access.rs)), so
  a captured proof without the private key buys nothing.
- **Tests.** [`crates/server/tests/dpop.rs`](../crates/server/tests/dpop.rs):
  `a_replayed_jti_is_refused`, `two_keys_may_choose_the_same_jti`,
  `a_proof_minted_for_one_endpoint_is_not_accepted_at_another`,
  `a_proof_for_another_tenants_endpoint_is_refused`,
  `an_iat_outside_the_window_is_refused`,
  `an_unavailable_replay_store_refuses_rather_than_accepting`,
  `the_age_window_and_the_jti_are_independent_defences`. Fuzz:
  [`fuzz/fuzz_targets/dpop_proof.rs`](../fuzz/fuzz_targets/dpop_proof.rs).
- **Beads.** `ast-a05.6` (closed, DPoP), `ast-a05.10`/`ast-a05.11` (closed,
  wiring and the nonce secret), `ast-p2l.4` (closed, replay-row retention).
- **Residual risk.** Replay protection is per deployment database, and the `iat`
  window is exactly the interval in which a *resource server* — which this
  project does not ship — may accept a proof it has never seen. An agent calling
  an RS that keeps no `jti` cache has, at that RS, no replay protection beyond
  the window. Nonces are optional and off by default.

#### T-A3 — Approval fatigue in CIBA and the device flow (detail of the row above)

- **Attacker: A1.** One registered client — including a compromised honest one —
  is enough.
- **Threat.** An agent raises backchannel authentication requests until the
  owner approves one out of habit, or approves the wrong one because two look
  alike.
- **Control.** [`crates/server/src/http/approvals.rs`](../crates/server/src/http/approvals.rs)
  and [`crates/oidc/src/ciba.rs`](../crates/oidc/src/ciba.rs): a pending request
  expires in five minutes and `requested_expiry` may only shorten that; an
  approval requires an authentication within `approvals::FRESHNESS` (two
  minutes), so a browser somebody walked away from cannot approve; `acr_values`
  is enforced at the one moment a person is present; the decision is a single
  `UPDATE … WHERE status = 'pending'`, so a double-click or a replay moves no
  row; the `binding_message` is length- and character-bounded so it cannot be
  used to write instructions onto the page; the client, the scopes and the RFC
  9396 elements are named there; and both outcomes are audited with the
  `approval_id` and the deciding session.
- **Control — the limits (`ast-5lw`).**
  [`crates/domain/src/rate_limit.rs`](../crates/domain/src/rate_limit.rs) has
  `LimitedEndpoint::Backchannel`, and it is the one endpoint with a
  `per_subject` bucket:
  [`crates/server/src/http/limits.rs`](../crates/server/src/http/limits.rs)'s
  `guard` counts the address and the authenticated client, and `guard_subject`
  counts requests about the *person the hint resolved to* — keyed by the
  resolved account, so an address, a username and an `id_token_hint` naming one
  person are one budget. All three are operator-tunable
  (`limits.backchannel_per_address`, `_per_client`, `_per_user`), all three
  refuse with the same `429` and `Retry-After`, and a refusal is one
  `request.throttled` record per window and an `asterius_endpoint_throttled_total`
  labelled `subject`. On top of them, `ciba::MAX_PENDING_PER_USER` (five) bounds
  what a window cannot: a slow, patient client keeping an inbox permanently
  full. **The new request is refused — `invalid_request` with a description —
  and nothing already waiting is dropped**, because replacing the oldest would
  let one client cancel another's approval, and would change what a person is
  looking at in the instant before they press approve. A hint that resolves to
  nobody fills no subject bucket and is still §13's `unknown_user_id`, which is
  the oracle the specification mandates and not a new one. The decision form
  carries its own per-session budget (`approvals::DECISIONS_PER_WINDOW`, twenty
  per ten minutes), keyed by the session rather than the address because a
  household is one address and several approvers.
- **Tests.** The limiter tests in `crates/server/src/http/limits.rs`
  (`a_client_with_budget_left_is_refused_about_one_person`,
  `one_persons_budget_is_not_another_persons`,
  `a_subject_refusal_is_indistinguishable_from_a_client_refusal`,
  `a_flood_about_one_person_is_audited_once_per_window`), the pending-ceiling
  tests in `crates/oidc/src/ciba.rs` (`a_full_inbox_refuses_the_new_request`,
  `a_full_inbox_is_reported_as_an_invalid_request`), the decision-budget tests
  in `crates/server/src/http/approvals.rs`
  (`a_session_may_decide_until_its_budget_is_spent`,
  `a_limiter_that_cannot_be_read_refuses`), and the decision-form tests in the
  same module (`a_decision_form_names_one_request_and_one_answer`,
  `a_form_that_answers_twice_is_refused`, `a_third_answer_is_refused`,
  `a_reference_that_is_not_a_digest_is_refused`) and the lifetime and
  binding-message tests in `crates/oidc/src/ciba.rs`. Fuzz:
  [`fuzz/fuzz_targets/approval_decision.rs`](../fuzz/fuzz_targets/approval_decision.rs),
  [`fuzz/fuzz_targets/ciba_form.rs`](../fuzz/fuzz_targets/ciba_form.rs),
  [`fuzz/fuzz_targets/device_user_code.rs`](../fuzz/fuzz_targets/device_user_code.rs).
- **Beads.** `ast-lh3.6` (closed), `ast-lh3.4` / `ast-lh3.5` (closed),
  `ast-p2l.3` (closed), `ast-5lw` (closed — the limits and the pending
  ceiling).
- **Residual risk.** The limits are fixed windows in the database, so a client
  that paces itself to the ceiling may still raise
  `limits.backchannel_per_user` requests about one person every window, and the
  pending ceiling is what keeps that from accumulating: five waiting at once,
  each expiring in five minutes. Identical pending requests are still not
  *deduplicated* — two requests for the same scopes appear as two lines in the
  inbox — because a client legitimately retries after a person has read one,
  and collapsing them would make the second one's `binding_message` disappear.
  `/device_authorization` remains outside `LimitedEndpoint`; the device
  verification page has its own budget, and the authorization endpoint behind
  it has not.

#### T-A2 — Confused-deputy MCP server (detail of the row above)

- **Attacker: A1**, or **A1a** where the attacker runs an MCP server in the
  ecosystem.
- **Threat.** An MCP server holding a user's token is induced, by a tool
  description it was handed, to call a resource on the attacker's behalf with
  the user's authority.
- **Control.** Every access token is audience-specific: `ResourceRegistry::targets`
  in [`crates/domain/src/entities/resource_server.rs`](../crates/domain/src/entities/resource_server.rs)
  returns `Err(InvalidTarget)` rather than an empty audience, and a `resource`
  must pass both the client's own allow-list and the tenant registry. A
  multi-audience token carries only the scopes **every** named resource server
  permits (`ResourceRegistry::permitted_scopes`), so widening the audience never
  widens authority. There are no public clients anywhere (ADR-0002), so an MCP
  client cannot be impersonated by a redirect alone, and consent is per client:
  a second MCP server is a second client with its own consent screen.
- **Tests.** The `ResourceRegistry` tests in
  `crates/domain/src/entities/resource_server.rs`; `crates/server/tests/discovery.rs`
  for what a tenant advertises.
- **Beads.** `ast-gxh.7` (closed), `ast-lh3.8` (**open** — the MCP compatibility
  profile itself), `ast-lh3.10` (**open** — the pre-issuance policy port),
  `ast-m9c.8` (**blocked** — the decision on MCP public clients and Client ID
  Metadata Documents).
- **Residual risk.** Two of the three controls the index table claims are beads
  that have not landed: there is no MCP profile and no pre-issuance policy port
  today. What exists is audience binding and confidential clients — the
  substantive half — but the deputy problem is only fully answered when the
  resource server *checks* `aud` and the AS takes a policy decision per mint.

#### T-A13 — MCP token passthrough

- **Attacker: A1, A5.**
- **Threat.** An MCP server accepts a token that was not issued for it and
  forwards it upstream, or hands its own upstream token back down. The token
  travels further than its audience and the resource server at the end cannot
  tell who asked.
- **Control, at this server.** `aud` is never empty and never client-chosen
  (RFC 9068 §2.2, RFC 8707 §3 — `ResourceRegistry::targets`); the token is
  sender-constrained (`cnf.jkt`, or `cnf.x5t#S256` where the `mtls` flag is on),
  so forwarding it without the private key fails at the next hop that checks;
  tokens are short-lived and grant-bound, and revoking the grant revokes
  everything minted from it.
- **Tests.** `crates/server/tests/token.rs` and `crates/server/tests/userinfo.rs`
  cover audience and binding on issuance and on presentation; fuzz:
  [`fuzz/fuzz_targets/access_token_claims.rs`](../fuzz/fuzz_targets/access_token_claims.rs).
- **Beads.** `ast-gxh.7` (closed), `ast-a05.3` (closed), `ast-lh3.8` (open).
- **Residual risk.** Passthrough is a *resource server* failure, and this
  repository ships no resource server. An AS cannot stop an RS from accepting a
  token addressed to somebody else; all it can do is make the token say who it
  is for, which it does. `ast-lh3.8` owns the guidance that tells an MCP
  implementer to check `aud` and to refuse a token it did not request.

#### T-A14 — Loopback redirect URIs on agent and MCP clients

- **Attacker: A1**, sharing the machine — another local process, or another
  application the user installed.
- **Threat.** MCP authorization leans on `http://127.0.0.1:<port>` callbacks;
  whichever local process binds the port first receives the code.
- **Control.** The loopback exception is RFC 8252 §7.3 and no wider:
  `loopback_parts` in
  [`crates/domain/src/entities/client.rs`](../crates/domain/src/entities/client.rs)
  varies **the port and nothing else** — the path must match exactly, the host
  must be a literal loopback address (not `localhost`), `http` is admissible
  only for a native client, and everything else falls under exact-string
  matching (ADR-0005). A pairwise client whose only redirect URI is a loopback
  callback is refused a sector (`ast-m9c.10`). PKCE `S256` is mandatory, so an
  intercepted code cannot be redeemed.
- **Tests.** `a_native_clients_loopback_redirect_matches_on_any_port`,
  `the_loopback_exception_varies_the_port_and_nothing_else`,
  `only_a_native_client_gets_the_loopback_port_exception`,
  `loopback_http_is_admissible_only_for_a_native_client`,
  `two_loopback_uris_that_differ_only_in_their_port_are_one_registration`, and
  the property tests `a_match_between_different_strings_can_only_be_a_loopback_port`
  and `a_loopback_registration_matches_every_port_but_only_its_own_path`. Fuzz:
  [`fuzz/fuzz_targets/redirect_uri.rs`](../fuzz/fuzz_targets/redirect_uri.rs).
- **Beads.** `ast-m9c.7` (closed), `ast-m9c.10` (closed), `ast-m9c.8`
  (blocked — public MCP clients).
- **Residual risk.** A local attacker who wins the port race still learns that a
  flow happened and can deny service to the honest client. And because this
  server has no public clients, the MCP "native app on a laptop" shape is a
  *confidential* client with a private key on that laptop — a different residual
  (a client key at rest on a shared machine), owned by `ast-m9c.8`.

### 4.2 FAPI 2.0 SP §6 security considerations, one row each

§6 of the Security Profile lists the attacks an implementation is expected to
have thought about. Clause numbers appear only where they were verified against
the Final text (§6.7); the rest are named rather than numbered, deliberately —
an invented citation is worse than none, and §6 as a whole is the reading a
human owes this table (see the verification note at the top of this file).

| §6 consideration | Attacker | Control, and where it lives | Test / fuzz | Bead | Residual |
|---|---|---|---|---|---|
| **DPoP proof replay** | A2, A5 | Single-use `jti` scoped per key in one statement, `htm`/`htu`/`iat` binding, fail-closed when the replay store is down, optional server nonces — `crates/server/src/http/dpop.rs` | `crates/server/tests/dpop.rs` (`a_replayed_jti_is_refused`, `the_age_window_and_the_jti_are_independent_defences`); `fuzz/fuzz_targets/dpop_proof.rs` | `ast-a05.6`, `ast-a05.10`, `ast-a05.11` (closed) | The `iat` window is all a resource server with no `jti` cache has (T-A12); nonces are off by default |
| **Stolen-token injection ("Cuckoo's token")** | A1, A2, A5 | Every token is sender-constrained — `cnf.jkt` (`crates/oidc/src/tokens/access.rs`) or `cnf.x5t#S256` under the `mtls` flag; `TokenBinding` has no unbound variant, so `dpop_bound_access_tokens: false` cannot be registered; `aud` is never empty (`ResourceRegistry::targets`); the `authorization_code` grant binds the code to the DPoP key | `crates/server/tests/token.rs`, `crates/server/tests/dpop.rs`, `crates/server/tests/mtls_client_auth.rs`; `fuzz/fuzz_targets/access_token_claims.rs` | `ast-a05.2`, `ast-a05.3`, `ast-a05.7`, `ast-gxh.7` (closed) | A resource server that never checks `cnf` or `aud` is outside this trust boundary |
| **Authorization-request leak → CSRF** | A3a, A5 | PAR is the only way to start a flow (ADR-0002): the front-channel URL carries `client_id` and a `request_uri` and nothing else; the reference is 256 bits, stored only as a digest and single-use; RFC 9207's `iss` is returned so a client can tell which AS answered (`crates/server/src/http/authorize.rs`) | `crates/server/tests/par.rs`, `crates/server/tests/authorize.rs`; `fuzz/fuzz_targets/par_form.rs` | `ast-gxh.1` (closed) | `state` is the client's defence and the client's responsibility; this server cannot verify that an RP validates it |
| **Browser swapping** | A1, A3a | A code is minted only into the browser that finished the interaction: the interaction is held in a `__Host`-scoped cookie, a repeated cookie is refused rather than resolved (`crates/web/src/interaction.rs`), every interaction form carries a synchroniser token derived from the session's digest, and minting re-reads the session and refuses one that is no longer usable | `crates/server/tests/interaction.rs`, `crates/server/tests/authorization_code.rs`; `fuzz/fuzz_targets/interaction_cookie.rs` | `ast-gxh.1`, `ast-a05.2` (closed) | The client-side half — binding the redemption to the browser that started the flow — is PKCE plus `state` at the RP, outside this server |
| **Client impersonating the resource owner (§6.7)** | A1 | A `client_id` minted here carries `ClientId::MINTED_PREFIX` (`c.`, `crates/domain/src/ids.rs`), a prefix that cannot occur in either spelling of a `sub` this server issues; `act` names the actor separately from `sub`; the audit trail records the chain in the same order the token does | `crates/server/src/http/token_exchange.rs` (`the_audit_chain_holds_the_actors_the_token_does_in_the_same_order`), the `ClientId` tests in `crates/domain/src/ids.rs` | `ast-lh3.1`, `ast-lh3.9` (closed) | A resource server keying authorisation on `sub` alone still cannot see the agent (T-A1) |
| **Key compromise** | A1, A2 | Private keys are sealed at rest under a KEK (`crates/store-pg/src/keys.rs`); rotation and purge are operator commands with audit records (`docs/runbooks/kek-rotation.md`); a purge destroys the private half, unpublishes the key and makes this server refuse its signatures; client keys come only from the source that client's own registration named; every grant is individually revocable | `crates/server/tests/rotation.rs`, `crates/server/tests/signing.rs`; `fuzz/fuzz_targets/kek_unwrap.rs` | `ast-7rq`, `ast-7kw` (closed) | A purge does not reach a token a third party has already accepted, and `LocalKek` keeps the KEK on the machine holding the database credentials — both rows in §5 |

## 5. Known residual risks

A risk is here when somebody decided to accept it. A choice nobody has made yet
is in [§7](#7-decisions-pending-security-review) instead — including the mTLS
rows below, which are listed in both places on purpose: §5 describes what ships,
§7 states the options.

| Risk | Why we accept it (for now) | Tracked by |
|---|---|---|
| The decoy verification equalises cryptographic work, not every path. | A *known* client whose key set is not cached triggers an outbound `jwks_uri` fetch, which is far slower than anything local. So the observable signal is not "does this client exist" but "is this client's key set warm" — which an attacker can also produce for a client they already know about, and which a cache hit erases. Closing it fully would mean making every failure wait out a network timeout, which is a denial-of-service amplifier pointed at ourselves. | `ast-m9c.2` |
| A client assertion is accepted with no `typ`, or with `typ: JWT`. | RFC 7523 predates RFC 8725 §3.11 and requires no explicit type, so refusing one would reject conforming clients and fail the FAPI conformance client-auth tests. The set is still closed — `at+jwt` is refused — so a token minted for another purpose cannot be presented as an assertion; what is lost is only the ability to distinguish an assertion from an untyped JWT that happens to carry the right `iss`, `sub`, `aud` and a live `jti`, which requires the client's key to produce. | `ast-m9c.2` |
| A `request` object (JAR, RFC 9101) is refused rather than processed. | JAR is `ast-s36.1`. Refusing is the safe half of the choice — ignoring the parameter would mean honouring the query parameters the object exists to protect — but it does mean a client that signs its requests cannot use this server until that lands. | `ast-gxh.1`, `ast-s36.1` |
| A tenant may store `max_clients_per_initial_access_token` and `unused_client_expiry_seconds`, and neither is enforced yet. | The policy is data and both members parse, round-trip and are evaluated by pure functions (`check_client_quota`, the stored duration) — but there is no `initial_access_tokens` table to count against and no sweep that retires a client nobody has used. Initial access tokens are still strings from `asterius.toml`, hashed at boot, with no row and therefore no per-token counter. Storing a limit that does not bind is the failure mode this file exists to name: an operator who writes `25` today gets no cap. The parsing and the evaluation are in place so that the table is the only thing missing. | `ast-m9c.6`, `ast-f7m.5` |
| A tenant that narrows an **open** deployment to `initial_access_token` refuses every caller. | The credentials are still the deployment's, and an open deployment has provisioned none — so the narrowed tenant demands a token nobody can hold. That is the safe direction of the mistake (nobody registers, rather than everybody), and it is what the per-tenant token table above turns into a working configuration. | `ast-m9c.6` |
| A client may name no `resource` indicator until its allow-list exists. | `ast-m9c.6` owns the per-client audience allow-list. Until then the registered set is empty and every indicator is refused, because an empty allow-list must mean "none" rather than "all" — the alternative is a client naming an audience nobody granted it. | `ast-gxh.1`, `ast-m9c.6` |
| The credential scanner is a heuristic, and heuristics cut both ways. | It classifies a long high-entropy base64url run as a credential. That caught two OAuth error codes — `temporarily_unavailable` and `unsupported_grant_type` — and destroyed them in the audit trail, replacing the reason a request was refused with a marker saying a secret had been removed. Fixed by excluding values that are entirely `[a-z_]`, which no CSPRNG-drawn credential is (one in seventy million at the shortest length considered). The residual is the mirror image: a genuinely all-lower-case credential would now pass. No generator here produces one, and a test asserts that. | `ast-6ng` |
| Scope descriptions are not yet per tenant. | A scope with no description is shown by its bare token. That is honest rather than misleading — an unexplained scope looks unexplained — but it is a worse decision than a described one, which is what FAPI 2.0 SP §7's "insufficient understanding" is about. `ast-ndk.5` adds tenant wording, on top of the template set `ast-ndk.2` fixes. | `ast-uwv.1`, `ast-ndk.5` |
| Every page declares a locale and every page is in English. | `locale` reaches the `lang` attribute and nothing else until message bundles land, so a page served as `lang="fr"` carries English words. That is a WCAG 2.2 SC 3.1.1 failure rather than a security one, but it is a decision worth seeing: a user who cannot read a consent screen cannot judge what they are approving, which is the same "insufficient understanding" the row above is about. Both locales are pinned as golden files and a test asserts, in so many words, that French is still only an attribute — so the gap is in the test output rather than only here. | `ast-ndk.2`, `ast-ndk.5` |
| A resource server cannot be told which clients it serves, so `resource_access` is narrowed to the token's own client rather than to the audience. | `ast-gxh.7` asks for the roles in a token to be filtered by the resource server it is audienced at. Nothing in the schema records the relationship — there is no `resource_servers.clients` column and no registration field for one — so the only client whose roles can be disclosed without guessing is the one that authenticated at the token endpoint. That is the *conservative* end of the choice: an API audienced by two clients gets two tokens naming two different clients, and never learns about the other. The cost is that a resource server serving several front ends has to read each token's `resource_access` by its own `client_id` rather than finding one merged object, and that a deployment wanting a shared vocabulary must use tenant roles. | `ast-095`, `ast-gxh.7` |
| Application roles are not shown at consent. | They are authorisation attributes the tenant assigned, not personal data the client asked for (OIDC Core §5.5), so they are not gated on a scope and do not appear on the consent screen — an application that silently received *no* roles would authorise as if the person held none, which is worse than one that received them. The residual is that a person approving a client is not told which of their roles that client will see. `ast-uwv.1` owns the screen if that decision is revisited. | `ast-095`, `ast-uwv.1` |
| A client may put its own users' roles into a token that passes through a browser. | `ast-mqt` lets a client ask for `roles` and `resource_access` in its **ID token**, per authorization with OIDC Core §5.5's `claims` parameter or once with the `roles_in_id_token` registration member. Nothing is disclosed that the client does not already hold: an ID token is audienced at exactly one client, the claims are narrowed to that same client by `IdToken::with_roles`, and RFC 9068 §6 already makes an access token readable by the client holding it. What changes is the *container* — an ID token travels the front channel, is stored by the client and turns up in pasted logs — so the default is off, no scope ever turns it on, and the decision is the client's for its own users. The residual is that a client which asks for it and then logs its ID tokens has published which of its users hold which of its roles. | `ast-mqt`, `ast-095` |
| A logout notifies the relying parties, but not synchronously and not the ones that registered no endpoint. | Back-channel logout is built (`ast-o4u.2`): every participating client that registered a `backchannel_logout_uri` is queued a `logout+jwt` and the outbox delivers it, so the section above is the threat model for it. What remains is the shape of the mechanism rather than a gap in it. A client that registered no endpoint is told nothing at all — there is no front-channel logout and no session-management iframe (`ast-o4u.4`) — and delivery is asynchronous, so between "the user logged out here" and "the application knows" there is a window measured by the receiver's availability rather than by the request. The CAEP `session-revoked` signal still has nothing queueing into it. | `ast-o4u.1`, `ast-o4u.2`, `ast-o4u.3`, `ast-o4u.4` |
| A registered passkey cannot be renamed or removed by the person who owns it. | Enrolment writes a credential with a null `label` and there is no account page to list, rename or delete one — `ast-2vk.3` owns that surface. Until it lands, a passkey the user no longer trusts can only be removed by an operator, which is the wrong party for a decision about somebody's own device. | `ast-2vk.15`, `ast-2vk.3` |
| A tenant reachable at a `custom_host` outside its issuer's domain cannot enrol a passkey there. | The RP ID is the issuer's host, and a credential scoped to it is one a browser will only offer at that host or below. A vanity host on an unrelated domain is therefore left out of the accepted origin list rather than added to it: listing it would accept a ceremony from an origin no credential of this tenant is scoped to, without making enrolment work there. Giving such a tenant its own RP ID is a per-tenant policy with a credential migration behind it. | `ast-2vk.15`, `ast-2vk.3` |
| `uv=required` is the whole deployment's policy, not a per-tenant one. | `relying_party` hands `asterius-webauthn` `UserVerification::Required`, so a passkey that proved presence but not verification is refused at registration **and at authentication** — the same relying-party description drives both ceremonies, which is why the two cannot drift apart. That is the strict default FIDO's passkey guidance assumes, and it is the right one while passkeys are treated as sufficient on their own — but a tenant that wants passkeys as a second factor beside a password cannot say so yet. | `ast-2vk.15`, `ast-2vk.4`, `ast-2vk.3` |
| Blocking a credential on a counter regression cannot be undone by its owner. | §7.2 step 21 leaves the decision to the relying party, and this one blocks: the credential is disabled and every later assertion with it is refused. That is not reachable by an attacker — the counter is only compared for an assertion whose signature verified over a challenge issued minutes earlier — but the recovery is an operator's, because there is no account page on which a user could enrol a replacement or clear the block. `SignCountPolicy::Allow` exists for a deployment that has met a genuinely broken authenticator model, and nothing selects it yet. | `ast-2vk.4`, `ast-2vk.3`, `ast-2vk.7` |
| A failed passkey sign-in is limited by client address only. | The assertion names nobody — that is what a discoverable credential is — so there is no identifier to count against, and resolving the credential to its owner before the assertion verifies, purely to choose a bucket, would be the enumeration the ceremony is built to avoid. What remains is the per-address limit, which is the one that bounds a credential-id sweep; an attacker spread across many addresses buys back proportionally more attempts, against refusals that are all indistinguishable and challenges that are single-use. | `ast-2vk.4`, `ast-2vk.9` |
| The login limiter counts in fixed windows, so a boundary admits up to twice the limit. | A window that resets on the clock lets an attacker who times their attempts spend one window's budget just before the boundary and another just after. The alternative is a sliding window: a row per attempt rather than a counter per bucket, in the database that is also serving the login. Twenty guesses in the worst-aligned quarter hour instead of ten is not the difference between safe and unsafe against any password policy this server accepts. | `ast-2vk.9` |
| A correct credential clears the account limit, and only that one. | Until `ast-b3u` a fixed window forgot nothing until it rolled over, so somebody who mistyped nine times and then remembered their password spent the rest of the quarter hour one slip away from a lockout, having just proved they are the person the counter is about. A credential that verifies — a password or a passkey, through the one call both sign-in paths make — now empties the account bucket, every window of it, so the number means "wrong guesses since the last proof". The address bucket is deliberately left alone: emptying it would hand an attacker who has *one* valid credential a way to buy back the budget for their sweep across the other identifiers behind the same address. And the reset is reachable only from a verification that succeeded, never from the refusal that means "no such identifier", so it adds no observable that separates a real account from an invented one. The residual is what a proof buys the person who made it: an attacker signing into an account they own gets that account's bucket back, which is budget against a password they already know. | `ast-2vk.9`, `ast-b3u` |
| Behind a proxy, the per-address limit is only as good as `trusted_cidrs`. | The address comes from `X-Forwarded-For` when — and only when — the immediate peer is a configured trusted proxy, and from the socket otherwise. A deployment that lists a CIDR wider than its own proxies lets a client choose its own bucket, which makes the per-address limit ornamental. The per-account limit is unaffected: it is keyed by what was typed, which no header controls. | `ast-2vk.9`, `ast-p2l.3` |
| A throttled sign-in answers faster than one that was checked. | A refused-before-checked attempt skips Argon2id, so it returns in a millisecond where a real verification takes tens. That tells an observer they are throttled, which the response says in words anyway. It does not tell them whether the identifier they typed belongs to anybody: the bucket is created on the first failure whether the account exists or not, so a real account and an invented one reach the throttled state after the same number of attempts and answer identically. | `ast-2vk.9` |
| Some endpoints are still unlimited. | `ast-p2l.3` covers the five client-facing endpoints that exist and do work: `/register`, the RFC 7592 configuration endpoint, `/par`, `/token` and UserInfo. `/introspect` and `/revoke` are the remaining unlimited ones — `/introspect` answers 501, where limiting a constant answer limits nothing, and `/revoke` is the known gap the table above records. The CIBA endpoint joined the set with `ast-5lw`, which also gave it a bucket per person and a ceiling on how many approvals may wait for one. `/device_authorization` is built (`ast-lh3.3`) and is not in `LimitedEndpoint` yet: it authenticates its caller with a signature verification before it does any work, and the flows it opens are bounded at the page a person actually reaches. That is a gap rather than a decision. The password-reset, self-registration and email-verification flows the bead names do not exist at all, so there is nothing there to limit either. Discovery, JWKS and `/logout` are reads of documents or of one session row, bounded by the transport's body and timeout limits rather than by a counter. | `ast-2vk.9`, `ast-p2l.3` |
| A limit per address and per client bounds one caller, not a botnet. | The buckets are the two dimensions a request can be attributed to without asking the directory anything: where it came from, and — once it has succeeded — which client it authenticated as. Distributed abuse, one request per address across thousands of addresses, is invisible to both. The obvious answer, a tenant-wide ceiling, is worse than the disease: a counter every caller shares is a denial of service anybody can aim at everybody, which is the mistake the per-identifier login bucket exists to avoid. What remains for that shape of attack is the transport's connection and timeout limits and whatever the operator runs in front. | `ast-p2l.3`, `ast-83p.4` |
| A caller who never authenticates can exhaust the address budget for everyone behind their NAT. | A request is charged to the client bucket only when it *succeeded*, which is the property that stops anyone from spending a competitor's budget by naming their `client_id` in a request full of nonsense. The cost of that choice is the mirror case: an attacker inside a corporate NAT fills the address bucket for that endpoint, and a legitimate caller sharing the address who has not yet authenticated once in this window is refused with them. A client that is working is unaffected — its successful traffic is charged to itself — so what is lost is the first request of a cold client during someone else's flood, for at most one window. | `ast-p2l.3` |
| The per-endpoint limiter counts requests it then refuses only once. | Refused requests are not counted, so the counter measures work done rather than work attempted, and a flood does not extend its own window. The audit trail is written once per bucket per window — a marker counter beside the one that was full — because a record per refused request would be an amplification primitive aimed at `audit_events`, the one table where volume cannot be undone. What is lost is the exact size of a flood in the trail; the metric has it. | `ast-p2l.3` |
| `amr` says `swk` for every passkey, and never `pin`. | RFC 8176 distinguishes software from hardware keys and names PIN verification separately. An assertion carries neither fact: attestation is `none` by policy (ADR-0007), so nothing proves hardware, and only the `uvm` extension would report *how* the user was verified. Claiming either would be asserting something unproved to a relying party that may act on it, so this server claims `swk` and adds `user` when the UV bit was set. | `ast-2vk.4`, `ast-2vk.7` |
| `acr` is not set by a passkey sign-in. | The session records `amr` and `auth_time`; the `acr` a tenant policy would map them to is `ast-2vk.7`, which also owns step-up and `acr_values` processing. Until then a relying party asking for an assurance level gets no claim rather than a wrong one. | `ast-2vk.4`, `ast-2vk.7` |
| The consent screen does not name the signed-in user. | It has the session but not a display name; `ast-2vk.8` resolves one. On a shared machine that makes it harder to notice you are approving against somebody else's account. | `ast-uwv.1`, `ast-2vk.8` |
| Every access token issued by the `authorization_code` grant carries a `grant_id`, which is a correlator. | RFC 9068 §6 notes that a JWT access token is readable by whoever holds it, so a resource server presented with two tokens can tell they came from one authorization. This deployment's own resource servers need exactly that: UserInfo resolves claims from the grant the token was minted under, and a person may hold several grants to one client, so without the claim the endpoint would have to guess — and a wrong guess releases the claims of an authorization the token was not minted from. The correlator is per authorization rather than per person, and `sub` is already stable for that pair. Making it a tenant option, so a deployment whose resource servers are all third parties can turn it off, is follow-up work. | `ast-1sk.3` |
| No refresh-token rotation, by default and on purpose. | FAPI 2.0 SP §5.3.2.1 item 9 forbids relying on rotation as a security measure; refresh tokens are sender-constrained and grant-bound instead, so theft without the key is not usable. Rotation detects the replay of a *bearer* token, which this deployment does not issue, and costs the familiar failure where a client that loses one response loses the authorization. What is accepted is the mirror image: a token stolen **together with** the client's DPoP private key is reusable until one of its two deadlines passes or the grant is revoked, and nothing detects it in between, because there is no second use for a rotation scheme to notice. | `ast-a05.5` |
| A tenant may switch rotation on, under `rotation = "migration"`. | FAPI 2.0 SP Note 1's "extraordinary circumstances", and the reason the mode exists is a migration off a server that rotated, where clients in the field discard any refresh token they did not just receive. While it is on there is a grace window in which two refresh tokens are live for one grant — which is the state rotation is supposed to eliminate. It is bounded to an hour, the window is measured from the first supersession so a retry cannot renew it, and every presentation of a superseded token is an audit field. It is still a mode meant to be turned off again, and nothing yet reminds an operator that it is on. | `ast-a05.5` |
| An `offline_access` grant that outlives its browser session reports the authentication the *authorization* recorded, not a later one. | `ast-dlk`. OIDC Core §11 makes `offline_access` access "when the user is not present", so the grant is entitled to outlive the session — and a sweep, a sign-out or a retention policy is exactly what takes that row away. `auth_time`, `acr` and `amr` are therefore copied onto the grant when the authorization completes, and `issuance::session_facts` reads the session while it exists and that copy once it does not, so a refresh after the session has gone issues a token rather than failing as a server-side inconsistency. What is accepted is the gap the two sources can open: a step-up (`ast-2vk.7`) moves the session onto a stronger `acr` and a newer instant and is reported while the session lives, but the grant's copy is not rewritten by it — OIDC Core §2's `auth_time` is when the authentication that produced *this* grant occurred — so the same refresh reports the original authentication once the session is purged. Nothing is invented either way: a grant written before `ast-dlk`, whose session has since been swept, still refuses rather than guess. | `ast-a05.5`, `ast-uwv.3`, `ast-dlk` |
| A remembered consent means a person is not asked again. | `ast-uwv.3`. The grant is the memory — there is no consent table — so a revoked or expired grant stops answering for the user at the instant it stops standing, and every comparison is a subset test per dimension: scopes, the (destination, claim) pairs a §5.5 request would disclose, `authorization_details` compared as canonical JSON text, and RFC 8707 resources. What is accepted is that a consent given once stands until the grant is withdrawn or lapses: a user who agreed in January is not asked again in June, and a client that keeps asking for the same thing never puts it in front of them. `offline_access` is excepted — OIDC Core §11's explicit consent, bounded to ninety days by `consent_memory::DEFAULT_OFFLINE_ACCESS_MEMORY` so a long-lived grant is periodically re-affirmed rather than renewed forever in silence (FAPI 2.0 SP §6.1) — and the per-tenant "always ask" switch turns the whole memory off. | `ast-uwv.3` |
| Grant Management is an Implementer's Draft. | Behind a feature flag, off by default; metadata advertises it only when enabled. | `ast-uwv.4` |
| FAPI 2.0 Message Signing (JAR/JARM/HTTP signatures) not implemented. | Out of v1 scope; the attacker model above does not require it for G1–G3 at this profile level. | `ast-s36.1` |
| A client cannot mint a redirect URI per request, which RFC 9126 §2.4 would allow us to permit. | Declining that relaxation is the point of ADR-0005: it is what keeps a stolen client key from also being a code-exfiltration channel. The cost lands on off-the-shelf MCP clients, which is a compatibility question rather than a security one. | ADR-0005, `ast-m9c.8` |
| A native client that binds a privileged or default port must present `http://127.0.0.1/cb` rather than `http://127.0.0.1:80/cb`, and an internationalised callback must be registered in punycode. | Both follow from refusing to normalise: `:80` and the Unicode host are not forms a URL parser produces, so neither side may spell them that way. RFC 8252 §7.3 expects an ephemeral port, so a real native client is unaffected. | ADR-0005, `ast-m9c.7` |
| The audit hash chain detects tampering, it does not prevent it. | An attacker with arbitrary SQL access can rewrite the whole table *and* recompute the chain; what the chain removes is the quiet single-row edit. Off-box shipping of the chain tip is the real defence. | `ast-p2l.4` |
| Purging a key does not reach a token a third party has already accepted. | `ast-7rq`. A purge destroys the private half, unpublishes the key and makes this server refuse its signatures — everything inside the trust boundary. It cannot recall an access token a resource server validated ten seconds ago against a JWK Set it had cached, and it cannot undo an authorization a relying party already granted on the strength of an ID token. Those are bounded by the token's own `exp` and by whatever revocation the resource server honours, which is why FAPI 2.0 SP §6.8 item 1 asks for short-lived keys *and* short-lived tokens rather than for a destruction button alone. A purge also cannot reach a copy of the ciphertext in a backup taken *before* it, which is a KEK question, not a key question. | `ast-7rq`, `ast-mxc.3` |
| A purge commits before its `key.purged` record is written, exactly as a rotation does. | The same gap and the same reason: the audit sink owns its own transaction. The emptied envelope columns and `purged_at` remain as evidence that the destruction happened, and a failed audit write fails the call, so the missing line is reported rather than silent. | `ast-7rq`, `ast-0ju.9` |
| A rotation commits before its `key.rotated` record is written. | `AuditSink` owns its own transaction and its own per-tenant lock, so the two cannot be one commit. A crash in the gap leaves a rotation whose only evidence is the key rows and their timestamps — which is still evidence, and the states are append-only in practice because nothing moves a key backwards. Making the pair atomic needs the transactional outbox. | `ast-mxc.3`, `ast-0ju.9` |
| `LocalKek` keeps the key-encryption key on the same machine as the database credentials. | It is the development and single-box implementation; an operator who can read the process's environment can usually read its database too, so it defends against a leaked dump and a stolen backup, not against host compromise. The `Kek` port is what a KMS adapter plugs into, and the `kek_id` stored with every row is what makes migrating to one a re-wrap rather than a re-issue. | `ast-mxc.3` |
| A KEK rotation re-seals a pairwise salt by `DELETE` + `INSERT`, not by `UPDATE`. | `tenant_pairwise_salts` refuses `UPDATE` from a trigger, deliberately — an updatable salt is an updatable set of subject identifiers — so `asterius rewrap-kek` re-seals the byte-identical plaintext through the one verb the trigger leaves, in one transaction per tenant, and proves the salt read back unchanged before committing. That window is closed as of `ast-7kw`: with `[keys] kek_previous_*` set, the replicas move to the new key first and retry under the old one whatever the re-wrap has not reached yet. A deployment that declines to configure a previous key still takes the old window — a signer keeps signing from memory, but a restart, a staged key or a first `sub` in a new sector fails until the replicas are moved over. | `ast-xni`, `ast-7kw`, `ast-p2l.4` |
| A configured `keys.kek_previous_*` keeps a retired key-encryption key readable by the process. | Accepted, and bounded by procedure rather than by code. It is what makes a KEK rotation online (`ast-7kw`): during one, a stolen configuration plus a stolen database dump opens rows sealed under *either* key, which is the exposure a rotation is usually meant to end. Three things bound it. It is **optional** — a deployment that is not rotating configures nothing and holds one key. It is **read-only** — `CompositeKek` seals under the current key and has no path that seals under the previous one, so setting it never creates a row that depends on it, and every write moves a row forward. And it is **visible** — the boot logs a `warn` naming both key ids, and every fallback logs a `warn` naming the row, so an operator who has forgotten to remove the line can see it. Step 6 of [the KEK rotation runbook](runbooks/kek-rotation.md) §2 is the removal, and it is the step that ends the rotation. | `ast-7kw` |
| The retention sweep is bounded per pass, so a large backlog takes several passes. | A pass deletes at most a hundred batches of a thousand rows per table per tenant, and reports `more_to_do` when it stops short. The alternative — sweeping until empty — turns the first sweep after an outage into an hours-long transaction holding the tenant's lock, which is a worse failure than being five minutes late. Nothing that survives an extra interval is usable: every read path checks the clock rather than the row's existence. | `ast-p2l.4` |
| Rotating the key-encryption key needs an operator, and both keys at once. | `asterius rewrap-kek` moves every sealed row — signing keys and pairwise salts — under a per-tenant advisory lock, resumably, and refuses a rotation onto the key already in use. It is a foreground command rather than a sweep, because destroying the old material is a decision no timer should take, and both keys have to be readable by the process: `LocalKek` is the only `Kek` implementation, so a KMS rotation is still not a thing this can do. | `ast-xni`, `ast-mxc.3` |
| The IPv4 half of the SSRF guard is a deny-list of IANA's special-purpose registry. | IPv4's global space is defined by subtraction, so an allow-list would be the whole internet minus the same table. A *new* special-purpose assignment would be reachable until the table is updated; IPv6, where global unicast is exactly `2000::/3`, is default-deny and has no such gap. | `ast-mxc.5` |
| The guard confines the fetch to public addresses, not to the client's own server. | "The client's keys live somewhere else" is a legitimate registration, so pointing at a third party cannot be distinguished from it. What is bounded is the traffic: one fetch per client per minute, negative caching, and a cap on size and time. | `ast-mxc.5` |
| Client keys are cached in memory, per process. | The rate limit and the negative cache are therefore per replica: *n* replicas may each fetch a client once per window. Sharing the cache would put a write on the authentication path and make one replica's poisoned entry everyone's; the `client_keys` table in the baseline schema is unused and has no column that could express a negative entry. | `ast-mxc.5` |
| The socket path of the JWK Set fetcher has no automated test. | Its decisions — which URL, which address, which media type, which status — are pure functions with table tests and a fuzz target, and the guard is deliberately impossible to reach from a test that binds a loopback listener, because loopback is what it refuses. Exercising the connection would mean a test-only bypass in the guard, which is worse than the gap. | `ast-mxc.5` |
| A pairwise client whose only redirect URI is a loopback callback is refused a sector at authorization time rather than at registration. | RFC 8252 §7.3 gives every native client the same `127.0.0.1` host, so OIDC Core §8.1's "the host component of the registered redirect_uri" would put every native client in one sector and hand them a correlatable identifier under a registration that says `pairwise`. `SectorIdentifier::of_client` refuses it and asks for a `sector_identifier_uri`; `ClientMetadata::validate` should refuse the same combination at registration, so that it is a rejected document rather than a failed authorization. | `ast-2vk.6`, `ast-m9c.1` |
| A tenant's pairwise salt is never rotated. | Every derived `sub` is stored, so rotating would not move an identifier already issued — but it would make the same user in the same sector derive differently if a row were ever lost, and OIDC Core §8 says a Subject Identifier is never reassigned. Recovering from a leaked salt therefore means reissuing every identifier, which is a relying-party migration and not a rotation. Not merely unimplemented: `PairwiseSalt` has no mutator, the salt is written by an `on conflict do nothing` insert, and `tenant_pairwise_salts` refuses `UPDATE` from a trigger. | `ast-2vk.6`, `ast-2vk.11` |
| A `sub` is not tombstoned when a user is deleted. | Deleting a user cascades over `subject_identifiers`, which frees the identifier for reuse in principle. In practice nothing regenerates one, because the local account id is a random UUID that is never reissued — but "never in practice" is weaker than OIDC Core §8's "never reassigned", and closing the gap needs a tombstone table and therefore a migration. | `ast-2vk.6` |
| `sector_identifier_uri` is not fetched or checked against the registered `redirect_uris`. | OIDC Registration §5 requires the document to be fetched over https and to list every registered redirect URI. That is an outbound fetch with an SSRF guard, and it lives with the other outbound fetches. Until then the sector is taken from the registered URI's host without confirming the client controls the document — which lets a client name a sector it does not own, and so share another group's `sub` values for its own users. | `ast-2vk.6`, `ast-mxc.5`, `ast-m9c.1` |
| A *deployment's* initial access tokens still have no quota. | `ast-cu3` gave the per-tenant tokens one: a token issued through the admin API carries `max_uses` stamped from the tenant's `max_clients_per_initial_access_token`, charged atomically at `POST /register` and given back if the registration does not complete, so a leaked one creates a bounded number of clients and then stops. The tokens an operator configures in the deployment's own file are unchanged — they are strings hashed at boot with no row to count against — so under a deployment-wide `mode = "initial_access_token"` a leaked credential is still bounded only by the per-address limit `ast-p2l.3` put in front of the endpoint. The remedy available today is for the tenant to name its own mode, which moves it onto rows. | `ast-m9c.4`, `ast-p2l.3`, `ast-cu3` |
| A registration commits before its `client.registered` record is written. | The same gap as a key rotation, decided the other way: a rotation fails the call when its audit write fails, but a registration cannot, because the row is already committed and the caller holds the only copy of its registration access token. Refusing after the fact would strand a live client whose owner was told it failed. The gap is logged at `error` with the tenant and `client_id`; making the pair atomic needs the transactional outbox. | `ast-m9c.4`, `ast-0ju.9` |
| A denial at the registration gate is counted but not audited. | An audit row per unauthenticated request would be an amplification primitive aimed at `audit_events`, which refuses `DELETE` outside the retention job — the one table where volume cannot be undone. So only requests that passed the gate are recorded, success or failure. What is lost is the trail of credential-guessing attempts, which is properly a rate limiter's signal rather than an auditor's. | `ast-m9c.4`, `ast-p2l.3` |
| A registration access token presented at the wrong client's URL is refused but not revoked. | RFC 7592 §2.1 says such a token SHOULD be revoked. Honouring it means finding a credential by its digest across the tenant's clients on a request that has not authenticated, and `clients` has no index on `registration_access_token_hash` — a sequential scan per hostile request. `ast-p2l.3` has since put the endpoint behind a per-address limit, which bounds how many such scans a caller can provoke, but does not make the scan itself a good idea. The value is small, since a token that matched belongs to a client its holder already controls completely; the cost is not, since this server issues no client secret and a revoked registration access token has no re-issue path, so one mistyped URL would strand a live client — the state RFC 7592 §5 warns about. | `ast-m9c.11`, `ast-p2l.3` |
| The registration access token is not rotated unless a tenant asks for it. | RFC 7592 §5 makes rotation a MAY on read or update, and OIDC Registration §4.3 argues against doing it on a read at all — so a `PUT` rotates where the tenant's registration policy sets `rotate_registration_access_token`, and a `GET` never does. The delivery problem the MAY creates is solved rather than ignored: the previous token keeps working for a bounded grace window (300 seconds by default, one hour at most), so a client that never received the `200` retries with what it holds, and the predecessor is retired the instant the successor is used. A rotation that could not be written is not announced. The residual is the default: rotation is **off** unless a tenant turns it on, because this server issues no client secret and a client that loses both tokens has no re-issue path — so for every tenant that leaves it off, a leaked token stays valid for the life of the client and the only remedy is to delete the registration and register again. | `ast-m9c.12` |
| The client configuration endpoint distinguishes an existing client from an absent one by timing, though not by its answer. | The response is identical, which is what OIDC Registration §4.4 asks for, and the digest comparison is equalised with a decoy. The database lookup in front of it is not: a row that exists takes longer to not-match than a row that does not. What that leaks is whether a `client_id` is registered, and a `client_id` is 128 bits of CSPRNG output that already travels in the clear in every PAR and authorization request. Closing it would mean a constant-time read against a table, which the storage layer cannot offer. | `ast-m9c.5` |
| The client configuration endpoint is limited by address alone. | `ast-p2l.3` put the RFC 7592 endpoint behind a per-address limit, which is the bound that was missing: guessing a 256-bit token was never the concern, making the process do a database lookup per request was. The bucket is deliberately not keyed by the `client_id` in the path — that segment is written by whoever is guessing, so a bucket named by it would let a caller spend a registration's budget by naming it. The residual is that a caller who moves between addresses gets a fresh budget for each. | `ast-m9c.5`, `ast-p2l.3` |
| Two of the four fields RFC 7592 §2.2 forbids in an update are ignored rather than refused. | §2.2 says an update "MUST NOT include" `registration_access_token`, `registration_client_uri`, `client_secret_expires_at` or `client_id_issued_at`. The first and third are refused, because both describe a credential and a client that asked to set one and got a 200 would believe something false. The other two are computed by this server from values a client cannot influence, so no value it sends changes anything — and they are the two a *read* returns, while §2.2's other sentence requires an update to "include all client metadata fields as returned to the client from a previous registration, read, or update operation". Refusing them would put a field-stripping step in the middle of the flow §2.2 itself prescribes. | `ast-m9c.5` |
| A management change commits before its audit record is written. | The same gap as a registration, and the same reason: the row is already gone or already replaced when the audit write is attempted, and failing the call afterwards would tell a client its delete did not happen when it did. Logged at `error` with the tenant and `client_id`; making the pair atomic needs the transactional outbox. | `ast-m9c.5`, `ast-0ju.9` |
| A read at the client configuration endpoint is audited; a refusal before authentication is not. | Same rule as the registration gate, and a stronger reason: this endpoint is reachable with nothing but a path segment, so an audit row per unauthenticated request would be an amplification primitive aimed at `audit_events`. What is lost is the trail of token-guessing attempts, which is a rate limiter's signal. | `ast-m9c.5`, `ast-p2l.3` |
| The client configuration endpoint sends no CORS headers. | OIDC Registration §4 makes it a SHOULD, for "JavaScript Clients and other Browser-Based Clients". FAPI 2.0 SP §5.3.2.1 permits only `private_key_jwt` and mTLS, so every client here holds a private key and none of them is a page. The SHOULD serves a population this profile does not have. | `ast-m9c.5`, ADR-0002 |
| A closed deployment still advertises `registration_endpoint` in its metadata. | `Endpoint::Registration` has no feature gate, so the discovery document lists it whatever `[registration]` says, and the endpoint answers 403 rather than 404 — the URL is right, the caller is not. Gating the advertisement means a capability flag and a per-tenant one at that, since the bead's policy is per tenant and deployment-wide flags are all there is today. | `ast-m9c.4`, `ast-f7m.4` |
| Registration policy is deployment-wide, not per tenant. | `ast-m9c.4` describes a per-tenant choice, and per-tenant flags are `ast-f7m.4` — the discovery handler carries the same note. Until then every tenant on a process shares one posture, so a deployment that wants open registration for one tenant gets it for all of them. | `ast-m9c.4`, `ast-f7m.4` |
| A registered `redirect_uri` carrying `?code=` makes an error response look like a success. | RFC 6749 §3.1.2 lets a redirect URI hold a query, so `https://rp.example/cb?code=already` is a legal registration; appending an error response to it produces a URL with both a `code` and an `error`, and OIDC Core §3.1.2.5/§3.1.2.6 are two responses rather than one with optional halves — a client reading whichever it finds first gets to be wrong. `AuthorizationResponse::redirect_url` therefore drops every name in `code::RESERVED` from the registered URI before appending its own, so exactly one of each reaches the client. Found by fuzzing, not by review. | `ast-gxh.4` |
| Two tabs both submit the consent form and two codes are minted for one authorization. | FAPI 2.0 SP §5.3.2.2 Note 3 puts one-time use at the *completion* of authorization, so the request is spent by `complete_interaction` — one `update … where consumed_at is null` — **before** anything is minted, and the loser of that statement sends no authorization response at all. Spending after minting would leave a window in which both tabs hold a code. | `ast-gxh.4` |
| A code outlives its window because a tenant is misconfigured. | `code::clamp_lifetime` reduces anything over 60 seconds rather than refusing it, so a bad configuration produces a compliant server rather than one that will not start (FAPI 2.0 SP §5.3.2.1 item 11) — and `authorization_codes` carries the same rule as a `CHECK`, so a row breaking it cannot be written even if the clamp were wrong. | `ast-gxh.4` |
| A code is replayed and the tokens drawn from it stay live. | RFC 6749 §10.5. The revocation happens *inside* `PgCodeRepository::redeem`, not in its caller: a replay and a theft are indistinguishable from there, so the grant and every refresh token on it are revoked before `Replayed` is returned. A caller that had to remember to revoke is a caller that will not. | `ast-gxh.4`, `ast-a05.2` |
| The session ends between consent and the redirect, and a code is issued for a user who is not there. | `mint` reads the session the interaction recorded and checks `Session::status(now).is_usable()`; a session that is gone, idle, expired or revoked produces `access_denied` rather than a code. The grant is what a token traces back to, and one bound to a user whose session has ended is authority nobody granted. | `ast-gxh.4`, `ast-2vk.2` |
| The release image is not reproducible bit-for-bit. | `ast-9mg` closed the provenance half of this: `release.yml` signs each image with cosign keyless (the identity is the workflow file at the tag, so there is no long-lived key to steal) and publishes a CycloneDX SBOM for both the binary and the image, the latter attached as a signed attestation. `docs/deployment/verifying-a-release.md` is the verification procedure. What remains is reproducibility — the `Dockerfile` pins `rust:1.98-bookworm` by tag rather than digest and its apt layer resolves at build time, so a third party cannot rebuild the digest and compare. The signature says *this repository built it*, not *you could build it again*. **Untested in anger: the workflow has not yet run on a tag.** | `ast-p2l.7` |
| The binary is dynamically linked against glibc rather than statically against musl. | ADR-0004 puts the crypto on `aws-lc-rs`, whose musl build still needs a hand-assembled toolchain; a static artefact nobody can reproduce is worth less than a distroless one everybody can. The residual is the base image's own libc surface, which is why the runtime stage carries nothing else — no shell, no package manager, no `curl`. | `ast-p2l.7` |
| The example compose stack terminates no TLS. | It speaks cleartext on the loopback so that a smoke test can reach it without a certificate, which FAPI 2.0 SP §5.2 forbids for anything real. Bounded three ways: the port is published on `127.0.0.1` only, every file in `deploy/compose/` says it is a development stack, and `deploy/README.md` lists TLS first among the changes required before the shape is safe. The reverse-proxy and HSTS guide is still to be written. | `ast-p2l.7` |
| Part of the container hardening lives in the compose file rather than in the image. | `read_only`, `cap_drop` and `no-new-privileges` are properties of how a container is *run*, and no image can assert them for its operator. The image does what it can — a non-root `USER`, no shell to fall back to — and the compose file repeats the rest so that a copied stack starts hardened. A deployment that writes its own manifests has to set them again, and the Kubernetes guidance that would say so is still to be written. | `ast-p2l.7` |
| No formal analysis of the agent extensions. | G4 is ours, not FAPI's, so it has no published formal model. Mitigated by narrowing-only exchange and audit. | `ast-p2l.6` |
| A revoked client certificate keeps authenticating until it expires. | No CRL and no OCSP: both are a network fetch on the authentication path, with the failure-mode question — fail open or fail closed — that comes with one, and OCSP additionally tells the CA which client authenticated and when. A deployment that needs revocation configures it at the proxy that terminates mTLS, which is where such a fetch belongs and where it can be cached across every request rather than per token request. What is bounded meanwhile is the certificate's own validity, which the chain check enforces against the request's clock. | `ast-m9c.3` |
| A client certificate cannot reach this process from its own TLS listener. | `[server] mode = "terminate_tls"` builds the rustls configuration with `with_no_client_auth`, so no certificate is requested during the handshake and none is available afterwards. RFC 8705 §2 therefore works only behind a proxy that terminates mTLS and forwards the certificate. Requesting client certificates from *every* peer — including the browsers that fetch the login pages from the same listener — is a change to the transport that needs its own decision, since a browser shown a certificate request may prompt the person in front of it. | `ast-m9c.3` |
| An mTLS request presenting an intermediate chain is validated against the leaf alone. | A proxy forwards one certificate in one header, in a format it chose; a chain would be a second, per-proxy format this server would have to guess at, and a chain assembled from a guess is a chain this server built rather than one the client sent. So `intermediates` is always empty on the proxy path, and a tenant whose CA issues through an intermediate lists that intermediate in its anchors file. | `ast-m9c.3` |
| The SET issuance tests cross-check a foreign JOSE implementation, but no longer a foreign crypto backend. | `asterius-ssf` verifies its Security Event Tokens with `jsonwebtoken`, so that "the SET verifies against the published JWKS" is not this workspace agreeing with itself. That library was built here on its `rust_crypto` backend — a genuinely independent implementation — until `rust_crypto` was found to pull the `rsa` crate unconditionally, and with it RUSTSEC-2023-0071 (the Marvin timing attack, no fixed version). A SET is only ever EdDSA or ES256 (ADR-0003), so no RSA code could run; but cargo-deny does not distinguish a dev-dependency from a shipped one, and the alternative — an advisory exception in `deny.toml` — teaches this repository that a red supply-chain gate is something to be silenced, on a server whose whole posture is FAPI. So the backend moved to `aws_lc_rs`, which `asterius-jose` also uses. The residual: a bug in aws-lc-rs's Ed25519 or P-256 verification would now be invisible to both sides of the comparison. What the tests still cross-check independently is everything this workspace actually wrote — the signing input, the base64url, `typ`, `kid`, the shape of the published JWK, and the `iss`/`aud` validation a receiver runs — which is where an interop bug in a SET profile lives. Restoring the lower half would mean a direct `ed25519-dalek`/`p256` cross-check of the raw signature, which needs no JWT library and therefore no `rsa`. | `ast-l4n`, `ast-0ju.2` |

## 6. Keeping this file honest

A story is not done until this file reflects it. Concretely, the definition of
done for any protocol story is:

1. a spec-derived or conformance-suite test passes;
2. a fuzz target exists for every new parser or validator;
3. the relevant row here is added or updated, with the bead id, when the
   change moves a trust boundary (a new endpoint, outbound fetch, stored
   secret or principal type) — a change with no attacker-reachable surface
   adds no row;
4. no new `unsafe` (enforced: `#![forbid(unsafe_code)]` in every crate);
5. a human has read the cited spec clause.

## 7. Decisions pending security review

These are not residual risks that have been accepted; they are *choices nobody
has made yet*. Each one was raised while the code was being written, each has at
least two defensible answers, and each needs a human — the owner, or an external
reviewer — to pick one. The options are stated as neutrally as the author could
manage; picking one is not this file's job. Until a decision lands, the row in
§5 (where there is one) is the honest description of what ships.

### 7.1 The admin passkey bootstrap exemption has no bound (`ast-895`)

**What ships.** A deployment-scope admin must have proved a user-verified
passkey ([`crates/domain/src/entities/admin_access.rs`](../crates/domain/src/entities/admin_access.rs)):
the rule reads the session's `amr`, not a claim the browser makes. But the
bootstrap problem is real — a passkey cannot be seeded by an operator, because
it is produced by an authenticator the account holder is standing in front of —
so an account with **no enabled passkey at all** is admitted on its password.
Nothing bounds that exemption in time, nothing pushes the account towards
enrolment, and the only signal is a `warn` per request.

**Options.**
1. Bound the exemption to the first session: the account may use its password
   once, and that session may do nothing but enrol a passkey.
2. Bound it in wall-clock time (a deployment-configured window from account
   creation), after which the account is locked out rather than downgraded.
3. Accept it as documented, on the argument that a deployment admin's password
   is already a high-value secret held to the deployment's own standards, and
   that a lockout with no passkey is an outage with no recovery path.

**What a decision costs.** Options 1 and 2 need a "you must enrol now"
interstitial and a recovery story for the admin who loses their authenticator.
Option 3 needs the `warn` to become something an operator actually sees — an
audit event and a console banner rather than a log line.

**Test coverage gap, whichever way it goes.** The e2e fixture is `tenant_admin`,
which does not exercise the rule; a `deployment_admin` scenario in
[`e2e/tests/console.spec.ts`](../e2e/tests/console.spec.ts) would.

### 7.2 An unreadable audit record is chained but not re-hashed (`ast-9g2`)

**What ships.** The audit reader renders a record it cannot deserialise as
`AuditRecord::Opaque` with an `OpaqueReason`
([`crates/domain/src/audit/record.rs`](../crates/domain/src/audit/record.rs)),
and `chain::verify` traverses it by its stored hash **without recomputing it**
([`crates/domain/src/audit/chain.rs`](../crates/domain/src/audit/chain.rs): an
opaque link contributes its stored hash to the chain). The reason is
structural: the hash is over the canonical form, and canonicalising requires
deserialising — which is precisely what failed. The consequence is stated
plainly: **the content of an opaque record can be altered without detection, as
long as the stored hash is left intact** — and an opaque record is exactly where
an attacker would hide a trace.

**Options.**
1. Hash the stored bytes as they are, so verification never needs to
   deserialise. This changes the chain function and requires a migration that
   recomputes every stored hash — a one-way door, and one that must not run
   while writers are active.
2. Keep canonical hashing but refuse to verify a chain containing an opaque
   link: `verify` reports "unverifiable from record *n*" instead of "intact".
   Cheap, honest, and turns a silent hole into a loud one; it also means one
   corrupt row invalidates the report for everything after it.
3. Accept, with documentation and an alert: an opaque record is itself an
   anomaly, so emit an operational signal when one is read and leave the chain
   semantics alone.

**Why it needs a human.** Option 1 is the only one that closes the hole, and it
is the only one that touches stored data.

### 7.3 mTLS: no client certificate is requested, and no revocation is checked (`ast-m9c.3`)

Two independent decisions, both listed as residual risks in §5 today.

**(a) `terminate_tls` requests no client certificate.**
[`crates/server/src/http/tls.rs`](../crates/server/src/http/tls.rs) builds the
rustls configuration with `with_no_client_auth()`, so mTLS client
authentication ships **behind a trusted proxy only**, through the
client-certificate header ([`docs/deployment/tls-and-proxy.md`](deployment/tls-and-proxy.md) §4).
Asking every peer for a certificate on the listener that also serves the login
and consent pages is a transport decision, not a protocol one: browsers would be
prompted, and a certificate request changes the handshake for everyone.
*Options:* (i) a second, dedicated listener for mTLS clients — the shape RFC
8705 §3 expects, at the cost of a second port and a second certificate; (ii) SNI
or ALPN-based selection on the same port; (iii) keep proxy-terminated mTLS as
the only supported deployment and say so in the certification submission.

**(b) No CRL and no OCSP.** A revoked client certificate authenticates until it
expires. *Options:* (i) fetch a CRL on a schedule and hold it in memory —
bounded, cacheable, stale by design; (ii) OCSP on the authentication path —
fresh, but a network fetch inside a login, with a fail-open/fail-closed choice,
and it tells the CA who is authenticating and when; (iii) OCSP stapling required
of the client, which few clients implement; (iv) accept, and require short-lived
client certificates by policy instead.

### 7.4 Forwarding headers are trusted on configuration alone, and nothing tests the deployment (`ast-4me`)

**What ships.** [`crates/server/src/http/forwarded.rs`](../crates/server/src/http/forwarded.rs)
reads `X-Forwarded-Host`, `Forwarded` and the client-certificate header **only**
when the immediate peer is inside the configured `trusted_cidrs`. That is the
correct server-side rule, and it is the only one a server can enforce: nothing
in a header says who wrote it. So the entire security of the host, the client
address and the client certificate rests on the proxy stripping those headers
from inbound requests — a property of somebody else's configuration file.
[`docs/deployment/tls-and-proxy.md`](deployment/tls-and-proxy.md) §10 gives the
`curl` commands that check it, and §11 says what a proxy must never do; nothing
in this repository runs them against a real deployment.

**Options.**
1. Ship the guide and the checklist, and treat verification as an operator duty
   (what happens today).
2. Add a deployment self-test — a command, or a `--verify-proxy` mode — that
   sends the §10 requests to a live deployment and fails loudly, so that "we
   checked" becomes an artefact rather than a memory.
3. Refuse to start when `trusted_cidrs` is non-empty and a startup probe finds
   the headers are honoured from an untrusted source. Strongest, and the one
   most likely to break a legitimate topology.

### 7.5 Account recovery ends on a password, even for a passkey-only account (`ast-2vk.10`)

**What ships.** [`crates/server/src/http/recovery.rs`](../crates/server/src/http/recovery.rs)
sets a password. An account that had only a passkey therefore comes back from
recovery on a strictly weaker, phishable factor — NIST SP 800-63B §6.1.2.3 is
the clause that objects.

**Options.**
1. Send the user straight into passkey enrolment after recovery (the mechanism
   exists, `ast-2vk.4`) and refuse the session anything else until they do.
2. Refuse email recovery for an account with no password — which then needs an
   answer to "so what *is* the path?" (a second passkey registered in advance, a
   recovery code issued at enrolment, or an administrator).
3. Accept: a recovered account is a password account, and the user may enrol a
   passkey afterwards if they remember to.

### 7.6 Back-channel logout cannot be tested over a socket (`ast-o4u.2`)

**What ships.** `outbound::post` refuses loopback destinations (ADR-0006, the
anti-SSRF guard), and a test relying party on `127.0.0.1` is exactly what the
guard exists to refuse. §2.6 of the OIDC Back-Channel Logout validation is
therefore exercised in-process rather than over a socket.

**Options.**
1. An explicit test hook in the guard — a `cfg(test)`/test-only feature that is
   never compiled into a release binary — so the delivery path is exercised end
   to end.
2. Accept the limit, and rely on the in-process validation plus the conformance
   suite where it covers logout.

A reviewer should note which one is chosen *and* that option 1 puts a
release-gate obligation on the build: a test-only escape hatch in an SSRF guard
is only safe while something proves it cannot reach a release artefact.

## 8. Preparing for an external review

What an auditor should be handed, and the command that produces each artefact.
Every command below exists in `scripts/`, in the `Makefile` or in a workflow in
`.github/workflows/`; a command that does not exist is not listed, however
useful it would be.

| Artefact | How it is produced | Where it lands |
|---|---|---|
| This threat model, and the residual-risk list | read it; §6 is the rule that keeps it current | `docs/threat-model.md` |
| Decision log (ADRs) | read it; ADR-0001 to ADR-0010 | [`docs/adr/`](adr/README.md) |
| Everything CI checks, locally, in fail-fastest order | `./scripts/check.sh` (add `--db` for the database tests) | terminal |
| Format, strict lints, targeted tests | `./scripts/verify.sh <scope>` | terminal |
| Full test suite, as CI runs it | `cargo nextest run --workspace --all-features --no-fail-fast`, then `cargo test --workspace --doc --no-fail-fast` | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) |
| Layering proof (protocol crates cannot reach `sqlx`, `axum`, `tokio`, `hyper`, `reqwest`, `askama`, directly or transitively) | `./scripts/check-layering.sh` | CI job, and locally |
| No `unsafe` in first-party code, three ways | `#![forbid(unsafe_code)]` in every crate root, `./scripts/check-no-unsafe.sh`, `./scripts/check-geiger.sh` | [`.github/workflows/audit.yml`](../.github/workflows/audit.yml) |
| Fuzz coverage: every parser and validator has a target, and no target is orphaned | `./scripts/check-fuzz-coverage.sh`; the committed inventory is regenerated with `./scripts/gen-fuzzing-doc.sh > docs/fuzzing.md` | [`docs/fuzzing.md`](fuzzing.md) |
| Fuzzing results | nightly `cargo fuzz run <target>` over the corpus | [`.github/workflows/fuzz-nightly.yml`](../.github/workflows/fuzz-nightly.yml) |
| Dependency advisories, bans, licences and sources | `cargo deny check advisories bans licenses sources` (configuration in `deny.toml`) | [`.github/workflows/audit.yml`](../.github/workflows/audit.yml) |
| FAPI 2.0 conformance report, and the waivers | `make conformance` (or `./scripts/conformance.sh --help`); the waived modules are `conformance/waivers.json` and the submission checklist is [`docs/certification.md`](certification.md) | [`.github/workflows/conformance.yml`](../.github/workflows/conformance.yml) |
| The release gate that refuses a tag whose conformance report is red or stale | [`.github/workflows/release-gate.yml`](../.github/workflows/release-gate.yml) | CI |
| Supply-chain provenance for a release image (cosign keyless, identity = the workflow at the tag) | [`.github/workflows/release.yml`](../.github/workflows/release.yml) | the registry |
| Browser-facing behaviour: CSP, no-JS baseline, form-post, accessibility | `./scripts/browser-tests.sh --project=<project>` | [`e2e/`](../e2e/README.md) |
| Log redaction and PII minimisation proof | the `log_redaction` tests (`crates/server/tests/log_redaction.rs`) and `fuzz/fuzz_targets/redaction_scan.rs` | CI |
| JSONB sentinel scan (stored JSON cannot smuggle a sentinel past a query) | `./scripts/check-json-sentinels.sh` (needs a database) | CI |
| Performance baseline and the sizing that follows from it | `scripts/load/` (see [`docs/performance.md`](performance.md)) | `docs/performance.md` |
| Running deployment, end to end, from a checkout | `docker compose -f deploy/compose/docker-compose.yml up --build -d` then `./scripts/smoke-test.sh` | terminal |
| Configuration surface, with every key's type, default and secret source | [`docs/configuration.md`](configuration.md) — checked against the code by a test in `crates/server/src/config_reference.rs` | CI |
| Operational procedures | [`docs/runbooks/`](runbooks/README.md): upgrade, KEK rotation, backup and restore | — |
| Vulnerability reporting channel and disclosure policy | [`SECURITY.md`](../SECURITY.md) | — |

**What to tell a reviewer before they start.**

1. **The citations in this file are claims, not evidence.** The verification note
   at the top is the project rule: a human must read the cited clause. An
   external reviewer is the first reader who has not also been the author.
2. **§7 is where the value is.** Six decisions are open, and each one is a place
   where this project would rather have an outside answer than its own.
3. **The FAPI 2.0 conformance suite is an outside judge with a narrow remit.**
   It certifies the profile; it says nothing about the agent extensions (G4),
   which have no published formal model — see the `ast-p2l.6` row in §5.
4. **Scope boundary.** This repository is an authorization server. Several
   residual risks above end at a resource server this project does not ship
   (T-A12, T-A13, T-A1). A review that treats "the RS will check `aud`" as an
   assumption should say so explicitly in its report.
