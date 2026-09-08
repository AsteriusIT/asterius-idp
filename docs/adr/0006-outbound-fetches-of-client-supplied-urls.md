# ADR-0006: How this server dereferences a URL a client chose

- **Status:** Accepted
- **Date:** 2026-09-08
- **Bead:** ast-mxc.5
- **Deciders:** Quentin RODIC

## Context

Several protocol features ask the authorization server to fetch a URL that a
*client* supplied: `jwks_uri` (OIDC Registration §2), `sector_identifier_uri`
(OIDC Core §8.1), a software statement's key set, and — if MCP client-id
metadata documents are ever adopted (`ast-m9c.8`) — a `client_id` that is
itself a URL.

Every one of those turns the server into an HTTP client acting on an
attacker-chosen address, from inside the network perimeter, with whatever
credentials the network grants by position. That is server-side request forgery,
and it is the most valuable thing an OAuth registration endpoint can be tricked
into doing: cloud instance metadata at `169.254.169.254` hands out role
credentials to anything that asks.

The first implementation of this is `jwks_uri` resolution. The policy it
establishes will be inherited by every later fetch, so it is worth settling once
rather than four times.

There is no specification to defer to here. RFC 7591 §5 warns that an
authorization server dereferencing registration URLs "can be used as a vector
for a denial-of-service or SSRF attack" and leaves the mitigation to the
implementer. Two citations that look relevant do not apply: RFC 9700 §4.16 is
*Clickjacking* and OIDC Core §16.2 is *Server Masquerading*.

## Decision

**One outbound path.** All fetching of client-supplied URLs goes through
`asterius_server::outbound`. Not through `asterius-jose`, whose job is
cryptography, and not through ad-hoc calls at each feature — a second path is a
path with a second policy.

**Layering.** The port takes bytes in and bytes out
(`asterius_domain::ports::JwksFetcher`); parsing lives in `asterius-jose`; the
socket lives in `asterius-server`. `scripts/check-layering.sh` bans `hyper` from
`asterius-jose` and that ban is right on its merits: dereferencing an
attacker-chosen URL is a security decision with its own surface, and it belongs
next to the socket in a file small enough to read whole.

**The address is checked, not the name.** The name is resolved once, *every*
returned address is checked, and the connection is made to a vetted
`SocketAddr`. The hostname is then used only as the TLS `ServerName`, matched
against a certificate. This is what closes DNS rebinding: no name is handed to
anything that could resolve it a second time. A mixed answer — some addresses
permitted, some not — fails as a whole rather than falling back to the
permitted ones.

**IPv6 is default-deny, IPv4 is deny-list.** Only `2000::/3` is permitted for
IPv6, minus Teredo, 6to4 and documentation ranges. IPv4 has no equivalent
"public" prefix, so it is a deny-list: loopback, link-local (including
`169.254.169.254`), private, CGNAT, documentation, benchmarking, multicast and
class E. The asymmetry is a real residual risk and is recorded as one — a new
IANA special-purpose IPv4 assignment would be permitted until the list is
updated.

**Redirects are never followed.** A redirect is a second URL chosen by someone
else after the first was vetted. Re-vetting it would be possible; not following
it is simpler and costs a client nothing it cannot fix by publishing its keys
where it says they are.

**Failures are cached.** A negative cache and a refresh rate limit exist so that
an unreachable `jwks_uri` cannot be used to make this server hammer a third
party, and so that a stream of unknown `kid`s cannot force a fetch each time.

**Non-443 ports are allowed.** Registration does not restrict them, and a client
that registers successfully but can never authenticate is a worse failure than
the marginal risk: reaching a non-TLS service on an unusual port still requires
it to complete a TLS handshake with a publicly trusted certificate for the
requested name, which it cannot.

## Consequences

**Easier.** Every later feature that dereferences a client URL inherits a
policy that has already been argued about, and a single place to change it.
The address-checking predicate is pure, so the interesting decisions are
table-tested without a network.

**Harder.** The socket path itself has no automated test, because exercising it
would need a test-only bypass in the guard — loopback is exactly what it
refuses — and a bypass that exists in the binary is worse than the gap. The
decisions it depends on are tested; the wiring is reviewed.

**What this does not stop**, stated plainly so nobody assumes otherwise: a
client can still aim the server at a *public* third-party host, which is
indistinguishable from legitimate hosting and is bounded by caching rather than
by the guard; a public host that proxies inward defeats it entirely; and an
operator who gives internal services public addresses has removed the
distinction the guard relies on.

## Spec clauses

| Clause | What it requires | How this decision satisfies it |
|---|---|---|
| RFC 7591 §5 | Warns that dereferencing client-supplied registration URLs is an SSRF and DoS vector; mitigation is left to the implementer | A single vetted outbound path, address-level checks, no redirects, negative caching and rate limiting |
| OIDC Registration §2 | `jwks_uri` is a URL the AS fetches to obtain client keys | Fetched only over the vetted path, parsed against the ADR-0003 algorithm allow-list |
| FAPI 2.0 SP §5.4.2 | Do not use `x5u` or `jku`; do not serve duplicate `kid`s | Neither header is honoured; duplicate `kid`s are resolved by trying candidates (SP §5.4.3) |
