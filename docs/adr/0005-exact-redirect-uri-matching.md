# ADR-0005: Redirect URIs are matched exactly against the registered set, including under PAR

- **Status:** Accepted
- **Date:** 2026-09-08
- **Bead:** ast-m9c.7
- **Deciders:** Quentin RODIC
- **Refines:** [ADR-0002](0002-fapi-2-0-as-the-only-mode.md)

## Context

Exact matching is the baseline everywhere. RFC 6749 §3.1.2.3: "If the client
registration included the full redirection URI, the authorization server MUST
compare the two URIs using simple string comparison as defined in [RFC3986]
Section 6.2.1." RFC 9700 §4.1.3 says why, having just spent §4.1.1 on what
pattern matching costs:

> The complexity of implementing and managing pattern matching correctly
> obviously causes security issues. This document therefore advises simplifying
> the required logic and configuration by using exact redirection URI matching.

But both documents then hand back an exception that this product, uniquely,
qualifies for. RFC 9700 §4.1.3 closes with:

> If the origin and integrity of the authorization request containing the
> redirection URI can be verified, for example, when using [RFC9101] or
> [RFC9126] with client authentication, the authorization server MAY trust the
> redirection URI without further checks.

and RFC 9126 §2.4 spells the same relaxation out:

> The exact matching requirement MAY be relaxed when using PAR for clients that
> have established authentication credentials with the authorization server.
> […] The authorization server MAY allow such clients to specify "redirect_uri"
> values that were not previously registered with the authorization server.

ADR-0002 makes PAR the only way to start an authorization request and
`private_key_jwt`/mTLS the only ways to authenticate, and FAPI 2.0 SP §5.3.2.2
item 6 requires the `redirect_uri` parameter in a pushed request. So Asterius
satisfies the precondition of that relaxation on **every** request, by
construction. The question is therefore real rather than rhetorical: we could
drop the registered set for the authorization flow entirely and nothing in the
profile would object.

The argument for taking it is client management. RFC 9126 §2.4 is candid that
"the redirect URI is typically the most volatile part of a client policy", and
per-request redirect URIs are exactly what an MCP-style or dynamically deployed
client wants. The argument against is what the relaxation actually assumes:
that authenticating the client is the same thing as knowing where the code
should go.

## Decision

**A redirect URI is accepted only if it is byte-equal to one in the client's
registered set** — at registration, at PAR (`ast-gxh.1`) and at the token
endpoint (`ast-a05.2`), through one function,
`RedirectUri::is_registered` in `asterius-domain`. The RFC 9126 §2.4 and
RFC 9700 §4.1.3 relaxations are declined.

Concretely, what "byte-equal" means here:

- **RFC 3986 §6.2.1 simple string comparison, and nothing else.** No prefix, no
  pattern, no case folding, no percent-decoding, no IDNA equivalence. A trailing
  slash, a path in different case, an added query parameter, userinfo, an
  explicit `:443` and the Unicode spelling of a punycode host are all different
  URIs.
- **The registered bytes are never normalised.** A URI that is not already the
  form a URL parser produces is *refused*, not rewritten — because rewriting
  changes what the client must send back, and keeping a rewritable form stores
  a string no browser request can carry. `https:///cb` (whose empty authority
  resolves to the host `cb`) and `https://пример.example/cb` (which travels as
  punycode) are the two shapes that make this concrete. This is the opposite
  choice from the issuer identifier, which *is* normalised once at the boundary
  because an operator writes it by hand into a configuration file and then never
  touches it again; a redirect URI has no such moment, and the contrast is
  commented at both ends in the code.
- **`https` only, with one exception.** FAPI 2.0 SP §5.3.2.2 item 8: an
  authorization server "shall not allow redirect URIs that use the "http" scheme
  except for native clients that use loopback interface Redirection as described
  in Section 7.3 of [RFC8252]".
- **The loopback exception varies the port and nothing else.** RFC 8252 §7.3:
  "The authorization server MUST allow any port to be specified at the time of
  the request for loopback IP redirect URIs". RFC 8252 §8.4 states the residue
  exactly — "the exception is loopback redirects, where an exact match is
  required except for the port URI component" — and that is what is implemented:
  scheme, host, path and query stay byte-equal.
- **`http://localhost` is not the exception.** RFC 8252 §8.3 says the use of
  `localhost` is NOT RECOMMENDED because it resolves through name resolution;
  only the IP literals `127.0.0.0/8` and `[::1]` qualify.
- **Private-use ("custom") schemes are refused outright.** RFC 8252 §7.1's
  scheme-based redirection is interceptable by any application on the device,
  and RFC 8252 §8.4 classes the clients that use it as public clients — of which
  ADR-0002 has none. There is no client here a custom scheme could belong to.

The **placement** of the loopback rule is deliberate and is the one design
decision inside this that a reader might reasonably take the other way.
Admissibility — may this URI enter the registered set at all — is in
`RedirectUri::parse`, so only a native client can register a loopback `http`
URI. Equivalence — is this presented URI that registered one — is in
`RedirectUri::matches`, and that is where the port is allowed to vary. The
alternatives both fail: normalising the port away at registration would rewrite
the bytes that *are* the comparison, and storing a port wildcard would put a
pattern back into the registered set, which is the thing RFC 9700 §4.1.3
removed.

### Alternatives rejected

- **Trust the pushed redirect URI (RFC 9126 §2.4, RFC 9700 §4.1.3).** Client
  authentication proves the request came from something holding the client's
  key. It does not prove the key is still only in the client's hands, and it is
  precisely the key-compromise case where the difference matters: with the
  relaxation, one stolen `private_key_jwt` key is a complete authorization-code
  exfiltration channel — push a request with a redirect URI the attacker
  controls, receive the code. With exact matching, the same stolen key still has
  to deliver the code to the honest client's registered callback, where the
  legitimate client and its logs are. That is not a hypothetical improvement:
  it is the difference between "the attacker can act as the client" and "the
  attacker can also silently harvest users".
- **Relax with a prefix or a varying query parameter** — the shape RFC 9126 §2.4
  suggests ("the authorization server MAY require a certain URI prefix or allow
  only a query parameter to vary at runtime"). This is pattern matching by
  another name, and RFC 9700 §4.1.1 is a catalogue of how it goes wrong. It also
  would not survive contact with our own rule that nothing is normalised: a
  prefix test over unnormalised bytes is a different test than a prefix test
  over URLs.
- **Make it a per-client switch.** ADR-0002 already refused this shape of
  answer: a weaker path that exists for one client exists for the deployment.
- **Follow RFC 6749 §3.1.2.2's fallback** ("registration of the URI scheme,
  authority, and path, allowing the client to dynamically vary only the query
  component"). Superseded in practice by RFC 9700 §4.1.3, which is the current
  BCP and says exact.

## Consequences

**Easier.** There is one redirect-URI comparison in the product and three
callers of it, so the authorization endpoint and the token endpoint cannot
develop different opinions about the same URI — which is a real failure mode,
since RFC 6749 §4.1.3 makes the token endpoint re-check the value. The
registered set stays a static, reviewable artefact: an operator reading a
`clients` row knows every place that client's codes can be delivered, and an
incident responder does not have to reconstruct it from PAR records.

**Harder.** A client that mints a redirect URI per request cannot work here, and
that is the population of off-the-shelf MCP clients almost exactly. `ast-m9c.8`
owns that decision and this record is one of its inputs; the answer is not
"relax matching" but "register the callbacks", and if that turns out to be
untenable it is a new ADR superseding this one, not a flag.

Two smaller edges follow from refusing to normalise, and both are deliberate:

- A native client that binds port 80 must present `http://127.0.0.1/cb`, not
  `http://127.0.0.1:80/cb` — the second is not a form a URL parser produces, so
  neither side may spell it that way. RFC 8252 §7.3 expects an ephemeral port,
  so this costs a real client nothing.
- A client whose callback lives on an internationalised domain must register the
  punycode form, because that is the form the browser will send.

Registration uses the same comparison as everything else, so two loopback
entries differing only in their port are **one** registration and the second is
refused as a duplicate. Without that, `MAX_REDIRECT_URIS` could be filled with
port variants of a single callback, and the set would stop being a set under the
relation the authorization endpoint actually uses.

**To maintain.** `ast-gxh.1` and `ast-a05.2` must call
`ClientRegistration::accepts_redirect_uri` rather than comparing strings
themselves; a second comparison anywhere in the server re-opens exactly the gap
this record closes. The fuzz target `redirect_uri` asserts the invariants
against a structured URI generator, including that normalisation is never
applied and that two different strings can only ever match across a loopback
port.

## Spec clauses

| Clause | What it requires | How this decision satisfies it |
|---|---|---|
| RFC 6749 §3.1.2.2 | The AS SHOULD require registration of the complete redirection URI prior to use of the authorization endpoint | Registration is required for any client holding `authorization_code`, and the complete URI is what is stored |
| RFC 6749 §3.1.2.3 | Compare the received value against a registered one "using simple string comparison as defined in [RFC3986] Section 6.2.1" | `RedirectUri::matches` is `==` on the registered bytes, with only the RFC 8252 §7.3 port exception |
| RFC 3986 §6.2.1 | Equivalence is character-for-character identity of the two URIs | The registered bytes are stored unchanged and compared unchanged; nothing is decoded or folded first |
| RFC 9700 §4.1.3 | Exact matching, no pattern matching; the only exception is a native app's loopback URI, where variable ports MUST be allowed | Implemented as stated; the MAY that permits trusting a PAR-pushed URI is declined, and the reason is recorded above |
| RFC 9126 §2.4 | The exact-matching requirement MAY be relaxed under PAR with client authentication | Declined. The registered set is consulted on every pushed request |
| RFC 8252 §7.3 | "The authorization server MUST allow any port to be specified at the time of the request for loopback IP redirect URIs" | Any port matches a registered loopback URI for a native client, including none |
| RFC 8252 §8.3 | Use of `localhost` rather than the loopback IP literal is NOT RECOMMENDED | `http://localhost` is refused at registration; only `127.0.0.0/8` and `[::1]` qualify |
| RFC 8252 §8.4 | Exact match required, "the exception is loopback redirects, where an exact match is required except for the port URI component"; private-use schemes belong to public clients | The port is the only component that varies; private-use schemes are refused, since ADR-0002 admits no public clients |
| FAPI 2.0 SP §5.3.2.2 item 6 | "shall require the `redirect_uri` parameter in pushed authorization requests" | PAR (`ast-gxh.1`) requires it and checks it against the registered set |
| FAPI 2.0 SP §5.3.2.2 item 8 | "shall not allow redirect URIs that use the http scheme except for native clients that use loopback interface Redirection as described in Section 7.3 of [RFC8252]" | `https` is required except for a loopback IP literal on `application_type=native` |

Every clause listed here must have been read by a human, not only cited.
