# Supported Provider Commands interoperability evidence

The owned runtime at source `97ac7245561064d2f58fbc8c48581f62ee72c451`
passed [25 real checks](integrations/evidence/provider-commands-2026-10-08.json)
against the [independent controlled RP](../scripts/integrations/provider_command_peer.mjs).
The consumer uses native Node crypto and no Asterius verifier. This exercises
[OpenID Provider Commands draft02](https://openid.net/specs/openid-provider-commands-1_0.html),
published 25 September2025, for the supported synchronous invalidate/delete
account commands. It is interoperability evidence for those flows, without a
claim of formal certification or support for the complete draft.

The guarded admin API created an owned Basic OIDC client with a pinned public
HTTPS command endpoint and a separate account/password. A real browser code
flow with PKCE and nonce established that account at the RP. The independent RP
verified the signed ID token and retained its exact subject; the database's
claimed-grant trigger retained the same RP subject for lifecycle delivery.

Actual conditional SCIM transitions drove the production outbox. The consumer
verified `command+jwt`, a published OP signing key, exact issuer, command endpoint
audience, registered client, tenant and known RP subject, integer bounded times,
unique `jti`, permitted claim shape and absence of ID-token `nonce`. Supported
signatures are ES256 and EdDSA. A first signed invalidate received a deliberately
invalid 204 response without `Cache-Control: no-store`; Asterius marked delivery
abandoned, and the controlled consumer made no account/session change. After
reactivation and a fresh disable, a newly signed invalidate returned HTTP200
with `no-store` and correct subject/account state. The producer marked delivery
delivered, and the RP revoked its sessions/tokens while retaining the account.
Actual SCIM deletion delivered a signed delete, returned HTTP200, and changed the
RP account to unknown. SCIM read then returned404 for the deleted account.

Private receiver probes reused the actual signed invalidate. Replay returned400;
a changed pinned issuer returned401 `unrecognized_provider`; a changed pinned
command audience and controlled expired clock returned400 `invalid_request`.
A receiver policy refusing the signed command returned400 `unsupported_command`;
a changed signature returned400 `invalid_request`. Each preserved RP state.
These are explicitly consumer refusal probes, not claims that Asterius emitted
incorrectly signed or incorrect-issuer/audience tokens. Guarded registration also
rejected an unsafe HTTP/loopback command endpoint with400 before client creation.

The [browser harness](../scripts/integrations/provider_command_browser.mjs)
accepts a private mode-0600 JSON with `manifest`, `automation`, `publicOrigin` and
`evidence`. Set `NODE_EXTRA_CA_CERTS` to the owned fixture CA, the installed
`ASTERIUS_PLAYWRIGHT_MODULE`, and `ASTERIUS_ACCEPTANCE_DB_CONTAINER` to the owned
fixture database container. Run:

```sh
node scripts/integrations/provider_command_browser.mjs <private-input.json>
```

The allowlisted public relay forwards only `/provider-command-peer/command` to
loopback14900; the independent RP callback uses HTTPS localhost18449. The relay
and Asterius outbound transport retain certificate checks and the public-IP
SSRF guard. Raw tokens, subjects, codes, passwords and client secrets stay in
memory/private input and are omitted from evidence. The harness removes only
its exact owned account/client UUIDs after public SCIM deletion has been checked;
SCIM's retained tombstone is not misreported as physical deletion. Previous
failed-attempt owned fixture rows were separately removed and verified.

IPSIE selected profile evidence is recorded separately in
[the readiness matrix](ipsie-readiness.md). Production deployment controls,
metadata/migrate/tenant/asynchronous commands and broad encryption key overlap
remain outside the implemented offering. No production users or remote cloud
objects were changed.
