# ADR-0016: Keep the CIBA assertion audience profile scoped to CIBA

- **Status:** Accepted
- **Date:** 2026-09-25
- **Bead:** ast-s36.27.1
- **Deciders:** Quentin RODIC

## Context

[CIBA Core 1.0 §7.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
requires an OP using JWT client assertions at its backchannel endpoint to
accept its issuer identifier, token endpoint URL, or backchannel endpoint URL
as the audience. The [RFC 7523 audience update draft-11](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11)
requires the issuer identifier as the sole audience for ordinary JWT client
authentication. It updates RFC 7523 but does not name CIBA among the
specifications it updates.

CIBA's three values are a final, endpoint-specific interoperability rule. The
draft is still work in progress. Removing the two endpoint URLs now would
make this implementation reject assertions that CIBA requires it to accept.

## Decision

Keep the CIBA Core audience set only at the CIBA backchannel authentication
endpoint. Other JWT client authentication endpoints continue to require the
exact tenant issuer as the sole audience. The CIBA assertion still has one
string audience, never an array, and all three accepted values come from this
tenant's canonical endpoint configuration. The usual signature, client,
expiry and replay checks remain in force. Revisit this decision if a final
RFC or a new CIBA profile changes the rule.

## Evidence and limits

`backchannel_authentication::assertion_rules` is the only caller of
`Audiences::ciba_backchannel`. Source-level conformance cases named
`the_assertion_audience_is_the_three_values_the_specification_names` and
`no_other_endpoint_widens_its_audiences` compare the exact accepted values
for CIBA and the generic issuer-only rule. These tests were not executed in
this session at the user's request. External client interoperability has not
been measured; this decision relies on the published CIBA rule.
