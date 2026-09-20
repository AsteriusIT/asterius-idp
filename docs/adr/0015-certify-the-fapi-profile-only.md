# ADR-0015: Certify the FAPI profile only

- **Status:** Accepted
- **Date:** 2026-09-20
- **Bead:** ast-p2l.2
- **Refines:** [ADR-0014](0014-explicitly-gated-standard-oidc-clients.md)
- **Deciders:** Quentin RODIC

## Context

The OpenID Foundation's FAPI 2.0 Security Profile plan exercises the profile
Asterius treats as its security baseline: confidential clients, PAR, PKCE and
sender-constrained tokens. Its OpenID Provider Basic, Config, Dynamic and Form
Post plans instead begin authorization requests without PAR. Accepting those
requests for a FAPI client would contradict FAPI 2.0 Security Profile
§5.3.2.2 item 3, which requires the authorization server to reject an
authorization request that was not received through PAR.

ADR-0014 subsequently added an explicitly opted-in standard OIDC profile for
conventional confidential applications. That compatibility profile does not
make a non-PAR request conform to FAPI, and its existence does not justify a
hidden certification-only behavior that differs from the profile being
certified.

## Decision

Asterius pursues the **FAPI 2.0 Security Profile certification only**, using the
existing `private_key_jwt` and DPoP variant. The mTLS variant may be submitted
when that feature is supported, and compatible logout profiles may be tested
separately without changing authorization-request handling.

We do not add a `conformance_mode`, a certification tenant, or any other
test-only switch that permits non-PAR authorization requests for a FAPI client.
The conformance harness exercises the same FAPI path deployed in production.
An application explicitly assigned the standard OIDC profile under ADR-0014
remains outside the FAPI certification claim; it is not a mechanism for earning
an OpenID Provider mark while representing the FAPI baseline as unchanged.

The following alternatives are rejected:

- **Add a tenant-scoped conformance mode.** It creates a second authorization
  contract solely to satisfy a test plan and makes a certification run unlike
  the product profile whose guarantees are being claimed.
- **Use the standard OIDC compatibility profile for Core certification.** The
  result would certify that optional profile, not the FAPI path, and would make
  the release claim easy to overstate.
- **Skip certification entirely.** The implemented FAPI plan and release gate
  already provide useful, profile-aligned evidence.

A future customer requirement for OpenID Provider certification requires a new
decision with an explicit claim boundary. It must not weaken FAPI clients or be
smuggled into the release build as a test-only exception.

## Consequences

The certification statement stays precise: reports and release gates establish
conformance of the FAPI client profile, not every optional client profile the
deployment can host. Production and conformance use one authorization path, so
there is no dormant downgrade switch to secure, document or accidentally
enable.

Asterius does not claim the OpenID Provider Basic, Config, Dynamic or Form Post
marks. Deployments that require those marks need a separately justified product
and certification decision. Logout interoperability can still be validated
where its plan is compatible with the FAPI authorization baseline.

## Spec clauses

| Clause | What it requires | How this decision satisfies it |
|---|---|---|
| FAPI 2.0 Security Profile §5.3.2.2 item 3 | Reject authorization requests not received through PAR | The certified FAPI path remains PAR-only, with no conformance exception |
| RFC 9126 §2 | Push an authorization request to the authorization server and use the returned request URI at the authorization endpoint | The FAPI conformance plan uses the production PAR flow |
| OpenID Connect Core §3.1.2.1 | A standard Authorization Code Flow request is sent to the authorization endpoint | Asterius does not claim Core OP certification by changing the FAPI path to accept this request shape |
