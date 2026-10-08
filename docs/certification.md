# FAPI 2.0 certification: submission checklist

What to run, what is knowingly not green, and where the evidence is. The
harness itself is documented in [`conformance/README.md`](../conformance/README.md);
this file is the short version somebody follows on the day of a submission.

## The plan, and its variants

One plan, `fapi2-security-profile-final-test-plan`, with exactly these variants:

| variant | value |
| --- | --- |
| `openid` | `openid_connect` |
| `client_auth_type` | `private_key_jwt` |
| `sender_constrain` | `dpop` |
| `fapi_profile` | `plain_fapi` |
| `authorization_request_type` | `simple` |

`client_registration` is not a variant: the clients are static because
`conformance/plans/fapi2-sp-final.json` carries a `client_id`.
`fapi_request_method` and `fapi_response_mode` are fixed by the plan itself.

Not submitted, and why:

- **mTLS** (`client_auth_type=mtls`, `sender_constrain=mtls`). The server does
  not offer it: `features.mtls` is off and the discovery document announces
  `private_key_jwt` alone. `ast-m9c.3` is the work. The job exists behind the
  `mtls` input of `.github/workflows/conformance.yml` and refuses to run until
  the flag is on, so the day it ships the plan is one line away.
- **Message signing (JAR/JARM)**: independently exercised as a separate,
  explicitly selected client profile, but not formally submitted for OIDF
  certification. The ordinary FAPI Security Profile keeps
  `request_parameter_supported` set to `false`.
- **OpenID Connect Core plans**: not submitted.
  [ADR-0015](adr/0015-certify-the-fapi-profile-only.md) selects FAPI-only
  certification and rejects a `conformance_mode` or other test-only exception
  for non-PAR requests. The standard OIDC compatibility profile from
  [ADR-0014](adr/0014-explicitly-gated-standard-oidc-clients.md) remains outside
  the FAPI certification claim.

## Running it

```bash
make conformance          # build, run the plan, tear the stack down
make conformance-keep     # the same, leaving the suite's UI up to inspect
```

`CONFORMANCE_HTTPS_PORT` moves the suite's UI if 8443 is taken on the machine;
the links inside the exported reports still say 8443, because that is the port
the suite listens on inside its own network.

In CI: `.github/workflows/conformance.yml` — nightly, on demand from the Actions
tab, and on every push to a `release/**` branch.

## The verdict

`scripts/conformance-verdict.py` decides, from the run's `verdict.json` and
`conformance/waivers.json`. Not `run-test-plan.py`'s exit code, which reports
"a module did not pass" for modules that cannot pass here.

- **PASSED, REVIEW, WARNING, SKIPPED**: green. REVIEW is the suite asking a
  human to look at a screenshot the harness already uploads; the WARNING is
  `sid` in the ID token, required by Back-Channel Logout 1.0 §2.1 and unknown to
  the suite's claim list. The RSA negative modules are skipped when the
  independently configured client keys use ES256; a skip is not RSA evidence.
- **FAILED, or finished with no verdict**: red, unless waived.
- A waiver names an open beads ticket.
  `crates/server/tests/conformance_plan.rs` fails the per-PR pipeline if that
  ticket is closed or unknown, so a waiver cannot outlive the decision behind
  it.

## Current independently executed evidence

The final 2026-10-08 independent runs used clean source
`0b4c7a4a4486fb981ac18dac39b9a8431065accc` and the exactly labelled prebuilt
GNU runtime image `asterius-idp:local-ticket-final-composed-20261008`:

- **Security Profile Final:** all 56 modules executed; 50 PASSED, 4 REVIEW,
  1 WARNING, 1 SKIPPED, 0 FAILED.
- **Message Signing Final:** all 70 modules executed; 63 PASSED, 4 REVIEW,
  1 WARNING, 2 SKIPPED, 0 FAILED.

Both repository gates passed with empty waiver lists. Each plan's four REVIEW
artifacts were inspected: missing PAR and foreign-client request URIs return
HTTP400; completed/reused and expired handles return HTTP404. Each captured
response is a local HTML error page with “This sign-in request cannot be
continued.” The browser remains at the authorization endpoint without an unsafe
client callback. The generic wording avoids revealing whether a handle is
unknown, expired or consumed. The official REVIEW results remain unchanged;
this assessment does not constitute OIDF human submission approval.

The WARNING identifies the `sid` extension claim. The RSA negative modules did
not execute because the client fixture uses ES256: client assertions in both
plans, and request objects additionally in Message Signing. These runs do not
establish RSA interoperability or default musl Dockerfile packaging. OIDF
certification and coverage of every supported profile are not claimed.

Earlier Message Signing failures exposed strict `typ` compatibility, the local
missing-PAR browser error format, and the error code for forbidden parameters
inside a verified signed request object. Their narrow fixes passed targeted
regressions before the final full independent plans above.
[Sanitized outcomes and manual artifact assessments](integrations/evidence/oidf-fapi-2026-10-08.json)
record all runs and their bounds. Raw exports, keys and tokens remain private.

The separate [independent RFC 9701 consumer evidence](integrations/evidence/rfc9701-independent-consumer-2026-10-08.json)
records thirteen successful controls on later source
`97ac7245561064d2f58fbc8c48581f62ee72c451`, including real authenticated token
introspection, independent Ed25519 verification, privacy envelopes and refusal
controls. This later consumer run does not move the 126 official suite verdicts
to the newer revision or constitute OIDF certification.

## Where the evidence is

Per run, in `conformance/.run/results/` locally and in the `conformance-report`
artefact of the workflow run (30 days):

- `export/*.zip` — the machine-readable result archive from
  `run-test-plan.py`. **This is what a certification submission is made of.**
- `report-<planid>.zip` — the suite's HTML report for the plan.
- `verdict.json` — one line per module, plus the revision and the plan. Also
  published on its own as the `conformance-verdict` artefact (90 days), which is
  what the release gate reads.

## Tagging a release

`.github/workflows/release-gate.yml` runs on `v*` tags. It takes the newest
completed run of `conformance.yml` — preferring one on the commit being tagged —
downloads its verdict and refuses the tag if a module failed without a waiver,
or if the report is more than 24 hours old.

So, before tagging: run the conformance workflow on the commit, wait for it to
be green, tag within the day. The gate can be run from the Actions tab
beforehand to find out the answer while it is still cheap to act on.

The gate is no longer triggered by the tag directly. `release.yml` owns the
`v*` trigger and calls `release-gate.yml` as a reusable workflow
(`jobs.gate.uses`), so the verdict is still applied to every tag and applied
once, and no image is built or signed behind a red one. What a tag then
publishes, and how anyone can check it from the outside, is
[`deployment/verifying-a-release.md`](deployment/verifying-a-release.md).
