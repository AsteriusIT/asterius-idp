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
- **Message signing (JAR/JARM)**: a separate plan;
  `request_parameter_supported` is `false`.
- **OpenID Connect Core plans**: gated by decision E16_02.

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
  the suite's claim list; the SKIPPED is RS256, which ADR-0003 refuses to offer.
- **FAILED, or finished with no verdict**: red, unless waived.
- A waiver names an open beads ticket.
  `crates/server/tests/conformance_plan.rs` fails the per-PR pipeline if that
  ticket is closed or unknown, so a waiver cannot outlive the decision behind
  it.

## What is waived today

One module, and the submission has to say so:

| module | ticket | why |
| --- | --- | --- |
| `fapi2-security-profile-final-user-rejects-authentication` | `ast-k5u` | The module needs the person at the browser to refuse. The only refusal this server offers is *Deny* on the consent screen, and that screen is skipped once the tenant remembers a consent covering the request. Fixing it is a product decision — a per-tenant "always ask" setting, a refusal on the login page, or accepting that this one module is driven by hand at submission time. |

Last full run, 2026-09-10, 56 modules: **48 PASSED, 5 REVIEW, 1 WARNING,
1 SKIPPED, 1 FAILED** — the FAILED being the waived module above.

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
