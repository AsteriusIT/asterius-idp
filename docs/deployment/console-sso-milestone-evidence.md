# Console and SSO milestone evidence

This is the release audit snapshot for `ast-6uqw.15`, captured on 2026-09-20.
It records what was actually observed; it is **not a release approval**. The
candidate exists only in local commits at this snapshot, so no remote check is
evidence for its exact revision.

## Local focused browser evidence

The integrated candidate through local merge `e4211ed` was exercised against a
real Asterius process with the JavaScript Playwright project:

```sh
E2E_RESET_DB=1 ./scripts/browser-tests.sh --project=js \
  e2e/tests/groups.spec.ts e2e/tests/sso-demo.spec.ts e2e/tests/console.spec.ts \
  --grep 'group membership|two confidential|branding|authentication assurance editor|policy editor'
```

Five journeys passed: branding validation/save/runtime sign-in rendering,
branding reset/refusal/unsaved state, authentication-assurance editing, managed
group membership with effective application roles, and two-confidential-BFF
SSO/logout. The policy-editor journey exposed an incorrect console URL: it sent
the probe outside `/admin/api/v1` and received 404. The route was corrected and
the failed journey was repeated with:

```sh
E2E_RESET_DB=1 ./scripts/browser-tests.sh --project=js \
  e2e/tests/console.spec.ts --grep 'policy editor refuses'
```

That journey then passed (one passed, zero failed). Together these runs cover
all six selected journeys, including the real saved branding at the sign-in
runtime; they do not claim the unrun browser matrix.

The single permitted final targeted verifier (`./scripts/verify.sh console
policy`) completed formatting and strict Clippy, then stopped after 66 passing
tests and two integration failures. It found the branding URL placeholder in
the embedded-bundle origin audit and a stale registration-policy assertion that
still rejected the ADR-0014 `client_secret_basic` method. Both inconsistencies
were corrected, and `cargo check` then passed. The verifier was not run a
second time because repository policy permits exactly one final invocation;
therefore this snapshot does not call the targeted Rust result green.

## Remote evidence and disposition

| Evidence | Revision and time | Observed outcome | Release meaning |
| --- | --- | --- | --- |
| Required CI, [run 35490524519](https://github.com/AsteriusIT/asterius-idp/actions/runs/35490524519) | `f7c8d734`, 2026-09-20 | Red | It predates the local milestone and cannot clear it. |
| FAPI conformance, [run 35500540377](https://github.com/AsteriusIT/asterius-idp/actions/runs/35500540377) | remote `main`, 2026-09-20 | Red: 10 failed modules and interrupted modules | [Issue #72](https://github.com/AsteriusIT/asterius-idp/issues/72) is the existing linked release blocker. |
| Sonar quality gate | `f7c8d734`, 2026-09-20 05:00 UTC | Green | Useful historical evidence only; it is not a local-candidate analysis. |
| Supply-chain audit, run 35507462902 | remote `main`, 2026-09-20 | Green | It covers its remote revision, not this candidate. |
| Nightly fuzzing, run 35497801255 | remote `main`, 2026-09-20 | Green | It covers its remote revision, not this candidate. |

The Sonar analysis reports no bugs, vulnerabilities or unreviewed security
hotspots. Its 48 unresolved findings are 47 major and one minor code smells;
the bounded dispositions and ownership are the already closed `ast-4p31`
remediation workstreams. The gate is green for `f7c8d734`, but Sonar must still
analyse the exact release candidate before this ticket can close.

[ADR-0015](../adr/0015-certify-the-fapi-profile-only.md), delivered and closed
as `ast-p2l.2`, fixes the claim boundary: only the production FAPI 2.0 Security
Profile path using `private_key_jwt` and DPoP is targeted for certification.
There is no `conformance_mode` or non-PAR test exception, and the optional
standard OIDC profile from ADR-0014 is outside that certification claim.

## Release decision

The milestone is **blocked for release**, and `ast-6uqw.15` remains open. To
clear it, the exact integrated revision must be pushed and receive green
required CI, a fresh green FAPI conformance verdict under the repository's
24-hour rule, and a green Sonar analysis whose remaining findings have explicit
outcomes. Issue #72 remains the linked conformance blocker. Follow
[Verifying a release](verifying-a-release.md) and attach the exact run URLs and
commit SHA; do not substitute the focused local journeys or an older green run.
