# Console and SSO milestone evidence

This 2026-10-08 audit supersedes the historical 2026-09-20 local release posture.
The user explicitly authorized local merges without remote CI, necessary
focused verification, standalone Sonar analysis with cleanup, and deferral of
coverage proof and remaining maintainability debt for this local milestone.
It is **not production release approval or OIDF certification**.

## Exact source and local verification

Final production source is `18375e7e253eb47c37aa3745db8e0b88971ea6fa`.
Later evidence-only merges do not constitute a new protocol runtime test. The
root agent verified formatting, strict Clippy across all targets, and these
separate focused test gates with mandatory source/secret audits:

| Focused gate | Passed | Scope and limit |
| --- | ---: | --- |
| Security, retention and architecture adapter database regressions | 86 | Includes the expressly approved ignored PostgreSQL cases; all passed. |
| IPSIE and Message Signing compatibility | 55 | Explicit selected profiles and real signed request-object checks. |
| SSF receiver and Basic-client response encryption | 35 | Actual extractor and schema fixes, including database regressions. |
| Final Message Signing error handling | 35 | Mandatory PAR browser refusal and forbidden signed-object parameters. |
| RFC 9701 and generated configuration reference | 60 | Includes current reference and mandatory audits; 4,453 tests intentionally excluded. |
| Final Sonar fixes and audit inventory | 45 | Review timestamp codecs, explicit-null lifecycle context, asynchronous file reads and complete audit-event round trips; 4,472 tests intentionally excluded. |

These gates overlap. Their counts must not be added and reported as distinct
coverage or a full suite. No full local Rust suite or remote GitHub workflow ran.
Frontend architecture changes passed eight focused model checks and three
browser journeys. The final Sonar frontend fixes passed typecheck/build, six
focused model checks, and two browser journeys covering native input/button
keyboard access, refused drafts, mobile themes and axe. Local Kubernetes
v1.35 admission validation passed two tests covering 26 controls; the owned
cluster was cleaned up.

Historical milestone journeys remain separately recorded: six focused browser
journeys covered branding save/reset and real sign-in rendering, assurance
editing, managed group membership/effective roles, policy refusal and two
confidential BFF SSO/logout. The group-name follow-up passed its focused browser
lifecycle and frontend checks. These historical observations do not imply a
fresh run of the entire browser matrix on the final source.

## Independent protocol outcomes

The official pinned OIDF suite `release-v5.2.4` ran both plans on the same exact
GNU runtime source `0b4c7a4a4486fb981ac18dac39b9a8431065accc`:

- Security Profile: all 56 modules executed, 50 PASSED, 4 REVIEW, 1 WARNING,
  1 SKIPPED, zero FAILED.
- Message Signing: all 70 modules executed, 63 PASSED, 4 REVIEW, 1 WARNING,
  2 SKIPPED, zero FAILED.

Both repository gates exited zero with empty waiver lists. The four REVIEW
pages in each plan were inspected against captured HTTP and HTML: missing PAR
and another client's handle refused with HTTP400; reused and expired handles
refused with HTTP404. Each browser stayed on the local authorization error
page. Official REVIEW results are preserved, not relabelled as PASSED. The
warning is the `sid` extension; RSA negative modules were skipped because the
client fixture used ES256. No RSA interoperability, OIDF submission approval or
certification is claimed. See the
[complete sanitized plan outcomes](../integrations/evidence/oidf-fapi-2026-10-08.json).

The [RFC 9701 consumer](../integrations/evidence/rfc9701-independent-consumer-2026-10-08.json)
passed 13 independent controls on source `97ac7245`, separately from the 126
OIDF modules. The [provider-command consumer](../integrations/evidence/provider-commands-2026-10-08.json)
passed 25 controls. Native and independent
[SSF lifecycle](../integrations/evidence/ssfgo-asterius-lifecycle-2026-10-08.json),
[native SSF push](../integrations/evidence/ssfgo-native-push-2026-10-08.json),
[Keycloak OIDC/JWE adversarial callbacks](../integrations/evidence/keycloak-oidc-adversarial-2026-10-08.json)
and [selected IPSIE RPs](../integrations/evidence/ipsie-selected-rp-2026-10-08.json)
retain their own exact revisions and bounded profile assertions. They do not
certify every advertised standard or the final build merely because its source
includes their fixes.

The final GNU artifact was built with fresh embedded console assets from
`18375e7e`: image `asterius-idp:local-ticket-verified-release-20261008`, binary
SHA256 `cf4d4872108b09b53ba9cbad9cea7b0d860f555befbe97c8c4d8194a45f14a03`.
This build is not an additional runtime interoperability run. Default musl
Dockerfile packaging is not validated by this evidence. Owned protocol and
selected-profile runtimes, databases, test containers and public fixture routes
were removed; pre-existing user services and Serve ports were preserved.

## Sonar outcome and explicit deferred ownership

Official standalone SonarScanner 8.1 scanned clean source `18375e7e` using the
existing production-source scope. Analysis ID:
`33e93dac-6303-4b9b-8c2d-c049d4c2a831`.

The raw analysis-ID gate remains **ERROR**, preserving pre-disposition
reliability D and missing coverage. Five individually evidenced findings were
then marked FALSE-POSITIVE: two lifecycle fields intentionally require explicit
null approval context, and three credential-like literals exist only in
compiled-out test assertions. Their actual issue keys, API outcomes, actors and
times are recorded. No `NOSONAR`, scope exclusion or blanket secret waiver was
introduced.

Before restoring Automatic Analysis, the exact candidate was confirmed current
both before and after these dispositions. Its recomputed current gate had
reliability, security and maintainability ratings A, reviewed hotspots 100%,
and duplication 2.1%; **only coverage remained ERROR** (0% imported, existing
80% requirement). No overall green Sonar gate is claimed. Missing imported
coverage is not evidence that the executed tests covered no code.

The user explicitly approved these two deferred records:

- `ast-wwsr`: all 426 unresolved CODE_SMELL findings—34 critical, 316 major,
  76 minor; 382 in new code. Every key, source, rule, severity and maintainer
  area is inventoried. They remain OPEN in Sonar and DEFERRED in Beads.
- `ast-84ny`: generate and import genuine coverage for the production release
  candidate and satisfy the existing actual coverage gate in a future
  authorized release workflow. No report is fabricated or threshold lowered.

There are zero unresolved bugs, zero unresolved vulnerabilities and zero
hotspots in the captured post-disposition candidate snapshot. This fresh debt
is distinct from the closed historical `ast-4p31` campaign. See the
[full 426-key accounting and cleanup proof](evidence/sonar-local-milestone-2026-10-08.json).
Both scanner runs restored the project's original Automatic Analysis mode and
revoked only their uniquely owned temporary tokens, verifying token absence
and failed token authentication. The separate disposition window also restored
the original mode. Restoration may immediately analyze older remote source;
that mutable project status must not replace the captured local candidate.

## Local milestone disposition and production release boundary

The implementation and bounded local validation passed the final ticket review
under the user's explicit local exceptions.
The administration runbook covers
[groups, policy changes, branding and SSO](../runbooks/console-sso-administration.md),
and [the runnable two-application demo](../sso-demo.md) remains documented.
[ADR-0015](../adr/0015-certify-the-fapi-profile-only.md) preserves the approved
FAPI certification boundary without a non-PAR testing exception.

A production release still needs green required CI, genuine coverage proof,
current release conformance evidence under the release gate, and the applicable
packaging and supply-chain checks. Historical red remote runs and GitHub issue
#72 are not silently reclassified by local success. Follow
[Verifying a release](verifying-a-release.md) for that separately authorized
workflow. No push, remote CI, release publication or formal certification occurs
as part of this local completion.

SCIM is outside `ast-6uqw` scope. `ast-p3p3` explicitly remains open for future
full native Entra lifecycle authorization; controlled local adapter checks and
native credential validation do not substitute for that lifecycle.
