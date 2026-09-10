# OpenID Foundation conformance harness

Everything else in this repository checks Asterius against our own reading of
the specifications. The specifications are quoted carefully and the tests
derived from them are many, but they are still our reading: if we misread a
clause, we misread it in the implementation and in the test that guards it, and
nothing notices. This directory brings in the outside judge — the OpenID
Foundation's own conformance suite, the software that decides whether a server
may call itself certified.

```
make conformance        build, run the FAPI 2.0 SP Final plan headless, tear down
make conformance-keep   the same, leaving the stack up so you can read the logs
```

No account, no secret, no API token. Everything runs on the local Docker
daemon; the only thing fetched from the network is the pinned suite (a Git tag
and two container images).

## What runs

`scripts/conformance.sh` brings up five containers from
`conformance/docker-compose.yml`:

| service | what it is |
| --- | --- |
| `db` | PostgreSQL 16, disposable |
| `asterius` | this tree, built from the repository `Dockerfile`, with the hardening of `deploy/compose/docker-compose.yml` unchanged |
| `mongodb`, `server`, `nginx` | the conformance suite's own three services, from its `docker-compose-prebuilt.yml` |

and then a sixth, `runner`, which executes the suite's own
`scripts/run-test-plan.py` and exits. The plan is

```
fapi2-security-profile-final-test-plan
  [openid=openid_connect]
  [client_auth_type=private_key_jwt]
  [sender_constrain=dpop]
  [fapi_profile=plain_fapi]
  [authorization_request_type=simple]
```

Those five are all the variants this plan takes and no more. The suite rejects a
variant name it does not know, and it also rejects one the plan sets for itself
— `fapi_request_method` and `fapi_response_mode` are fixed by the Security
Profile plan, and `client_registration` is not a variant at all: static clients
are what happens when the configuration carries a `client_id`, which
`plans/fapi2-sp-final.json` does.

which is FAPI 2.0 Security Profile Final §6.6's "test against a certified
implementation" read the other way round: it is the plan a certification
submission for this profile is made of.

Everything speaks TLS to everything else, over the compose network, by service
name. That is not ceremony: FAPI 2.0 SP §5.2 requires TLS on every endpoint, and
a harness that ran the server on cleartext — as the example compose stack
deliberately does — would never exercise the transport half of the profile.
`scripts/conformance.sh` issues a one-day certificate for `DNS:asterius`, and
teaches it to the suite's JVM by copying the JDK's own `cacerts` and adding that
one certificate to the copy. The public roots stay, because the suite also
fetches its own base URL.

The tenant is addressed at its issuer, prefix included:
`https://asterius:9443/t/conformance`, which is what the plan's `discoveryUrl`
fetches and what its browser `match` patterns name. Path-based tenancy is the
shape a deployment gets without extra DNS, and until `ast-295` the suite could
not walk it — `/authorize` named the interaction page root-relative, so the
browser lost its tenant on the second hop. The harness papered over that by
writing `custom_host` on the tenant after boot, which made it host-routed and
left the path-based flow untested; `ast-p2l.1` removed the statement, as
`ast-f0y` did for the browser sweep. A workaround kept past its cause hides the
next regression. The plan was replayed once without it, on 2026-09-10: the same
56 modules, the same 48 PASSED / 5 REVIEW / 1 WARNING / 1 SKIPPED / 1 FAILED.
Nothing about the verdict depended on that statement.

The tenant's user and its two clients are still seeded after Asterius has
started, for the one reason that survives: the rows reference a tenant the boot
upserts. `e2e/fixtures/seed.sql` records the same constraint, and that same file
is what seeds the user here. The clients are seeded by
`fixtures/clients.sql` with the suite's redirect URI byte for byte (ADR-0005
matches exactly) and with the public halves of the keys in
`plans/fapi2-sp-final.json`, derived from that file at seed time by
`fixtures/public-jwks.py` so that the two cannot drift apart.

## How it fails

A harness that runs and tests nothing is worse than no harness: it converts an
open question into a green tick. Every one of these is an error, with a distinct
exit code and a sentence:

| situation | exit |
| --- | --- |
| the suite could not be checked out or pulled | 69 |
| the pinned tag no longer points at the pinned commit, or an image digest moved | 70 |
| Asterius or the suite did not become ready in `CONFORMANCE_TIMEOUT` | 71 |
| the suite holds no plan, the plan executed zero modules, or not one module reached FINISHED | 72 |
| a status or a result the report gate does not recognise | 73 |
| a module FAILED, or finished with no verdict, and no waiver covers it | 74 |
| `conformance/waivers.json` is unreadable, or a waiver has no ticket | 70 at the start, 73 at the end |

72 and 73 are the important ones. `run-test-plan.py` exits 0 when every
module it ran passed, *including when it ran none* — a typo in a plan name, a
suite that lost its Mongo database and a variant combination with no modules in
it all look exactly like success. So `runner/report.py` reads the results back
out of the suite's API afterwards and fails on an empty or unreadable run,
whatever the runner said. It also refuses to interpret a status it does not
know: that is the `ast-yxu` lesson (an unpinned `cargo-geiger` changed its
output format and a gate went green on nothing) written as a check.

74 is the verdict, and it is deliberately *not* `run-test-plan.py`'s exit code:
that code says "some module did not pass", and some modules of this plan do not
pass for reasons that are not the server's. What a release may be cut on is
decided in one place, `scripts/conformance-verdict.py`, from the report and the
waiver list — see "The verdict, and what is waived".

## The pin, and how to move it

Four values, all in `scripts/conformance.sh`, and they move together:

```sh
SUITE_VERSION="release-v5.2.4"
SUITE_COMMIT="ab35a8df4864da35b49eff11483e204e01aa7961"
SUITE_SERVER_DIGEST="sha256:3a2615…"
SUITE_NGINX_DIGEST="sha256:43d34c…"
```

The tag is a mutable name on a server we do not control, so the commit is
checked after checkout and each image's digest after the pull. To update:

```sh
# the newest release tag and its commit
curl -s 'https://gitlab.com/api/v4/projects/openid%2Fconformance-suite/repository/tags?per_page=5'

# the digest each image tag currently resolves to
docker pull registry.gitlab.com/openid/conformance-suite:release-vX.Y.Z
docker image inspect --format '{{index .RepoDigests 0}}' \
  registry.gitlab.com/openid/conformance-suite:release-vX.Y.Z
```

`conformance/runner/requirements.txt` pins the two Python packages the suite's
runner script imports; the suite's own `scripts/requirements.txt` names no
versions. Move them in the same commit, and say in that commit what changed in
the suite — a new release routinely adds test modules, and a plan that suddenly
runs five more tests is a change in what we are claiming.

## What the first run found

Recorded here because it is the point of the ticket, and because a reader who
runs this tomorrow should be able to tell an old finding from a new one. None of
it was fixed while the harness was being written: a harness whose first run is
green because its author repaired the server at the same time proves nothing
about the runs after it.

At the pinned release, on the plan above, **56 modules run**. What did not pass:

* `fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-proof-jkt`
  — **FAILED**, and the most serious of these. The authorization request carries
  `dpop_jkt`; the token request then presents a DPoP proof made with a *different*
  key. The token endpoint answered `200` and issued an access token whose
  `cnf.jkt` was the `dpop_jkt` from the authorization request rather than the
  thumbprint of the key that actually signed the proof. The suite expected
  `invalid_grant`/`invalid_dpop_proof` (`CheckTokenEndpointReturnedInvalidRequestGrantOrDPopProofError:
  "Couldn't find error field"`). RFC 9449 §10.1 and FAPI 2.0 SP §5.3.2.1.
* `fapi2-security-profile-final-refresh-token` — **FAILED**. The first
  `grant_type=refresh_token` call, with a DPoP proof made with the same key as
  the code exchange, is refused with
  `400 {"error":"invalid_grant","error_description":"the refresh token cannot be redeemed"}`.
  The suite expected `200` (`CheckTokenEndpointHttpStatus200`, RFC 6749 §5.1).
* `fapi2-security-profile-final-test-claims-parameter-identity-claims` —
  **WARNING**, twice; both settled by `ast-8p1`.
  `EnsureIdentityClaimsContainRequestedClaims`: the claims requested through the
  `claims` parameter were not all returned, although they are listed in
  `claims_supported`. The two missing ones were `name` and
  `preferred_username`, which exist only in a user's claim set — deployment
  data a tenant-wide document cannot promise. `claims_supported` is now
  assembled from the ID token builder and the `users` columns, and no longer
  names them. `CheckForUnexpectedClaimsInIdToken`: the `id_token` carries a
  claim name the suite does not know, and the name is `sid`. It is kept: it is
  a registered claim, Back-Channel Logout 1.0 §2.1 requires it whenever
  `backchannel_logout_session_supported` is advertised, and the suite's
  `ValidateIdTokenStandardClaims` list simply predates that specification.
  Expect this half of the WARNING to persist.
* `fapi2-security-profile-final-user-rejects-authentication` — **FAILED**, and
  this one is the harness rather than the server: the browser script always
  presses *Allow*, because the module that needs *Deny* and the module that needs
  *Allow* arrive at the same URL. The configuration *can* tell them apart —
  see "Six modules the first run could not drive" below — but the *Deny* button
  only exists on the consent screen, and the consent screen is skipped when the
  tenant already remembers this consent, which after the first module of the
  plan it does. Still red for that reason.
* `fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails`,
  `…-par-attempt-reuse-request_uri`, `…-par-attempt-to-use-expired-request_uri`,
  `…-par-attempt-to-use-request_uri-for-different-client` — **INTERRUPTED**. All
  four end on the server's own error page, and the suite's verdict for that is
  REVIEW: "upload a screenshot of the error page". The scripted browser had no
  task matching that page, so its non-optional *Verify Complete* task was
  reached on the wrong URL and the run stopped there. The server's behaviour up
  to that point was what the module asked for. Driven since — see below.
* `fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds`
  — **INTERRUPTED**, also the harness: the module requires the browser *not* to
  authenticate on its first visit to the login page, and the script did not know
  which visit it was on. Driven since — see below.
* `fapi2-security-profile-final-ensure-signed-client-assertion-with-RS256-fails`
  — **SKIPPED** by the suite itself, because the server advertises no RS256
  (ADR-0003). That is the expected outcome, not a gap.

Everything else passed, including the whole DPoP negative set, PKCE, the
client-assertion negative set, authorization-code binding and reuse, and both
discovery forms.

## Six modules the first run could not drive, and one URL that moved

The interaction pages moved first. `ast-295` gave every URL rendered to a
browser the tenant's mount prefix, so the login and consent screens are at
`/t/conformance/interaction/…` and no longer at `/interaction/…`, and a browser
script that matches the old path matches nothing: on the run of 2026-09-10 that
was **55 of 56 modules INTERRUPTED**, including the happy flow. The `match`
patterns here follow the server. A harness that drives a browser is coupled to
the URLs that browser is sent to, and this is the coupling — if the mount prefix
moves again, this file moves with it.


Five of the six are now driven, and none of the five needed a line of server
code. Nor is any of the six a regression of the merges that followed the first
run: the section above records the same six modules, failing for the same
reasons, on the run that produced it — the run that preceded those merges — and
`crates/server/src/http/authorize.rs`, which decides between a redirect and the
error page, is byte for byte the same at both commits (`ast-7fj`).

The whole of it is the suite's `override` map in
`plans/fapi2-sp-final.json`. It is keyed by module name, and what it holds is
moved over the top-level configuration for that module alone
(`DBTestPlanService.getModuleConfig`). One plan can therefore drive one browser
script per module, which is what these six need and what the first run did not
know about.

* Four modules end on the server's error page rather than at a `redirect_uri`,
  because a request whose `request_uri` is invalid, spent, expired or another
  client's is a request whose redirect target cannot be trusted (PAR §7.3). Their
  override is one task matching the authorization endpoint URL that waits for
  `p.error` and passes the page to `update-image-placeholder` — the screenshot
  the module's REVIEW asks a human for, taken by the script. Two of the four
  (`…-attempt-reuse-request_uri`, `…-request_uri-for-different-client`) run a
  nominal leg first, so their override keeps the login, consent and callback
  tasks and marks every task optional: on the first leg the error task is
  skipped, on the second the callback task is.
* `…-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` needs the
  first visit to the login page to end *without* signing in, and the second, with
  the same `request_uri`, to sign in. Its override is two blocks: the first
  carries `"match-limit": 1`, so it is spent on the first visit — it waits for the
  username field and stops — and the second takes every visit after it.
* `…-user-rejects-authentication` is the one still red. Its override signs in and
  then presses *Deny*, which is the only refusal this server offers a person; but
  the consent screen it lives on is skipped whenever the tenant remembers a
  consent that covers the request, and by the time this module runs it does.
  Until a tenant can be configured to always ask (`ast-f7m.4`), or the login page
  itself grows a way to refuse, this test needs a hand — press *Deny*, or run it
  first against a freshly seeded database.

The run that came out of all this, 2026-09-10, on 56 modules: **48 PASSED, 5
REVIEW, 1 WARNING, 1 SKIPPED, 1 FAILED**. The FAILED is
`user-rejects-authentication`, above. The five REVIEW are the five error-page
modules, whose verdict is REVIEW by construction — the suite wants a human to
look at the screenshot the script now uploads. One of the five says something
about the server rather than the harness:
`par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` ends on the
error page, so this server spends a `request_uri` when the browser first arrives
at the authorization endpoint rather than when the authorization completes,
which FAPI 2.0 SP §5.3.2.2 Note 3 recommends against. A recommendation, and a
ticket of its own. The two FAILED of the first run — the mismatched DPoP proof
`jkt` and the refresh token — now pass: `ast-36g` and `ast-1h1` fixed them.

## The verdict, and what is waived

"100 % pass" is not what this plan produces, and a gate that demanded it would
be a gate somebody turns off. The run of 2026-09-10 stands at 48 PASSED,
5 REVIEW, 1 WARNING, 1 SKIPPED, 1 FAILED, and each of the last three is
explained above rather than accidental. So the rule, decided in `ast-p2l.1` and
implemented in `scripts/conformance-verdict.py`:

* **PASSED, REVIEW, WARNING, SKIPPED — green.** REVIEW is the suite asking a
  human to look at a screenshot the harness already takes and uploads. The
  WARNING is `sid` in the ID token, which Back-Channel Logout 1.0 §2.1 requires
  and the suite's claim list predates. The SKIPPED is RS256, which ADR-0003
  refuses to offer.
* **FAILED, or finished with no verdict at all — red**, unless
  `conformance/waivers.json` names the module. UNKNOWN counts as red on purpose:
  a module that judged nothing has not judged the server.
* **A waiver carries a ticket**, and `crates/server/tests/conformance_plan.rs`
  fails the per-PR pipeline when that ticket is closed or unknown to beads. A
  waiver is a decision to ship a known non-conformance; it is not a way to
  quieten a run, and it is not allowed to outlive the person who took it.
* **A waiver that covered nothing is printed loudly and does not fail the run.**
  A module that started passing must not break a release — but a waiver kept
  past its cause is the next hidden regression, so it is shouted about.

Exactly one waiver exists today:
`fapi2-security-profile-final-user-rejects-authentication`, for `ast-k5u`, whose
story is two sections up. `docs/certification.md` is the submission checklist
that reads out of all this.

## What is not covered

* **mTLS.** FAPI 2.0 SP allows either `private_key_jwt` + DPoP or mTLS for both
  client authentication and sender constraining. This harness runs the first
  pair, which is the pair the server implements today: `features.mtls` is off
  and the discovery document announces `private_key_jwt` alone. The mTLS plan
  needs a client certificate issued per run and a second ingress on 8444.
* **Message signing (JAR/JARM).** `fapi2-message-signing-final-test-plan` is a
  separate plan; `request_parameter_supported` is `false` today.
* **OpenID Connect Core plans.** Gated by decision E16_02, per the ticket.
* **The mTLS variant of this plan.** Prepared but not wired: see
  `.github/workflows/conformance.yml`, whose `mtls` input exists and refuses to
  run until `features.mtls` and a second ingress do (`ast-m9c.3`).

## Where the results go

`conformance/.run/results/` — ignored by Git, recreated per run.

* `export/*.zip`, written by `run-test-plan.py`: the machine-readable result
  archive, which is what a certification submission is made of.
* `report-<planid>.zip`, written by `runner/report.py`: the suite's HTML report
  for the plan. This is what the nightly job publishes as an artefact.
* `verdict.json`, also written by `runner/report.py`: one line per module —
  name, result, status, log URL — plus the revision and the plan the run was
  about. Nothing is decided in it. It is the input to
  `scripts/conformance-verdict.py`, and it is what the release gate downloads.

With `make conformance-keep` the stack stays up and the suite's UI is at
`https://127.0.0.1:8443/` (`CONFORMANCE_HTTPS_PORT` if 8443 is taken on your
machine — the links inside the reports will still say 8443, because that is the
port the suite listens on inside its own network). Asterius is at
`https://127.0.0.1:9543/`, with a certificate no browser will like.

## Why this is not in the per-PR pipeline

It takes tens of minutes and it builds a release image. `ast-83p.15` exists
because one job once took 91 % of the pipeline; this one would take more. It
runs nightly, in `.github/workflows/conformance.yml`, on demand from the Actions
tab, and on every push to a `release/**` branch. The per-PR pipeline in `ci.yml`
is untouched — a separate file on purpose, so that the two never conflict.

What *does* run per PR is `crates/server/tests/conformance_plan.rs`: it ties the
plan's `match` patterns to the routes the router mounts, and every waiver to a
beads ticket that is still open. Both are cheap, and both catch the thing that
would otherwise be found at 3am by a job nobody reads.
