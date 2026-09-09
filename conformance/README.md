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

The tenant, its user and its two clients are seeded after Asterius has started,
because booting upserts the configured tenants and that upsert overwrites
`custom_host` — the same ordering constraint `e2e/fixtures/seed.sql` records,
and that same file is what seeds the user here. The clients are seeded by
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
| the plan ran and reported failures | `run-test-plan.py`'s own exit code |

The last two are the important ones. `run-test-plan.py` exits 0 when every
module it ran passed, *including when it ran none* — a typo in a plan name, a
suite that lost its Mongo database and a variant combination with no modules in
it all look exactly like success. So `runner/report.py` reads the results back
out of the suite's API afterwards and fails on an empty or unreadable run,
whatever the runner said. It also refuses to interpret a status it does not
know: that is the `ast-yxu` lesson (an unpinned `cargo-geiger` changed its
output format and a gate went green on nothing) written as a check.

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
  **WARNING**, twice. `EnsureIdentityClaimsContainRequestedClaims`: the claims
  requested through the `claims` parameter were not all returned, although they
  are listed in `claims_supported`. `CheckForUnexpectedClaimsInIdToken`: the
  `id_token` carries a claim name the suite does not know.
* `fapi2-security-profile-final-user-rejects-authentication` — **FAILED**, and
  this one is the harness rather than the server: the browser script always
  presses *Allow*, because the module that needs *Deny* and the module that needs
  *Allow* arrive at the same URL and nothing in the configuration can tell them
  apart. Certification runs this test by hand.
* `fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails`,
  `…-par-attempt-reuse-request_uri`, `…-par-attempt-to-use-expired-request_uri`,
  `…-par-attempt-to-use-request_uri-for-different-client` — **INTERRUPTED**. All
  four end on the server's own error page, and the suite's verdict for that is
  REVIEW: "upload a screenshot of the error page". A scripted browser has no
  screenshot to upload, so the run stops there. These are manual by design; the
  server's behaviour up to that point was what the module asked for.
* `fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds`
  — **INTERRUPTED**, also the harness: the module requires the browser *not* to
  authenticate on its first visit to the login page, and the script cannot know
  which visit it is on.
* `fapi2-security-profile-final-ensure-signed-client-assertion-with-RS256-fails`
  — **SKIPPED** by the suite itself, because the server advertises no RS256
  (ADR-0003). That is the expected outcome, not a gap.

Everything else passed, including the whole DPoP negative set, PKCE, the
client-assertion negative set, authorization-code binding and reuse, and both
discovery forms.

## What is not covered

* **mTLS.** FAPI 2.0 SP allows either `private_key_jwt` + DPoP or mTLS for both
  client authentication and sender constraining. This harness runs the first
  pair, which is the pair the server implements today: `features.mtls` is off
  and the discovery document announces `private_key_jwt` alone. The mTLS plan
  needs a client certificate issued per run and a second ingress on 8444.
* **Message signing (JAR/JARM).** `fapi2-message-signing-final-test-plan` is a
  separate plan; `request_parameter_supported` is `false` today.
* **OpenID Connect Core plans.** Gated by decision E16_02, per the ticket.
* **A release gate.** `ast-p2l.1` is the ticket that decides whether a red run
  blocks a release tag. This one delivers the harness and says what it found;
  turning that into a barrier is a separate decision, deliberately not
  pre-empted here.

## Where the results go

`conformance/.run/results/` — ignored by Git, recreated per run.

* `export/*.zip`, written by `run-test-plan.py`: the machine-readable result
  archive, which is what a certification submission is made of.
* `report-<planid>.zip`, written by `runner/report.py`: the suite's HTML report
  for the plan. This is what the nightly job publishes as an artefact.

With `make conformance-keep` the stack stays up and the suite's UI is at
`https://127.0.0.1:8443/` (`CONFORMANCE_HTTPS_PORT` if 8443 is taken on your
machine — the links inside the reports will still say 8443, because that is the
port the suite listens on inside its own network). Asterius is at
`https://127.0.0.1:9543/`, with a certificate no browser will like.

## Why this is not in the per-PR pipeline

It takes tens of minutes and it builds a release image. `ast-83p.15` exists
because one job once took 91 % of the pipeline; this one would take more. It
runs nightly, in `.github/workflows/conformance-nightly.yml`, and on demand from
the Actions tab. The per-PR pipeline in `ci.yml` is untouched.
