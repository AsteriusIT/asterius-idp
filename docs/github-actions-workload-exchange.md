# GitHub Actions workload exchange

An enabled `github` tenant trust now permits a GitHub OIDC JWT as the RFC8693
subject token. This implements the GitHub profile in the approved
[external workload ADR](adr/external-workload-trust.md). The shared Kubernetes
exchange boundaries remain: independently authenticated confidential client,
DPoP child, exact resource, narrowed scopes and registered actions, <=300-second
output, five-minute assertion freshness and atomic one-use assertion/grant/audit.
No refresh token, human principal or external JWT client authentication is added.

## Bootstrap and least privilege

The [sample workflow](../examples/github-actions/workload-exchange/workflow.yml)
uses a fresh isolated, operator-enrolled self-hosted runner dedicated to the
approved repository. Its independent ES256 client key is provisioned outside
GitHub repository secrets and removed with the runner; the reviewed immutable
client script is installed by the operator. Only `id-token: write` is granted.
There is no checkout, untrusted artifact execution or token output. Protect the
branch and environment, require trusted approvals, and never lend this runner or
key to pull-request jobs. These controls must be configured by the operator;
the YAML alone does not enforce runner isolation or environment reviewers.

The [client](../examples/github-actions/workload-exchange/client.mjs) acquires an
OIDC assertion with the tenant/trust-specific audience through GitHub's HTTPS
`ACTIONS_ID_TOKEN_REQUEST_URL` and runtime bearer credential. It uses independent
`private_key_jwt` authentication and an ephemeral DPoP key, reloads a fresh subject
on a token-endpoint nonce challenge, and includes `ath` on API proofs. Redirects,
oversized responses and duplicate assertions fail closed or retry within bounded
limits. It reports HTTP status only, never token bodies or raw claims. `id-token:
write` authorizes OIDC acquisition; it does not authorize Asterius access.

This recipe stores no OAuth client secret or GitHub repository credential, but
the independent asymmetric client credential still requires provisioning. GitHub
hosted runners do not acquire a confidential-client credential merely by issuing
an OIDC token or generating a DPoP key. Secretless direct hosted-runner bootstrap
is outside the accepted ADR. An operator may integrate an existing trusted broker
that authenticates workflows and holds its own independent client credential;
building or trusting a new broker requires its own reviewed architecture. This
ticket does not introduce such a broker or treat GitHub JWTs as client assertions.

## Exact trust policy

Use issuer `https://token.actions.githubusercontent.com`, explicit `RS256`, and
operator-pinned public GitHub JWKS or the guarded remote URI currently published
at `https://token.actions.githubusercontent.com/.well-known/jwks`. The server
never discovers keys from token claims or certificate metadata. The audience is
`urn:asterius:workload:<tenant>:<trust-id>` and must be the token's only audience.
Create disabled first, review these exact string claims, then enable explicitly:

The [trust template](../examples/github-actions/workload-exchange/trust.json) is
disabled and contains example IDs, subject, workflow path and a zero SHA. Replace
them with reviewed actual claims; it is not a working registration. Use tenant
`ci` and trust ID `github-deploy` only if those are the operator's intended exact
targets. Register the resource/client and the existing
`urn:asterius:workload-actions` schema before enabling the trust.

| Claim | Required policy |
| --- | --- |
| `sub` | Exact actual repository/environment subject |
| `repository_id`, `repository_owner_id` | Immutable numeric IDs encoded as strings; never names or JSON numbers |
| `environment` | Exact protected environment; absent/other environment fails |
| `ref` | Exact approved full ref; branch/tag wildcards are unsupported |
| `event_name` | Exact intended event; `pull_request` and `pull_request_target` cannot be registered |
| `workflow_ref`, `workflow_sha` | Exact caller workflow path/ref and immutable commit identity |
| `job_workflow_ref`, `job_workflow_sha` | Both exact callee pins for reusable jobs; both absent for ordinary jobs |

The caller and reusable callee are distinct identities. An ordinary trust rejects
any JWT containing reusable-job claims. A reusable trust rejects absent, partial,
different or untyped callee claims. Pin the callee by commit, not a mutable tag;
both caller workflow SHA and callee SHA remain required. Moving a ref or updating
a workflow commit requires an audited operator trust update. The sample allows
only `workflow_dispatch` on `refs/heads/main`; other event policies need explicit
operator review, including whether a `workflow_run` consumes untrusted artifacts.
GitHub's `dynamic` Dependabot event does not satisfy that sample event policy.

Fork repositories have different repository IDs, so a copied repository name or
workflow cannot inherit authority. `pull_request_target` can carry base-repository
identity even for an untrusted contribution; the event rejection prevents that
identity from being treated as an approved deployment. Do not infer fork safety
from a textual `sub`, branch name or environment alone.

## Renames, subject formats and header metadata

Numeric IDs establish identity independently of repository/owner names. Exact
subject and workflow strings intentionally fail closed after names, refs or
workflow identities change until the operator updates the trust. Updating text
does not authorize a different numeric repository/owner identity or remap the
non-human principal automatically. Transfers change owner identity and therefore
need a separate reviewed trust decision.

GitHub currently documents immutable default subjects for repositories created
after July 15, 2026, and for subsequent renames/transfers. Existing repositories
may still use legacy subjects or an operator-customized template. For example:
`repo:org/repo:environment:production` and
`repo:org@123/repo@456:environment:production` are different exact strings, not
equivalent aliases. Colons in environment names can be encoded as `%3A`. Inspect
the actual trusted workflow's claims through an operator-controlled tool and pin
the exact value; do not print the JWT into Actions logs. The server does not parse
`sub` into an inferred identity or automatically rewrite names/encodings.

GitHub documents a noncritical `x5t` JOSE header. This implementation accepts only
a base64url SHA-1 thumbprint representation decoding to exactly 20 bytes, and only
when verifying the GitHub provider. It treats this as inert signed metadata:
`kid` and pinned public JWKS determine the verification key. There is no SHA-1
authentication decision, certificate-chain trust, `x5u` fetch or `x5c` import.
This interop correction stays within the approved independent JWT profile;
unknown critical headers, embedded keys and token-provided URLs remain refused.

## Evidence and primary sources

The controlled CI runner and fixtures use a dedicated local signer and isolated
Asterius trust/database, not a JWT issued by GitHub. They exercise the same sample
client, real independently authenticated token endpoint and DPoP-protected API.
They are explicitly a controlled interoperability flow, not evidence of a live
GitHub Actions job. A live job requires separately authorized remote workflow
publication/dispatch and independently provisioned runner credentials.

The reproducible [acceptance launcher](../scripts/github-workload-acceptance.sh)
requires Node, OpenSSL, curl, psql and a dedicated local PostgreSQL fixture
listening at `127.0.0.1:5433` with the development `asterius` role/password.
It creates a uniquely named database, starts an already verified binary with
disposable TLS/KEK material, and removes only its own server/database/files.
Ports 9453 (Asterius) and 9450 (proof-checking API) must be free. No GitHub API
write, workflow publication, repository credential or remote deployment occurs:

```sh
ASTERIUS_BIN=/absolute/path/to/verified/asterius \
  ./scripts/github-workload-acceptance.sh
```

On 2026-10-03 this fresh-database launcher passed against the implemented server:
two real HTTPS exchanges and two signature/DPoP-verified API calls, including the
reusable-workflow case, with two durable GitHub provenance records and a
300-second ceiling. Signed fixtures for wrong numeric IDs/forks, JSON-number IDs,
pull-request events, ref/environment/workflow/audience/rename, unpinned or wrong
callee, stale/expired assertions, replay, external JWT client authentication,
scope/resource/action widening and disabled trust were refused. The recorded
output identifies `controlled-ci-fixture-not-live-github` and `local-RS256`;
the GitHub acquisition endpoint alone is stubbed. Separately, fmt/strict clippy,
78 targeted Rust tests, the Node client test and the 104-target fuzz gate passed.

The implementing agent reviewed these primary sources on 2026-10-03; the human
approval of the external workload ADR covers this profile. No additional human
review or live GitHub execution is claimed:

- [GitHub OIDC claim/subject/permission reference](https://docs.github.com/en/actions/reference/security/oidc): exact claims, immutable subjects and runtime acquisition.
- [GitHub reusable workflow OIDC](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows): caller versus callee identity.
- [GitHub provider discovery](https://token.actions.githubusercontent.com/.well-known/openid-configuration): explicit issuer and pinned JWKS endpoint, read by the operator rather than token discovery.
- [RFC7515 §4.1.7 and §10.11](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.7): certificate-thumbprint representation and its distinction from signature authority.
- [RFC8693 §2.1](https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1): independent client authentication and subject token use.
