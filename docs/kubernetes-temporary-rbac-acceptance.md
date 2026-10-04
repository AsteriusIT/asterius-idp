# Disposable native temporary RBAC acceptance

Refs: ast-dd1y.5.3. Candidate normative review remains pending; this evidence is
isolated interoperability validation, with no production enablement or main merge.
The contract is [the temporary RBAC ADR](adr/kubernetes-temporary-rbac.md).

The verified server artifact is SHA-256
`655b95bed262e31c1ecbd95e87eef87571189672cba51c4c745d9529f11be95f`.
It includes the closed SQL binding DTO correction and final ID-role release gate.
Its emitted `--admin-openapi` JSON equals `docs/admin-api-openapi.json`.

Run the fixture with an already verified candidate binary:

```sh
ASTERIUS_BIN=/path/to/verified/asterius bash scripts/kubernetes-temporary-rbac-acceptance.sh
```

The fixture creates only its own PostgreSQL database, HTTPS listener 9469,
`asterius-dd1y53` kind v1.35 cluster and issuer-forwarding container. It refuses
preexisting names and never uses the ambient Kubernetes context. Its trap removed
these owned resources after the successful run. Restricted-controller and human
requests use explicit bearer-only HTTP credentials; admin client certificates do
not accidentally supply authority to the negative cases.

Positive ID credentials come from actual authenticated PAR, PKCE authorization
code and proof-bound refresh against Asterius, with issuer/audience/nonce/ES256
verification. Account sessions and frozen assurance sidecars are explicitly seeded
controlled records: this run does not claim a new WebAuthn ceremony. Prior actual
ceremony evidence is retained by ast-dd1y.1.4. Separately labelled malformed-token
verifier negatives use only this disposable realm's development KEK, keeping key
material in memory and out of logs.

The successful run reported nine control groups:

- Same-tenant Console owner, CSRF, explicit CAS, ordinary-account boundary and
  proof-bound automation that cannot become the entitlement owner.
- Actual ordinary OIDC identity with an independent baseline ConfigMap binding.
- Real code and refresh JIT identity reaching only the fixed Secret get permission;
  list, foreign resource, insufficient and extra resource permissions are refused.
- Closed signed provenance: extra fields, wrong types and uncapped deadlines are
  refused; valid foreign role/namespace tuples select baseline and lack JIT access.
- Healthy revocation removes an old cryptographically valid credential's access.
  A second same-user live approval is refused by the existing lifecycle, and another
  independently approved user remains authorized after the first user's revocation.
- Controller SIGKILL leaves a real stale binding; the old JWT eventually receives
  401, while a newly issued ordinary token receives 403 for the Secret and retains
  its baseline ConfigMap permission.
- A standing role cannot produce temporary-only provenance. Disabling/re-enabling
  a mapping changes its revision; the new identity cannot match the old binding.
- Actual controller ServiceAccount cannot create bindings, edit Roles, patch a
  baseline binding, write another namespace, bind a ClusterRole or change roleRef.
- Baseline binding content and ordinary baseline access remain unchanged.

Observed projection-to-binding enable time was 0.003 seconds after both public
subjects had been established by token issuance; this is not full approval latency.
Healthy revocation was 0.210 seconds. Expired JWT refusal was 3.614 seconds after
`exp` in this warm-key run, with a ten-second successful-authentication cache.
The fixture allows two seconds of scheduling tolerance for that observed path.
It did not inject delayed JWKS retrieval and does not establish a ten-second
worst-case expiry guarantee. The [ADR](adr/kubernetes-temporary-rbac.md#expiry-and-revocation-boundaries)
now records the source-derived conservative supported limit of 40 seconds after
exp, plus scheduling margin and clock skew: up to 30 seconds of an already-started
verification followed by ten seconds of successful-authentication caching.
Kubernetes v1.35's
[vendored expiry-before-signature ordering](https://github.com/kubernetes/kubernetes/blob/v1.35.0/vendor/github.com/coreos/go-oidc/verify.go#L257-L307)
and [detached cache lookup/insertion](https://github.com/kubernetes/kubernetes/blob/v1.35.0/staging/src/k8s.io/apiserver/pkg/authentication/token/cache/cached_token_authenticator.go#L171-L197)
justify that conservative inference. Delayed-JWKS measurement was not performed;
no immediate offline expiry or outage revocation is claimed. The refinement
changes only the pending review documents and requires no Rust build.

Source validation passed `cargo check --all-targets`, strict formatting/Clippy and
85 targeted tests via `./scripts/verify.sh temporary kubernetes roles sign_identity
overlap`. The meaningful defensive projection regression handles duplicate historical
or imported approval rows and distinct-user overflow; it does not claim that the
current lifecycle permits overlapping approvals. The new PostgreSQL binding DTO
round-trip is ignored locally and selected by the existing temporary-entitlements
CI integration filter. Focused Go tests and vet passed for the controller/client/
Kubernetes adapters. All 113 registered fuzz targets passed inventory/format/strict
Clippy and full stable compilation (`cargo build --manifest-path fuzz/Cargo.toml
--bins`). This proves compilation, not a fuzz campaign. Both owned Rust targets
were cleaned after retained candidate validation.
