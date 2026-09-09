# Fuzzing

<!-- Generated file. Do not edit by hand: run `./scripts/gen-fuzzing-doc.sh > docs/fuzzing.md`. -->

Every parser and validator in this repository has a fuzz target. That is a
definition-of-done item rather than an aspiration, so it is enforced:
`scripts/check-fuzz-coverage.sh` runs in the `lint` job of CI and fails when a
declared parser has no target, when a target covers nothing, when the registry
in `fuzz/Cargo.toml` has drifted from the directory, or when a target no longer
compiles or is not lint-clean.

## Declaring a target

An entry point opts in with a marker comment on the line above it:

```rust
// fuzz-target: issuer_parse
pub fn parse(raw: &str) -> Result<Self, IssuerError> { … }
```

The gate then requires `fuzz/fuzz_targets/issuer_parse.rs` to exist and to be
registered as a `[[bin]]`. After adding or removing a target file, run
`./scripts/sync-fuzz-registry.sh` to regenerate that registry, and
`./scripts/gen-fuzzing-doc.sh > docs/fuzzing.md` to regenerate the table below.
Both are checked; neither is written by hand.

## Running

```sh
# One target, until you stop it. Needs a nightly toolchain and cargo-fuzz.
cargo +nightly fuzz run --target x86_64-unknown-linux-gnu issuer_parse

# The way CI runs it: bounded, with the final statistics.
cargo +nightly fuzz run --target x86_64-unknown-linux-gnu issuer_parse \
  -- -max_total_time=60 -print_final_stats=1
```

The target triple is pinned because AddressSanitizer cannot work against a
statically linked libc: on a host whose default target is a musl triple, every
run fails before it starts.

## Where it runs

| | On every pull request | Nightly |
|---|---|---|
| Workflow | `ci.yml`, job `fuzz` | `fuzz-nightly.yml` |
| Budget | 60 s per target | 600 s per target |
| Corpus | restored, not written back | restored and saved, and uploaded as an artefact |
| On a crash | job fails, artefacts uploaded | job fails, artefacts uploaded, and a GitHub issue is opened |

One job per target, never a loop: a loop stopped at the first failure and hid
two broken targets behind a third for an unknown length of time.

## When a crash is found

The nightly run uploads the crashing input as the artefact
`crash-<target>` and opens a GitHub issue titled `fuzz: <target> crashed`,
commenting on the existing one rather than opening a second if it is still
open. GitHub issues are used there because the project's tracker (beads) lives
in a local Dolt database that a runner cannot reach; triage still belongs in
beads, so the issue is a notification, not the ticket.

Reproduce with the downloaded input:

```sh
cargo +nightly fuzz run --target x86_64-unknown-linux-gnu <target> path/to/crash-input
```

## Coverage

The 35 targets below cover 41 declared entry points. Generated from the
`// fuzz-target:` markers in `crates/`.

| Fuzz target | Entry point | Source |
|---|---|---|
| `access_token_claims` | `AccessToken::subject_claim` | `crates/oidc/src/tokens/access.rs` |
| `access_token_claims` | `actor_claim` | `crates/oidc/src/tokens/access.rs` |
| `access_token_claims` | `thumbprint` | `crates/oidc/src/tokens/access.rs` |
| `attestation_object` | `parse` | `crates/webauthn/src/attestation.rs` |
| `audit_canonical` | `canonical_bytes` | `crates/domain/src/audit/chain.rs` |
| `authenticator_data` | `verify_registration` | `crates/webauthn/src/authenticator_data.rs` |
| `authorization_code` | `digest_of` | `crates/oidc/src/code.rs` |
| `claim_name` | `ClaimName::parse` | `crates/domain/src/entities/user.rs` |
| `claims_request` | `ClaimsRequest::parse` | `crates/oidc/src/claims.rs` |
| `client_assertion` | `check_assertion` | `crates/oidc/src/client_auth.rs` |
| `client_metadata_json` | `ClientRegistration::from_json` | `crates/domain/src/entities/client.rs` |
| `client_update_guard` | `update_guard` | `crates/server/src/http/client_configuration.rs` |
| `config_parse` | `Config::parse` | `crates/server/src/config.rs` |
| `cose_key` | `parse` | `crates/webauthn/src/cose.rs` |
| `csp_form_action` | `FormActionOrigin::parse` | `crates/web/src/csp.rs` |
| `dpop_proof` | `NonceIssuer::accepts` | `crates/jose/src/dpop.rs` |
| `dpop_proof` | `NormalisedUri::parse` | `crates/jose/src/dpop.rs` |
| `dpop_proof` | `check` | `crates/jose/src/dpop.rs` |
| `forwarded_resolve` | `resolve` | `crates/server/src/http/forwarded.rs` |
| `grant_record` | `GrantRecord::validate` | `crates/domain/src/entities/grant.rs` |
| `grant_record` | `LiveAccessToken::new` | `crates/domain/src/entities/grant.rs` |
| `id_token_claims` | `IdToken::build` | `crates/oidc/src/tokens/id_token.rs` |
| `initial_access_token` | `RegistrationPolicy::admit` | `crates/server/src/http/register.rs` |
| `interaction_cookie` | `id_from_cookie_header` | `crates/web/src/interaction.rs` |
| `issuer_parse` | `Issuer::parse` | `crates/domain/src/issuer.rs` |
| `jwk_set_parse` | `parse_jwk_set` | `crates/jose/src/client_keys.rs` |
| `jwks_uri_target` | `check_url` | `crates/server/src/outbound/ssrf.rs` |
| `jws_parse` | `parse` | `crates/jose/src/jws.rs` |
| `jwt_verify` | `verify` | `crates/jose/src/verify.rs` |
| `kek_unwrap` | `LocalKek::open` | `crates/jose/src/kek.rs` |
| `pairwise_subject` | `PairwiseSalt::derive_subject` | `crates/domain/src/entities/user.rs` |
| `par_form` | `validate` | `crates/oidc/src/authorize.rs` |
| `password_policy` | `normalise` | `crates/domain/src/entities/password.rs` |
| `pkce` | `CodeChallenge::parse` | `crates/oidc/src/pkce.rs` |
| `pkce` | `CodeVerifier::parse` | `crates/oidc/src/pkce.rs` |
| `redaction_scan` | `classify` | `crates/domain/src/audit/redaction.rs` |
| `redirect_uri` | `RedirectUri::parse` | `crates/domain/src/entities/client.rs` |
| `request_uri` | `digest_of` | `crates/oidc/src/par.rs` |
| `tenant_route` | `route` | `crates/oidc/src/tenancy.rs` |
| `token_form` | `dispatch` | `crates/oidc/src/token.rs` |
| `webauthn_client_data` | `verify` | `crates/webauthn/src/client_data.rs` |
