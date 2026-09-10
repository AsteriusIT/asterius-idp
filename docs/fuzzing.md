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

The 72 targets below cover 91 declared entry points. Generated from the
`// fuzz-target:` markers in `crates/`.

| Fuzz target | Entry point | Source |
|---|---|---|
| `access_token_claims` | `AccessToken::subject_claim` | `crates/oidc/src/tokens/access.rs` |
| `access_token_claims` | `actor_claim` | `crates/oidc/src/tokens/access.rs` |
| `access_token_claims` | `thumbprint` | `crates/oidc/src/tokens/access.rs` |
| `acr_policy` | `AcrPolicy::assign` | `crates/domain/src/entities/acr_policy.rs` |
| `acr_policy` | `AcrPolicy::from_json` | `crates/domain/src/entities/acr_policy.rs` |
| `admin_client_request` | `requested_status` | `crates/admin-api/src/clients.rs` |
| `admin_client_request` | `search_term` | `crates/admin-api/src/clients.rs` |
| `admin_cursor` | `Cursor::decode` | `crates/admin-api/src/pagination.rs` |
| `admin_fetch_metadata` | `site` | `crates/admin-api/src/csrf.rs` |
| `admin_idempotency_key` | `IdempotencyKey::parse` | `crates/admin-api/src/idempotency.rs` |
| `admin_initial_access_token_request` | `requested` | `crates/admin-api/src/initial_access_tokens.rs` |
| `admin_key_request` | `PurgeReason::parse` | `crates/domain/src/keys.rs` |
| `admin_key_request` | `PurgeRequest::reason` | `crates/admin-api/src/keys.rs` |
| `admin_key_request` | `RotationRequest::algorithm` | `crates/admin-api/src/keys.rs` |
| `admin_key_request` | `ScheduleRequest::schedule` | `crates/admin-api/src/keys.rs` |
| `admin_key_request` | `public_members` | `crates/admin-api/src/keys.rs` |
| `admin_user_claims` | `accept_claims` | `crates/admin-api/src/users.rs` |
| `agent_profile` | `AgentLimits::from_json` | `crates/domain/src/entities/agent.rs` |
| `agent_profile` | `AgentProfile::from_json` | `crates/domain/src/entities/agent.rs` |
| `attestation_object` | `parse` | `crates/webauthn/src/attestation.rs` |
| `audit_canonical` | `canonical_bytes` | `crates/domain/src/audit/chain.rs` |
| `audit_record` | `read_event` | `crates/domain/src/audit/record.rs` |
| `authenticator_data` | `verify_assertion` | `crates/webauthn/src/authenticator_data.rs` |
| `authenticator_data` | `verify_registration` | `crates/webauthn/src/authenticator_data.rs` |
| `authorization_code` | `digest_of` | `crates/oidc/src/code.rs` |
| `authorization_details` | `AuthorizationDetails::parse` | `crates/domain/src/entities/authorization_details.rs` |
| `authorization_hints` | `Prompt::parse_list` | `crates/oidc/src/authorize.rs` |
| `authorization_hints` | `parse_acr_values` | `crates/oidc/src/authorize.rs` |
| `authorization_hints` | `parse_id_token_hint` | `crates/oidc/src/authorize.rs` |
| `authorization_hints` | `parse_login_hint` | `crates/oidc/src/authorize.rs` |
| `authorization_hints` | `parse_max_age` | `crates/oidc/src/authorize.rs` |
| `claim_name` | `ClaimName::parse` | `crates/domain/src/entities/user.rs` |
| `claims_request` | `ClaimsRequest::parse` | `crates/oidc/src/claims.rs` |
| `client_assertion` | `check_assertion` | `crates/oidc/src/client_auth.rs` |
| `client_certificate` | `ClientCertificate::from_der` | `crates/oidc/src/mtls.rs` |
| `client_certificate_header` | `from_proxy_header` | `crates/server/src/mtls.rs` |
| `client_metadata_json` | `ClientRegistration::from_json` | `crates/domain/src/entities/client.rs` |
| `client_update_guard` | `update_guard` | `crates/server/src/http/client_configuration.rs` |
| `config_parse` | `Config::parse` | `crates/server/src/config.rs` |
| `consent_memory` | `Remembered::covers` | `crates/oidc/src/consent_memory.rs` |
| `cose_key` | `parse` | `crates/webauthn/src/cose.rs` |
| `csp_form_action` | `FormActionOrigin::parse` | `crates/web/src/csp.rs` |
| `device_authorization_request` | `validate` | `crates/oidc/src/device.rs` |
| `device_user_code` | `UserCode::parse` | `crates/oidc/src/device.rs` |
| `dpop_proof` | `NonceIssuer::accepts` | `crates/jose/src/dpop.rs` |
| `dpop_proof` | `NormalisedUri::parse` | `crates/jose/src/dpop.rs` |
| `dpop_proof` | `check` | `crates/jose/src/dpop.rs` |
| `endpoint_bucket` | `endpoint_client_bucket` | `crates/domain/src/rate_limit.rs` |
| `forwarded_resolve` | `resolve` | `crates/server/src/http/forwarded.rs` |
| `grant_management` | `parse` | `crates/oidc/src/grant_management.rs` |
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
| `login_bucket` | `account_bucket` | `crates/domain/src/rate_limit.rs` |
| `logout_request` | `LogoutRequest::parse` | `crates/oidc/src/logout.rs` |
| `pairwise_subject` | `PairwiseSalt::derive_subject` | `crates/domain/src/entities/user.rs` |
| `par_form` | `validate` | `crates/oidc/src/authorize.rs` |
| `password_policy` | `normalise` | `crates/domain/src/entities/password.rs` |
| `pkce` | `CodeChallenge::parse` | `crates/oidc/src/pkce.rs` |
| `pkce` | `CodeVerifier::parse` | `crates/oidc/src/pkce.rs` |
| `recovery_token` | `RecoveryToken::parse` | `crates/domain/src/entities/recovery.rs` |
| `redaction_scan` | `classify` | `crates/domain/src/audit/redaction.rs` |
| `redirect_uri` | `RedirectUri::parse` | `crates/domain/src/entities/client.rs` |
| `refresh_token` | `digest_of` | `crates/oidc/src/refresh.rs` |
| `refresh_token_scope` | `requested_scopes` | `crates/oidc/src/refresh.rs` |
| `registration_policy` | `RegistrationPolicy::evaluate` | `crates/domain/src/entities/registration_policy.rs` |
| `registration_policy` | `RegistrationPolicy::from_json` | `crates/domain/src/entities/registration_policy.rs` |
| `request_object_claims` | `parameters` | `crates/oidc/src/request_object.rs` |
| `request_uri` | `digest_of` | `crates/oidc/src/par.rs` |
| `resource_indicator` | `ResourceIdentifier::parse` | `crates/domain/src/entities/resource_server.rs` |
| `response_mode` | `ResponseMode::parse` | `crates/oidc/src/authorize.rs` |
| `revocation_request` | `classify` | `crates/oidc/src/revocation.rs` |
| `ssf_event_uri` | `EventUri::parse` | `crates/ssf/src/event.rs` |
| `tenant_message_overrides` | `MessageOverrides::from_json` | `crates/domain/src/messages.rs` |
| `tenant_route` | `route` | `crates/oidc/src/tenancy.rs` |
| `tenant_settings` | `TenantSettings::from_json` | `crates/domain/src/entities/tenant_settings.rs` |
| `theme_document` | `Theme::parse` | `crates/domain/src/entities/theme.rs` |
| `theme_image` | `accept` | `crates/admin-api/src/theme_image.rs` |
| `token_exchange_form` | `parse` | `crates/oidc/src/token_exchange.rs` |
| `token_form` | `dispatch` | `crates/oidc/src/token.rs` |
| `ui_locales_parse` | `UiLocales::parse` | `crates/domain/src/locale.rs` |
| `userinfo_presentation` | `present` | `crates/oidc/src/userinfo.rs` |
| `webauthn_client_data` | `verify` | `crates/webauthn/src/client_data.rs` |
