# Asterius Terraform and OpenTofu provider

This protocol 6 provider manages live Asterius configuration through the
[declarative API v1](../../docs/declarative-management.md). It provides six
resources and six corresponding read-only data sources:

| Resource and data source | API kind | Additional read/write scopes |
| --- | --- | --- |
| `asterius_tenant` | tenant | `admin.tenants:read`, `admin.tenants:write` |
| `asterius_application` | application | `admin.clients:read`, `admin.clients:write` |
| `asterius_resource` | resource | `admin.resource_servers:read`, `admin.resource_servers:write` |
| `asterius_group` | group | `admin.groups:read`, `admin.groups:write` |
| `asterius_membership` | membership | `admin.memberships:read`, `admin.memberships:write` |
| `asterius_policy` | policy | `admin.policies:read`, `admin.policies:write` |

Every operation also needs `admin.session:read`. Give a dedicated service client
only the kinds and reach it manages. Data sources need read scopes only. Tenant
creation requires a reserved-tenant service with deployment reach. Controllers
must use different service client IDs; Terraform addresses do not grant authority.

## Build and use locally

The provider is an independent Go module; it does not build the Rust server.
Install Go 1.24 or newer, then:

```sh
cd providers/terraform
go build -o bin/terraform-provider-asterius .
```

Set a CLI development override in a file outside the repository, and export
`TF_CLI_CONFIG_FILE` (also `TOFU_CLI_CONFIG_FILE` for OpenTofu) pointing to it:

```hcl
provider_installation {
  dev_overrides {
    "registry.terraform.io/asterius/asterius" = "/absolute/provider/bin"
    "registry.opentofu.org/asterius/asterius"  = "/absolute/provider/bin"
  }
  direct {}
}
```

Use the [example stack](examples/main.tf). With a development override, run
`terraform plan` / `terraform apply` or `tofu plan` / `tofu apply` directly;
`init` would try the public registry. No provider release or registry publication
is implied by a local build. Provider source addresses and CLI overrides follow
the [Terraform framework](https://developer.hashicorp.com/terraform/plugin/framework)
and [OpenTofu CLI configuration](https://opentofu.org/docs/cli/config/config-file/).

Configure credentials with environment variables so even external key paths do
not need to be included in saved plan configuration:

```sh
export ASTERIUS_ISSUER=https://id.example/t/admin
export ASTERIUS_CLIENT_ID=terraform-controller
export ASTERIUS_SIGNING_KEY_FILE=/run/secrets/terraform-controller.pk8.pem
export ASTERIUS_SIGNING_KEY_ID=controller-key-1
export ASTERIUS_TOKEN_RESOURCE=https://id.example/t/admin/admin/api/v1
export ASTERIUS_SCOPES='admin.session:read admin.groups:read admin.groups:write'
# Optional trusted PEM CA bundle, never skip certificate verification:
export ASTERIUS_CA_FILE=/run/config/organization-ca.pem
```

Each variable also has a provider configuration attribute: `issuer`, `client_id`,
`signing_key_file`, `signing_key_id`, `token_resource`, `scopes`, and `ca_file`.
`request_timeout` defaults to `60s`, bounded to `10m`. `target_tenant` (environment
`ASTERIUS_TARGET_TENANT`) routes creates to another tenant while authenticating
with the issuing tenant; cross-tenant operations require deployment reach.
For a vanity issuer, set `issuing_tenant` (`ASTERIUS_ISSUING_TENANT`) explicitly.
For a target with another authority or vanity host, set `target_issuer`
(`ASTERIUS_TARGET_ISSUER`) together with `target_tenant`; proof URLs then use that
canonical issuer. Tenant create is routed through an existing tenant and names its new target in
`spec_json.tenant_id`. Other operations route by the encoded import identity.

The signing file must hold one PKCS8 PEM P-256 key whose public JWK and `kid`
were independently registered for `private_key_jwt`. The provider obtains
short-lived client-credentials tokens using an issuer-audience assertion,
generates a separate process-local DPoP proof key, and signs fresh request-bound
proofs with token hashes. It handles bounded token and resource nonce challenges,
refreshes expired credentials, requires HTTPS and refuses redirects. This follows
[RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) and
[RFC 9449](https://www.rfc-editor.org/rfc/rfc9449). It does not register its own
service client, generate reusable client secrets, or export the proof key.

## Lifecycle and state

Set a unique, durable, nonsecret `external_key` for every create. Explicit creation
keys are required: repeating the same creation intent after an uncertain response
is safe, while changed intent or reuse after deletion fails. Refresh before retry;
never replace the logical key to hide an uncertain outcome. Preserve partial
stack state; there is no whole-stack transaction.

`spec_json = jsonencode(...)` uses the exact public API schema. It preserves
ordered policy rules. `observed_spec_json` contains the full canonical server
specification. During refresh the server's read-only `/plan` normalizes desired
metadata: defaults do not cause perpetual changes, and console edits update state
so the next plan shows drift. `id`, `identity_key`, `revision`, `owner`, and
`origin_json` expose stable identity and provenance. `identity_key` is the group
UUID or client ID for dependent specs. Each resource accepts `operation_timeout`
(default `2m`, maximum `10m`).

Update and destroy use the exact refreshed revision. A 412 or ownership conflict
stops the operation; refresh and review a new plan. The provider never steals
ownership or retries a stale write with a newer ETag. A group change also changes
membership revisions. When changing parent groups and memberships in one stack,
a dependent operation may require a fresh plan after the parent commits; preserve
completed state and replan. `-parallelism=1` is useful for reviewable acceptance
runs and does not disable concurrency guards.

Import an immutable API ID, never a name:

```sh
terraform import asterius_group.billing 'BASE64URL_IMPORT_ID'
# or: tofu import asterius_group.billing 'BASE64URL_IMPORT_ID'
```

Import/read never adopts. Set imported `spec_json` to the full canonical public
specification returned by the data source or `observed_spec_json`; review that
configuration before planning. A shorter partial spec may show a harmless first
update to align configuration after import. Omit `external_key` in imported resource configuration;
the provider records an import-only identity rather than inventing a creation
mapping. An unowned imported object requires `adopt = true` in a separate apply
before mutations. Existing controller ownership and managed builder origins refuse
adoption. Matching owned imports are usable without takeover.

Deletion protection defaults to true. Apply `deletion_protection = false`
separately before destroy. Group members and role dependencies must be removed
first. Use `retain_on_delete = true` to conditionally release ownership and retain
live state. Tenants always require retain/release; actual deletion is unavailable
in v1. A foreign controller's object cannot be deleted or released. Deleted
logical identities are retained by the API, and old creation keys cannot be reused.

State, plans and CLI output contain public specifications, identifiers, ownership,
provenance and optional configured file paths. Policy literals and tenant settings
are public configuration, **not** a secret store. Never embed confidential strings
in those fields. Private/symmetric JWK fields, reusable token/secret fields and
private PEM data are rejected, including duplicate JSON fields that could hide
material. Server responses are checked before state writes. The provider does not
log request/response bodies and reports only bounded error codes. Debug tracing in
Terraform/OpenTofu can print configuration supplied by the operator; do not put
secrets in HCL or enable trace logs for confidential configurations. Protect state
and saved plans as configuration records even though credentials are external.

## Checks and real server acceptance

```sh
go test ./internal/client ./internal/provider
go vet ./...
# Install Terraform and OpenTofu from their official releases first.
ASTERIUS_ACCEPTANCE_CLI=1 go test ./internal/acceptance -run TestControlledCLI -v
# Optional custom paths:
# ASTERIUS_ACCEPTANCE_TERRAFORM=/path/terraform ASTERIUS_ACCEPTANCE_TOFU=/path/tofu
```

The controlled HTTPS fixture verifies real ES256 assertions/proofs, token hashes,
scopes and proof replay; both actual CLIs apply/import all six kinds, read all six
data sources, refresh, obtain an empty second plan, repair console drift, refuse a
foreign controller, reject tenant deletion and exercise protection before delete.
State and captured diagnostics are scanned for private material and token fields.

`TestLiveCLI` runs the same scenario against a **real Asterius server**. The
[reproducible fixture runner](../../scripts/provider-acceptance.sh) uses Docker,
OpenSSL, Python with `cryptography`, Go and both CLIs, creates a uniquely named
PostgreSQL database, boots the supplied binary on a separate TLS port, seeds
public service registrations/user data, runs acceptance, then drops only that
database and removes temporary keys. It does not compile Rust:

```sh
ASTERIUS_BIN=/absolute/verified/asterius \
ASTERIUS_ACCEPTANCE_DB_CONTAINER=disposable-postgres-container \
ASTERIUS_ACCEPTANCE_TOFU=/absolute/tofu \
./scripts/provider-acceptance.sh
```

For an independently prepared fixture, prepare a
dedicated, migrated test database and a local TLS listener using existing bootstrap
configuration; never point it at production or an existing user's seeded DB.
Register two service clients with the same external public ES256 JWK but distinct
IDs, permit the six kind scopes above and the admin API resource, and seed one
existing same-tenant user. The issuer must be a reserved tenant so tenant creation
is authorized. The fixture must start without a tenant policy document. Use the
existing admin bootstrap/startup and seed SQL/API tooling; the provider intentionally
has no privileged bootstrap endpoint.

In addition to the credential variables, set:

```sh
export ASTERIUS_ACCEPTANCE_LIVE=1
export ASTERIUS_ACCEPTANCE_OTHER_CLIENT_ID=terraform-controller-other
export ASTERIUS_ACCEPTANCE_PUBLIC_JWK=/outside/repo/controller.public.jwk.json
export ASTERIUS_ACCEPTANCE_USER_ID=00000000-0000-0000-0000-000000000001
export ASTERIUS_ACCEPTANCE_DRIFT_COMMAND=/outside/repo/change-fixture-group
# This executable receives one import ID and changes its display_name through
# an ordinary admin API/console write, or the isolated fixture's DB writer.
go test ./internal/acceptance -run TestLiveCLI -v -count=1
```

The harness creates temporary configuration/state directories and uses explicit
creation keys. It removes its independent audience and its single tenant policy
after verification; retained tenants and the other fixture-owned objects stay in
the isolated database until the fixture database is dropped. Never treat acceptance
cleanup as a production teardown. Record the binary commit and CLI versions with
the acceptance result. Slow server acceptance belongs in an explicitly provisioned
CI fixture; default unit checks do not contact any live service.

Verified on 2026-10-03 with Terraform 1.15.8, OpenTofu 1.13.1 and the real
Asterius integration binary from commit `a351d707`. Both CLI scenarios passed;
the exact membership deletion retry also succeeded after deleting its parent
group, while creating a new membership with that missing parent returned 404.
The runner removed its isolated database and temporary credentials. Go unit
checks, `go vet`, controlled HTTPS CLI acceptance and native parser fuzzing also
passed. This records local acceptance, not a claim about a published provider
registry or a remote CI run.
