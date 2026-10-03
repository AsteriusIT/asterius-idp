# Entra inbound SCIM compatibility — 2026-10-03

The tested Asterius profile **does not support native Entra provisioning**.
The modern Entra connector reached the real server using `Authorization: Bearer`
without a DPoP proof. Asterius refused it with HTTP 401. User and group native
provisioning stops at this boundary; no successful native lifecycle is claimed.

The user explicitly selected Entra ID and authorized the already logged-in Azure
CLI session. Tests created nonce-named applications/service principals and disabled
jobs only. No existing enterprise application, tenant user or tenant group was
modified or assigned. No synchronization job was started. Own cloud objects,
local fixture databases, temporary signing keys and tunnel processes were removed.

## Versioned client and server matrix

| Component | Tested version/profile |
| --- | --- |
| Microsoft Graph | `v1.0`, global Azure cloud |
| Azure CLI | 2.88.0, existing authorized delegated session |
| Application template | `8adf8e6e-67b2-4cf2-a259-e3dc5476c621` non-gallery |
| Legacy requested job | `customappsso`, effective `customappssoOutDelta`, disabled |
| Modern requested job | `scim`, effective `scim`, disabled |
| Available templates | `customappsso`, `customappssoOutDelta`, `customappssoRoleIn`, `scim` |
| Asterius | integration binary `a351d707`, bounded SCIM v2 DPoP-only profile |
| Temporary public transport | cloudflared 2026.9.3, official release SHA256 verified |
| Native token configuration | `BaseAddress` plus a real Asterius scoped DPoP token in `SecretToken`; private temporary JSON |

Microsoft documents [template instantiation](https://learn.microsoft.com/en-us/graph/api/applicationtemplate-instantiate?view=graph-rest-1.0)
and [disabled job creation and credential validation](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/application-provisioning-configuration-api).
The [current SCIM job replaces legacy customappsso](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/application-provisioning-config-problem-scim-compatibility).

Sanitized [machine-readable lifecycle evidence](evidence/entra-scim-2026-10-03.json)
records the final real fixture run. Active-directory cleanup queries confirmed zero
remaining nonce-prefixed fixture applications or service principals.

## Native observations

| Native step | Observation | Consequence |
| --- | --- | --- |
| Instantiate app/SP and enumerate templates | Graph operations succeeded | Real authorized customer-tenant client exercised |
| Legacy `validateCredentials` | Appended `/scim` to configured SCIM base, requested `/scim/v2/scim/Users`; proxy boundary returned 404 | Legacy connector unsuitable for this mount; use current job for new integrations |
| Modern `validateCredentials` | `GET Users`, `Bearer`, no DPoP; upstream 401 SCIM error | Authentication incompatible, fail-closed |
| Modern Graph result | `CredentialValidationUnavailable`, nested `SystemForCrossDomainIdentityManagementCredentialValidationUnavailable`, upstream Unauthorized (401) | Native refusal recorded, rather than treating connection check as success |
| Native create/update/group/disable/delete/retry | Not executed after failed authentication | These remain unverified for Entra |

The temporary proxy exposed only the selected tenant's SCIM resource paths. It
forwarded authentication unchanged and recorded only method, resource name,
authorization scheme, proof presence and response status. It exposed no admin,
token, login, health or unrelated tenant endpoint. It did not mint proofs, convert
Bearer to DPoP, or grant native Entra requests authority. Query strings, tokens,
request/response bodies and credentials were absent from committed evidence.

## Independent real Asterius control probes

These use real client credentials/private-key JWT and DPoP locally, not Entra's
native provisioner. They separate server profile behavior from the native barrier.

| Probe | Actual result |
| --- | --- |
| Discovery: ServiceProviderConfig, Schemas, ResourceTypes | 200 each |
| Same valid token sent as Bearer | 401 |
| Same token attempts another tenant's user creation | 401 |
| Create user / duplicate same create | 201 / 409 |
| Exact `userName eq "value"` filter | 200 |
| `externalId` filter | 400 |
| User PATCH without `If-Match` / stale ETag | 428 / 412 |
| Boolean active=false / provisioning reactivation with current ETag | 200 / 200 |
| Security lock followed by SCIM active=true | 409, account remains locked |
| Disable locked user | 200; original run did not test a subsequent activation |
| Legacy string `active: "False"` | 400 |
| User POST with default `name` mapping | 400 |
| Create Group with direct member | 201 |
| Other provisioning client reads owned Group | 404 |
| Group `excludedAttributes=members` query | 400 |
| Modern `members[value eq "id"]` removal with current ETag | 200 |
| Group/User delete with current ETags, deleted User read | 204 / 204 / 404 |

The existing [Asterius runbook](../runbooks/scim-provisioning.md) defines the
supported profile. Microsoft's [documented endpoint behavior](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups)
uses Bearer authentication and broader attribute/query examples. Its examples
omit conditional write headers; this is a documented compatibility concern, not
an assertion that an authenticated native mutation was observed. Microsoft's
[known PATCH behavior](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/application-provisioning-config-problem-scim-compatibility)
also distinguishes legacy string booleans and modern member removal shapes.

## Reproduction

Install Azure CLI, Docker, OpenSSL, Python `cryptography` and an official verified
cloudflared binary. Supply an already verified local Asterius binary and a disposable
PostgreSQL container; no Rust build is required. The fixture creates a random database,
uses existing `e2e/fixtures/asterius.toml.in` bootstrap, registers only two local public
SCIM service clients and runs the control and native probes. Choose unused ports.
The current Azure CLI tenant must match the explicitly pinned tenant below.

```sh
ASTERIUS_BIN=/absolute/verified/asterius \
ASTERIUS_ACCEPTANCE_DB_CONTAINER=disposable-postgres-container \
ASTERIUS_ACCEPTANCE_PORT=9451 \
ASTERIUS_ENTRA_PROXY_PORT=9481 \
ASTERIUS_ENTRA_ACCEPTANCE=1 \
ASTERIUS_ENTRA_TENANT=authorized-tenant-uuid \
ASTERIUS_ENTRA_MANIFEST=/outside/repo/owned-entra-objects.json \
ASTERIUS_CLOUDFLARED=/absolute/verified/cloudflared \
./scripts/scim-entra-acceptance.sh > /outside/repo/sanitized-evidence.json
```

The explicit cloud flag acknowledges the separately authorized fixture; it does
not obtain Azure privileges. Bodies pass through mode-0600 files to `az rest --body
@file`. The runner pins the active cloud/tenant, creates only uniquely named app/SPs,
keeps jobs disabled, retries bounded directory replication reads, and deletes only
IDs returned by its own instantiate call. If cleanup fails, the external manifest
retains owned public object IDs for recovery. It never calls broad tenant cleanup.
The shell trap kills its own server, drops only its random database, and removes
private fixture files. An interrupt or host crash requires checking that recovery
manifest; remote object cleanup cannot be guaranteed after process termination.

## Security-lock follow-up

The initial control proved only direct locked-to-active refusal. A later real
HTTP regression against the same `a351d707` binary found that SCIM `active=false`
changed Locked to Disabled, after which `active=true` returned 200. This two-step
bypass is tracked in `ast-xxt7`. The updated control runner requires the second
activation to remain refused (409); the store correction preserves Locked through
SCIM disable/delete, leaving administrator unlock authority separate. Original
historical evidence above must not be read as proof against this two-step case.
Run the updated actual-server security regression without cloud operations:

```sh
ASTERIUS_BIN=/absolute/verified/security-fixed/asterius \
ASTERIUS_ACCEPTANCE_DB_CONTAINER=disposable-postgres-container \
ASTERIUS_SCIM_CONTROL_ONLY=1 \
./scripts/scim-entra-acceptance.sh
```

This control-only mode requires no Azure CLI/tunnel and explicitly reports native
validation as unexecuted.

## Linked gaps

- `ast-9mjp`: decide a bounded native Entra-compatible authentication boundary,
  with human review and real acceptance. Keep the current DPoP-only profile intact.
- `ast-p3p3`: review conditional-write semantics and a minimal approved attribute,
  filter and PATCH mapping; then run a genuine native lifecycle after the auth
  decision. Preserve tenant/client ownership and security-lock protection.

These are follow-up decisions outside the original epic's verification scope.
Verification of incompatibility is complete; native provisioning compatibility is
not advertised and requires the linked work.

The corrected real-server control run is recorded in
[`scim-security-lock-2026-10-03.json`](evidence/scim-security-lock-2026-10-03.json):
26 scoped DPoP HTTP cases passed, including `active: false` on the locked account
before and after disable and HTTP 409 on subsequent activation with a fresh ETag.
The workspace gate passed 34 targeted and mandatory source/secret audit tests.
The slow persisted Rust regression is compiled and remains reserved for CI.
This follow-up did not rerun native Entra provisioning.
