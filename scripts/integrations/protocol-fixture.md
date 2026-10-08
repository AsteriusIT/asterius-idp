Disposable protocol runtime
===========================

`protocol_fixture.py` runs the unchanged Asterius binary/image against a fresh
`ast_product_<random>` database in an explicitly selected owned PostgreSQL
container. SIGINT/SIGTERM stops only its named runtime and drops only that DB.
The helper seeds the existing browser test users and a confidential ordinary RP;
it does not bootstrap a provider by bypassing the admin API.

Set `ASTERIUS_BIN` to the exact host artifact (used for SHA256 evidence),
`ASTERIUS_ACCEPTANCE_DB_CONTAINER` to the owned DB container,
`ASTERIUS_ACCEPTANCE_DATABASE_ORIGIN` to its host connection origin, and
`ASTERIUS_FIXTURE_MANIFEST` to a new private file. Native execution remains the
default. Optional `ASTERIUS_RUNTIME_IMAGE` uses that image's configured entrypoint
with `--config`, host networking, the caller's UID/GID and read-only fixture mounts.
`ASTERIUS_RUNTIME_REVISION` requires the image's
`org.opencontainers.image.revision` label to match before starting.

`ASTERIUS_RUNTIME_HOSTS` accepts comma-separated `DNS-name:public-IP` mappings,
only inside this fixture container. It refuses private/loopback mappings and does
not alter production SSRF policy or the machine's resolver. Verify TLS on the
selected authorized relay before running. `ASTERIUS_FIXTURE_READONLY_PATHS` is a
colon-separated list of owned credential files/directories to mount read-only.

`ASTERIUS_FIXTURE_TENANT_CONFIG` names a private TOML fragment inserted inside the
`e2e` tenant, before the next tenant. Use nested `[[tenant.ssf_upstream_peer]]`
tables with the exact authorized issuer, expected receiver audience and an owned
bearer file; credentials stay in that file. This is operator configuration, not a
node setting. `ASTERIUS_FIXTURE_AUTOMATION_SCOPES` adds explicitly requested scopes
and client_credentials to the disposable RP client; the server still evaluates
its usual token/admin authority. Provider setup must use the guarded admin API.

The fixed issuer is `https://localhost:18444/t/e2e`, with ordinary RP redirect
`https://localhost:18445/callback`. Startup emits only `PRODUCT_FIXTURE_READY`.
The 0600 manifest contains the generated RP secret plus issuer, CA/config paths,
DB name, host binary hash and image revision; never print or commit it. It is
removed on clean shutdown. Each independent harness must use the CA and retain
PKCE/state/nonce and normal independent token verification. Readiness and fixture
provisioning alone are not interoperability evidence.

`ASTERIUS_FIXTURE_FEATURES` optionally selects space-separated `ssf`,
`dpop_nonce`, `request_object` or `advanced_claims` flags for this disposable
configuration. The default remains the original browser fixture configuration;
SSF protocol runs must explicitly enable `ssf`.
