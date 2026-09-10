# Deploying Asterius

One binary and one PostgreSQL. There is no message broker, no cache tier and no
second store to keep consistent: everything Asterius knows lives in PostgreSQL,
and every process is interchangeable with every other. That is a product
decision rather than an accident, and it is what makes the rest of this document
short.

- [`compose/`](compose/) — a runnable example stack.
- [`helm/asterius/`](helm/asterius/) — the Helm chart, and
  [`../docs/deployment/kubernetes.md`](../docs/deployment/kubernetes.md), the
  guide that goes with it.
- [`../docs/configuration.md`](../docs/configuration.md) — every key, with its
  type and default. Generated from the schema; do not edit it by hand.
- [`../docs/deployment/tls-and-proxy.md`](../docs/deployment/tls-and-proxy.md) —
  TLS, HSTS and what a reverse proxy must set, and must strip, in front of this
  server.
- [`../Dockerfile`](../Dockerfile) — the release image.
- [`../docs/deployment/verifying-a-release.md`](../docs/deployment/verifying-a-release.md) —
  checking the signature and reading the SBOM of a published image, before it
  reaches a deployment.
- [`../docs/runbooks/`](../docs/runbooks/README.md) — upgrading, rotating the
  key-encryption key, backup and restore.

## The example stack

```sh
export ASTERIUS_ADMIN_PASSWORD="$(head -c 24 /dev/urandom | base64)"
docker compose -f deploy/compose/docker-compose.yml up --build -d
./scripts/smoke-test.sh
```

The password is exported rather than written into the compose file on purpose:
it seeds the deployment admin, and a literal in a file everybody clones is a
credential everybody has. The stack refuses to start without it.

The smoke test asserts what an operator would check by hand: the process is
alive, it is ready (which means the database answered *and* every migration
compiled into the binary is recorded applied), the `demo` tenant answers on both
well-known forms, its JWKS publishes a public key and no private one, an unknown
tenant is a 404, the seeded deployment admin exists in the reserved tenant with
a deployment-scoped role and authenticated at boot, the reserved tenant refuses
to be deleted — and the container is running non-root, read-only and without a
shell.

Everything in that stack is a development value, and every file says so. Before
this shape is safe anywhere real:

| Change | Why |
| --- | --- |
| Terminate TLS, in front or in-process | The example speaks cleartext on the loopback. FAPI 2.0 SP §5.2 requires TLS on every endpoint. [`../docs/deployment/tls-and-proxy.md`](../docs/deployment/tls-and-proxy.md) is the guide for both shapes. |
| Replace `ASTERIUS_KEK` with a mounted `keys.kek_file` | The example KEK is in the compose file, and an environment variable is readable through `/proc/self/environ`. |
| Replace the database password | `asterius:asterius` is not a credential. |
| Replace `ASTERIUS_ADMIN_PASSWORD` with a mounted `admin.password_file` | The variable is fine for a demo you started by hand; a real deployment mounts the admin password from its secret store, and rotating it is an edit to that file and a restart. |
| Give PostgreSQL real storage and backups | The example uses one local volume and no backup. Losing the database loses every key, grant and session. |

The OpenID Foundation conformance suite is **not** a service in this stack, and
that is deliberate. It is a test harness rather than a thing anyone deploys, it
needs its own TLS, its own hostname and its own seeded clients, and bolting it
onto the example an operator copies would make that example less like a
deployment rather than more. It lives in `conformance/docker-compose.yml`, which
brings up its own PostgreSQL and its own Asterius; `make conformance` runs it.
See `conformance/README.md`.

## The image

`docker build .` produces a distroless image whose only content is the binary.

- **Non-root**, uid/gid 65532, both in the image (`USER nonroot`) and asserted
  again in the compose file, so the guarantee survives a rebuild from a
  different base.
- **Read-only root filesystem.** The process writes nothing of its own. `/tmp`
  is a small tmpfs so that a library reaching for a temporary file fails at
  write time rather than making the whole filesystem unusable.
- **No shell, no package manager, no `curl`.** An attacker who reaches remote
  code execution finds nothing to pivot with. This is also why health probes
  must be HTTP-level (`httpGet` in Kubernetes) rather than `exec`: there is
  nothing in the image to exec.
- **All capabilities dropped**, `no-new-privileges`. The server binds :9443,
  which needs no privilege.

### Why glibc and not musl

A statically linked musl binary would be the tidier artefact. ADR-0004 puts the
crypto on `aws-lc-rs`, whose musl build still means a hand-assembled toolchain,
and a static build nobody can reproduce is worth less than a distroless one
everybody can. Revisit when `aws-lc-rs` ships a musl target that builds from a
stock `rustup` toolchain.

## Configuration and secrets

The binary reads one TOML file, named by `--config` or `ASTERIUS_CONFIG`, and
every key can be overridden as `ASTERIUS__<TABLE>__<KEY>`. An unknown key is a
startup error, not a warning.

`docs/configuration.md` lists every key with its type and default, and its
"Secret sources" section says where each credential should come from. Two rules
matter more than the rest:

1. **The key-encryption key is the one thing you cannot lose.** Every signing
   key in the database is encrypted under it. Back it up somewhere the database
   backup is not.
2. **Nothing secret belongs in the image or in a compose file.** Mount it.

Regenerate the reference after any change to the schema:

```sh
cargo run --quiet --bin asterius -- --config-reference > docs/configuration.md
```

A test fails if you forget.

## Upgrades

Migrations run at startup, under a PostgreSQL advisory lock. Three replicas
starting at once do not race: one migrates, the others wait and then find there
is nothing to do. So an upgrade is an image bump and nothing else — no migration
job, no maintenance window, no ordering to get right.

Whether it can be a *rolling* one is a separate question, and the answer is per
migration: the first new replica migrates the database under the replicas that
have not restarted yet, and the schema is not generally N/N+1 compatible.
[`../docs/runbooks/upgrade.md`](../docs/runbooks/upgrade.md) §4 goes through the
migrations one at a time — most are additive, two break a specific request path
on an un-restarted replica. It is why the Helm chart defaults to `Recreate`.

Two more consequences worth knowing before the first upgrade:

- **A new binary may run against an old schema for a few seconds**, while the
  first replica migrates. `/readyz` returns 503 until every migration compiled
  into *that* binary is recorded applied, so a load balancer that honours
  readiness will not send traffic to a replica that cannot serve it.
- **Rolling back the image does not roll back the schema.** Migrations are
  forward-only. A rollback is safe only as far back as the schema still
  supports; take a database snapshot before an upgrade that you might want to
  undo.

## Kubernetes

[`helm/asterius/`](helm/asterius/) is a chart for the shape this page describes:
the binary, a ConfigMap holding `asterius.toml`, secrets mounted as files, and
an optional Ingress. It brings up no database — a database an application chart
created is a database nobody backs up.

The four things that are Kubernetes-specific rather than restatements of this
page, all of them argued in
[`../docs/deployment/kubernetes.md`](../docs/deployment/kubernetes.md):

- **Probes are `httpGet`, never `exec`.** There is nothing in a distroless image
  to exec. `/healthz` is liveness and never touches the database; `/readyz` is
  200 only when the database answered *and* every migration compiled into that
  binary is recorded applied. A startup probe covers the migration at boot, so
  that a slow migration is not killed by liveness.
- **`PodSecurityContext` repeats the image's guarantees** — non-root 65532,
  read-only root filesystem, no privilege escalation, all capabilities dropped,
  `seccompProfile: RuntimeDefault` — which is enough for the `restricted` Pod
  Security Standard.
- **Secrets are files in one projected volume**, matching `keys.kek_file`,
  `keys.kek_previous_file`, `admin.password_file` and `dpop.nonce_secret_file`.
  Only the database URL is an environment variable, because it has no file
  spelling.
- **The rollout defaults to `Recreate`**, for the reason in "Upgrades" above.

`image.repository` is `ghcr.io/asteriusit/asterius-idp`, which is what
[`release.yml`](../.github/workflows/release.yml) publishes on a `v*` tag. No
tag has been cut yet, so `Chart.appVersion` is still `0.0.0` and there is
nothing to pull: build the image yourself until a release exists. When one does,
set `image.digest` rather than `image.tag` — a tag can be re-pointed and the
cosign signature is over the digest and nothing else. See
[`../docs/deployment/verifying-a-release.md`](../docs/deployment/verifying-a-release.md).

## Still to come

Tracked as follow-ups to `ast-p2l.7`, and deliberately not sketched here in a
form nobody has run:

- Runbooks for upgrade and for key-encryption-key rotation. Until the rotation
  runbook exists, treat the KEK as unrotatable.
- A conformance-suite service in the example stack.
