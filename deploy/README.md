# Deploying Asterius

One binary and one PostgreSQL. There is no message broker, no cache tier and no
second store to keep consistent: everything Asterius knows lives in PostgreSQL,
and every process is interchangeable with every other. That is a product
decision rather than an accident, and it is what makes the rest of this document
short.

- [`compose/`](compose/) — a runnable example stack.
- [`../docs/configuration.md`](../docs/configuration.md) — every key, with its
  type and default. Generated from the schema; do not edit it by hand.
- [`../Dockerfile`](../Dockerfile) — the release image.

## The example stack

```sh
docker compose -f deploy/compose/docker-compose.yml up --build -d
./scripts/smoke-test.sh
```

The smoke test asserts what an operator would check by hand: the process is
alive, it is ready (which means the database answered *and* every migration
compiled into the binary is recorded applied), the `demo` tenant answers on both
well-known forms, its JWKS publishes a public key and no private one, an unknown
tenant is a 404 — and the container is running non-root, read-only and without a
shell.

Everything in that stack is a development value, and every file says so. Before
this shape is safe anywhere real:

| Change | Why |
| --- | --- |
| Terminate TLS, in front or in-process | The example speaks cleartext on the loopback. FAPI 2.0 SP §5.2 requires TLS on every endpoint. |
| Replace `ASTERIUS_KEK` with a mounted `keys.kek_file` | The example KEK is in the compose file, and an environment variable is readable through `/proc/self/environ`. |
| Replace the database password | `asterius:asterius` is not a credential. |
| Give PostgreSQL real storage and backups | The example uses one local volume and no backup. Losing the database loses every key, grant and session. |

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
is nothing to do. So a rolling upgrade is an image bump and nothing else — no
migration job, no maintenance window, no ordering to get right.

Two consequences worth knowing before the first upgrade:

- **A new binary may run against an old schema for a few seconds**, while the
  first replica migrates. `/readyz` returns 503 until every migration compiled
  into *that* binary is recorded applied, so a load balancer that honours
  readiness will not send traffic to a replica that cannot serve it.
- **Rolling back the image does not roll back the schema.** Migrations are
  forward-only. A rollback is safe only as far back as the schema still
  supports; take a database snapshot before an upgrade that you might want to
  undo.

## Still to come

Tracked as follow-ups to `ast-p2l.7`, and deliberately not sketched here in a
form nobody has run:

- A Helm chart, and the Kubernetes-specific parts of this guide (probes,
  `PodSecurityContext`, secret mounts).
- SBOM generation and publication with each release, plus image signing.
- The TLS/HSTS/reverse-proxy guide: what a proxy in front of Asterius has to
  set, and what it must not strip.
- Runbooks for upgrade and for key-encryption-key rotation. Until the rotation
  runbook exists, treat the KEK as unrotatable.
- A conformance-suite service in the example stack.
