# Kubernetes

The chart is in [`../../deploy/helm/asterius`](../../deploy/helm/asterius). It
deploys the binary and nothing else: PostgreSQL is yours, and so is whatever
backs it up.

**Status:** the chart renders and validates, and every claim below is read off
the templates or the code they configure. It has not been installed on a
cluster in anger, and there is no published image for it to pull yet — see
[The image, and the tag that is not there](#the-image-and-the-tag-that-is-not-there).

Related: [`../../deploy/README.md`](../../deploy/README.md) (the image, the
example compose stack), [`tls-and-proxy.md`](tls-and-proxy.md) (everything the
Ingress has to get right), [`../configuration.md`](../configuration.md) (every
key, generated from the schema), [`../runbooks/upgrade.md`](../runbooks/upgrade.md)
(what an upgrade does to the schema),
[`verifying-a-release.md`](verifying-a-release.md) (the signature and the SBOM
behind the image this chart pulls).

---

## 1. What the chart assumes

- **PostgreSQL exists** and the pod can reach it. There is no subchart and no
  operator: a database an application chart brought up is a database nobody
  backs up.
- **TLS is terminated in front**, by an Ingress controller. The chart's default
  `service.portName` is `http`, which is what `mode = "behind_proxy"` actually
  speaks. In-process TLS (`mode = "terminate_tls"`) works too — mount the
  certificate through `extraVolumes` and rename the port — but nothing in the
  chart assumes it.
- **One process, no coordination.** All state is in PostgreSQL; there is no
  leader, no cache to warm and no sticky session. Replicas are interchangeable,
  and the only reason the default is one is §4.

## 2. Install

```sh
kubectl create namespace asterius

# The three secrets, from your secret store rather than from a values file.
kubectl -n asterius create secret generic asterius-kek \
  --from-literal=kek="$(head -c 32 /dev/urandom | base64)"
kubectl -n asterius create secret generic asterius-admin \
  --from-literal=password="$(head -c 24 /dev/urandom | base64)"
kubectl -n asterius create secret generic asterius-database \
  --from-literal=url='postgres://asterius:…@postgres:5432/asterius'

helm install asterius deploy/helm/asterius -n asterius -f my-values.yaml
```

`my-values.yaml` has to contain at least `image.tag`, `config.contents` and the
names of those secrets; `helm install` fails with a message naming
`config.contents` rather than starting a pod that crash-loops on an empty
configuration. [`values.yaml`](../../deploy/helm/asterius/values.yaml) documents
every key, and
[`ci/minimal-values.yaml`](../../deploy/helm/asterius/ci/minimal-values.yaml) is
the smallest file that renders.

### The image, and the tag that is not there

`image.repository` defaults to `ghcr.io/asteriusit/asterius-idp`, which is what
[`release.yml`](../../.github/workflows/release.yml) publishes — with a cosign
signature and a CycloneDX SBOM — on every `v*` tag. The repository is real. The
tag is not: no release has been cut, so `Chart.appVersion` is `0.0.0` and names
nothing in the registry. Until the first tag, build the image and point
`image.repository` at your own registry.

When there is a release, set **`image.digest`, not `image.tag`**. A tag is a
name and a name can be re-pointed under a running deployment; the signature is
over the digest and nothing else, so a digest in the chart and a digest in
`cosign verify` are the same fact.
[`verifying-a-release.md`](verifying-a-release.md) is that check, and it is
worth running before the digest goes into a values file rather than after.

### Configuration is a file, not a values tree

`config.contents` is the whole of `asterius.toml`, pasted in and rendered into a
ConfigMap mounted at `/etc/asterius/asterius.toml`. The chart does not offer
`tenants:` or `features:` keys of its own, on purpose: an unknown key in that
file is a startup error rather than a warning, so a chart that templated the
schema would be a second copy of it that goes stale the first time the schema
moves. [`../configuration.md`](../configuration.md) is generated from the schema
and is the only thing that is authoritative.

Editing `config.contents` changes a checksum annotation on the pod template, so
`helm upgrade` restarts the pods. Without that, the ConfigMap would change and
nothing would read it until an unrelated rollout.

## 3. Secrets are files

Every secret the binary can take as a path is mounted as a file, in one
projected volume at `/etc/asterius-secrets`:

| File | Configuration key | Notes |
| --- | --- | --- |
| `kek` | `keys.kek_file` | 32 bytes, base64. Every signing key in the database is encrypted under it. |
| `kek-previous` | `keys.kek_previous_file` | During a rotation only. Remove it when `asterius rewrap-kek` is done — while it is set, a retired key stays readable. |
| `admin-password` | `admin.password_file` | Read on every boot and hashed with Argon2id, which is what makes rotating it an edit and a restart. |
| `dpop-nonce-secret` | `dpop.nonce_secret_file` | Only under `[features] dpop_nonce = true`. Absent means per-process nonces: a round trip, not a failure. |

A file rather than an environment variable because an environment variable is
readable through `/proc/self/environ` and shows up in a process listing;
`../configuration.md`, "Secret sources", says the same thing key by key.

The one exception is the database URL, which has no `*_file` spelling. It is
injected as `ASTERIUS__DATABASE__URL` from a Secret. That is second-best and it
is a deliberate second-best: the URL is a credential *to* the database, not the
key that decrypts what is in it.

`secrets.<name>.value` exists and creates a Secret from your values file. It is
for a test cluster. Anything in a values file is in the release history and in
`helm get values`, and the chart prints a warning when you use it.

The mount is beside `/etc/asterius`, not underneath it: the configuration is a
read-only ConfigMap volume and a second volume mounted inside it would need a
directory created in a read-only mount. If you change `secretMountPath`, change
the paths in `config.contents` to match — nothing checks that they agree except
the server, at boot, by failing.

## 4. Rollout strategy: why `Recreate`

Migrations run at process start, under a PostgreSQL advisory lock, so replicas
starting together do not race: one migrates and the others find there is nothing
to do. What they cannot avoid is sharing a schema. The first pod of a new build
migrates the database *under* the pods that have not restarted yet, and
[the upgrade runbook §4](../runbooks/upgrade.md) reads every migration against
the code that preceded it. Eight of ten are additive. Two are not:

- **`0005`** drops `auth_requests.dpop_jkt`. An un-restarted pod then fails PAR
  and the authorization request that consumes the `request_uri`.
- **`0011`** adds a check constraint on client mTLS subjects. An un-restarted
  pod then fails `POST /register` and console client creation for
  `tls_client_auth` clients.

Neither corrupts anything — both are refusals — so the cost is a window of
errors as wide as the rollout. `Recreate` closes that window by never having two
versions alive at once, and pays for it with a short outage. For an OpenID
Provider, whose failures are other systems' login failures, a bounded outage is
easier to reason about than a partial one.

Set `updateStrategy.type: RollingUpdate` when you have read §4 for the
migrations you are actually crossing and they are all additive. Then keep
`maxSurge: 1`, `maxUnavailable: 0` and the rollout short.

Upgrades themselves — backup first, what to read in the logs, how to roll back
— are [`../runbooks/upgrade.md`](../runbooks/upgrade.md). Two things from it
that decide chart values: there is no `migrate` subcommand, so no migration Job
belongs in this chart; and there are no down migrations, so rolling the image
back does not roll the schema back.

## 5. Probes, and what `/readyz` actually attests

Both probes are `httpGet`. They could not be `exec`: the image is distroless and
contains the binary and nothing else — no shell, no `curl`, nothing to exec.

**`/healthz` is liveness.** It never touches the database, deliberately: a
database outage that failed liveness would get every replica killed and turn an
outage into a longer one. It carries the running `version`, which makes it the
cheapest way to see which build a pod is on.

**`/readyz` is readiness, and it is a real assertion.** Reading
`crates/server/src/observability/health.rs`, it is 200 only when both of these
are true, and 503 otherwise:

- `database` — the store answered a ping;
- `migrations_applied` — every migration compiled into *this* binary is recorded
  applied.

```json
{"ready":true,"database":true,"migrations_applied":true,"features":["…"]}
```

So a pod that is ready has a reachable database *and* a schema at least as new
as its own code. Two caveats worth having in mind:

- The check is `count >= expected`, so a database that is *ahead* of the binary
  still reads ready. That is what makes rolling an image back possible at all,
  and it is also why readiness cannot tell you a pod is running against a schema
  it does not fully understand (§4 is that conversation, and it is a human one).
- `features` is the flag set this deployment offers. If it is not what you
  meant, the configuration is not what you meant — check it after the first
  install, before anyone integrates against the discovery document.

**The startup probe is what makes the liveness settings safe.** The first pod of
a new build applies migrations before it binds, and a migration that takes
longer than three failed liveness checks would have the kubelet kill it
mid-migration, repeatedly. `probes.startup` allows two minutes by default;
raise `failureThreshold` before crossing a migration you expect to be slow.

## 6. Pod security

The image is already non-root, shell-less and writes nothing of its own. The
chart asserts all of it again at the cluster level, so the guarantee survives
someone rebuilding the image from a different base — the same reason the compose
file repeats it. If one of these has to be removed to make the pod run, that is
a bug in the image.

| Setting | Value |
| --- | --- |
| `runAsNonRoot` / `runAsUser` / `runAsGroup` | `true` / `65532` / `65532` — the distroless `nonroot` user |
| `readOnlyRootFilesystem` | `true` |
| `allowPrivilegeEscalation` | `false` |
| `capabilities.drop` | `[ALL]` — the server binds :9443, which needs no privilege |
| `seccompProfile` | `RuntimeDefault`, on pod and container |
| `automountServiceAccountToken` | `false` — Asterius never calls the Kubernetes API |

`/tmp` is a 16 MiB memory-backed `emptyDir`. The process writes nothing of its
own; it exists so that a library reaching for a temporary file fails at write
time rather than making the read-only root filesystem unusable, and being
memory-backed it counts against the container's memory limit rather than filling
a node.

That set satisfies the `restricted` Pod Security Standard, so the namespace can
carry `pod-security.kubernetes.io/enforce: restricted`.

## 7. Ingress

Off by default, because an Ingress that gets the headers wrong is worse than no
Ingress. [`tls-and-proxy.md`](tls-and-proxy.md) is the guide; these are the
parts that decide annotations.

- **The host the pod sees must be the public authority, port included.** It is
  what chooses the tenant, and it must equal the authority of that tenant's
  `issuer` (§3 there). A controller that rewrites `Host` to a service name must
  send the public one in `X-Forwarded-Host`.
- **Nothing may rewrite the path.** `/t/<tenant>` is part of the issuer (§7). No
  `rewrite-target`, no prefix added or stripped.
- **A client-supplied `Forwarded`, `X-Forwarded-Host` or `X-Client-Cert` must
  never survive.** The trust check inside Asterius is on the *peer*, not on who
  wrote the header, so once the controller's pod CIDR is in `trusted_cidrs`
  anything it forwards is believed. Overwrite all three unconditionally —
  including setting the certificate header to empty when there is none, which
  decodes to "no certificate".
- **Do not let the controller add security headers.** Asterius sets HSTS, CSP,
  `X-Frame-Options` and `Referrer-Policy` on every response, and a browser
  treats duplicated CSP as the intersection of the two.
- **With mTLS, request but do not require a client certificate.** Browsers reach
  `/authorize` and `private_key_jwt` clients reach `/token` without one;
  verification happens inside Asterius against the tenant's anchors, so the
  controller's client-CA list is a filter, not the trust decision.

`ingress.annotations` in `values.yaml` carries a worked ingress-nginx example.
One controller-level catch: `nginx.ingress.kubernetes.io/configuration-snippet`
is refused unless the controller runs with `allow-snippet-annotations: true`,
off by default since ingress-nginx 1.9. If you cannot enable it, the header
rules have to live in the controller's own ConfigMap or in a proxy in front of
it. They are not optional — without them a client picks its own tenant and its
own certificate.

`trusted_cidrs` in `config.contents` must list the ingress controller's pods and
nothing wider. Everything on the proxy page reduces to that list.

## 8. Verifying the chart

```sh
helm lint deploy/helm/asterius -f deploy/helm/asterius/ci/minimal-values.yaml
helm lint deploy/helm/asterius -f deploy/helm/asterius/ci/full-values.yaml
helm template rel deploy/helm/asterius -f deploy/helm/asterius/ci/full-values.yaml \
  | kubeconform -strict -summary -kubernetes-version 1.30.0
```

The `-f` is not optional: with no values the chart refuses to render, which is
the behaviour §2 describes. `ci/full-values.yaml` turns on every optional object
at once — Ingress, PodDisruptionBudget, both KEKs, the DPoP nonce secret, a
`RollingUpdate` rollout and a chart-created Secret — so that the branches the
minimal file skips are exercised. Both files are development values and neither
is an example to copy.

Against a real cluster, the check is the same one the runbook makes:

```sh
kubectl -n asterius rollout status deploy/asterius
kubectl -n asterius port-forward svc/asterius 9443:9443
curl -fsS http://127.0.0.1:9443/readyz
```

and then one signature end to end — the discovery document, the JWKS and a
token for a test client. `scripts/smoke-test.sh` is that check written down; it
is aimed at the example compose stack, so against a real deployment read it and
take the requests rather than trusting its defaults.
