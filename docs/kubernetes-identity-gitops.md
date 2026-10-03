# GitOps interoperability and recovery

The reproducible acceptance uses the ordinary tenant management API, the real
Terraform executable, Flux source/kustomize controllers, and controller Pods
installed from the Helm chart. Run against an already verified local server
binary and a disposable PostgreSQL container:

```sh
ASTERIUS_BIN=/path/to/verified/asterius \
ASTERIUS_ACCEPTANCE_DB_CONTAINER=my-disposable-postgres \
ASTERIUS_OPERATOR_GITOPS=1 bash scripts/operator-acceptance.sh
```

Requirements are Linux amd64, Docker, kind, kubectl, Helm, Terraform, Go 1.24,
Node, Python with cryptography, Git, OpenSSL, curl and rg. The runner creates an
explicitly named Kubernetes 1.35 cluster and UUID database; cleanup removes only
those resources, its processes, image tags and private temporary directory. It
never changes the existing cluster context. The fixture server binds the Docker
bridge gateway so controller Pods and host Terraform can use the same HTTPS
issuer. A fresh certificate pins that exact address. Port 9457 (override with
`ASTERIUS_OPERATOR_PORT`) and the bridge Git fixture port 9462 must be free.

The public [Flux delivery example](../deploy/operator/gitops/flux.yaml) and
[Terraform read reference](../deploy/operator/gitops/terraform-reference.tf)
illustrate the separate writer and reader configuration. Provision the selected
ServiceAccount in the identity namespace and bind its least namespace Role separately.

Only generated public manifests enter the temporary Git repository. The test
serves that repository through Git's real HTTP backend on the disposable bridge.
No credentials are committed, and no remote Git repository is pushed. Flux's
release CLI is downloaded over HTTPS and checked against a pinned SHA256; its
only installed components are source-controller and kustomize-controller.
Production Git transport needs its own verified HTTPS/SSH trust and access
credentials. This fixture does not establish production repository trust.

## Authority and ownership

The platform administrator provisions the tenant, FAPI client, public JWKS,
Secrets, immutable tenant binding, CRDs, admission policies and Helm chart.
Keep the delivery ServiceAccount separate from Flux infrastructure controller
accounts. The acceptance checks actual denied Secret reads, binding writes
and status writes.

Flux delivers Application, Resource and Policy desired specs with
`spec.serviceAccountName: identity-gitops`. That account can manage these three
kinds only in the selected namespace. It cannot read Secrets, change bindings,
write status or strip the controller finalizer. The Flux installation itself is
trusted platform infrastructure; its bootstrap permissions are broader than
this impersonated delivery account. Do not grant its delivery account platform
administrator or operator credentials.

The operator retains its separate confidential client and persistent DPoP key.
A Terraform import and refresh can read an operator-owned identity and produce
an empty plan. A different client's update is refused with a visible ownership
conflict. Import is not a takeover. Prefer data sources when Terraform merely
references an operator-managed object. Resource imports require documented
ownership handoff before writes or destroy.

Use a single declarative writer per remote identity. Flux owns Kubernetes
specification fields, the operator owns finalizer/status fields, and Asterius
checks remote owner plus strong revision. A console change produces Drifted,
which the controller reports without overwriting. A reviewed Git generation can
then reconcile the desired change using the current remote revision.

## Restart, upgrade and rollback

Preserve the canonical issuer, tenant ID, client ID, public cluster ID and
binding UID. Keep the same Kubernetes object UID and remote import identities.
Lease failover may take 30 seconds after an abrupt stop. `Ready` is the last
confirmed observed generation; require a fresh reviewed generation to establish
that the replacement controller actually reconciles successfully.

1. Save public CRD specs, immutable binding pins, remote IDs and the last known
   good image digest. Store credentials in the external credential management
   system, separately from this public backup.
2. Review CRD compatibility, explicitly apply the chart's CRDs and wait for
   Established before upgrading the chart. The runner upgrades with `--skip-crds` after this explicit application.
   Never delete a CRD to perform an upgrade.
3. Upgrade a digest-pinned compatible image. Check Deployment rollout, Lease
   holder, observedGeneration/Ready, unchanged remote IDs and referenced IDs.
   Verify Terraform read plans remain empty for imported or referenced specs.
4. Roll back the chart/image to a compatible revision and verify a fresh desired
   generation again. Rollback does not reverse a remote policy change already
   applied; review an explicit desired rollback in Git if needed.

The controlled test changes immutable image packaging revisions of the same
controller binary, checks actual replacement Pods, then submits a fresh resource
generation after restart, upgrade and Helm rollback. It establishes compatible
packaging recovery; it makes no claim about an incompatible future schema or
conversion webhook. An incompatible CRD downgrade requires an independently
reviewed migration, rather than blindly applying an old CRD.

## Recovery without changing remote references

A lost `status.remoteId` with the original Kubernetes UID is recovered by the
exact durable creation key. Do not invent a replacement identifier or copy a
remote ID from another tenant. Recreating an object changes its UID and its
creation key; use the immutable public `spec.importId` for an existing remote
identity, with `adoptionPolicy: AdoptUnowned` only after the previous owner has
explicitly released it.

A deletion request is irreversible for the Kubernetes incarnation. If Flux
prunes an object configured with Delete while protection remains enabled, the
finalizer and remote object remain. Commit a reviewed recovery rather than
removing the finalizer:

1. Suspend the Flux Kustomization to prevent a simultaneous create/prune loop.
2. A namespace administrator changes the deleting object's deletionPolicy to
   Retain. The controller conditionally releases ownership and completes that
   Kubernetes deletion, preserving the protected remote object.
3. Restore the public manifest with the original remote importId, Retain and
   explicit AdoptUnowned. Resume Flux and wait for the new object incarnation to
   reach Ready with the same remote ID.
4. Verify dependent identity references and read plans. Adoption must fail if a
   different owner acquired the object in the meantime; resolve that conflict
   explicitly, without force.

For actual remote Delete, first apply deletionProtection false in a separate
reviewed generation and wait for Ready. The later delete must match that
confirmed unprotected generation and strong remote revision. Dependencies or a
concurrent revision change keep the finalizer; resolve the dependency or replan.
Protected Retain recovery never authorizes destructive remote deletion.

## Evidence and supported combinations

The CI job `kubernetes-interoperability` runs the same real runner and retains
`artifacts/operator-gitops-e2e.json`. The [committed public evidence](testing/kubernetes-operator-gitops-evidence.json)
records the
exact executable hash, date, versions and passed checks. Private keys, tokens,
Terraform state and fixture logs are removed during cleanup.

| Component | Tested contract |
| --- | --- |
| Asterius management | Contract version 1, ordinary tenant, private_key_jwt and DPoP |
| Identity CRDs | identity.asterius.io/v1alpha1, Kubernetes 1.35.0 structural schemas/CEL |
| Operator chart | 0.1.0, digest-pinned compatible packaging upgrade and rollback |
| Flux | 2.9.6, GitRepository source.toolkit.fluxcd.io/v1 and Kustomization kustomize.toolkit.fluxcd.io/v1 |
| Helm | 4.2.0, explicit CRD application then chart `--skip-crds` |
| Terraform | 1.15.8, actual import/plan/apply with the repository provider |

Other Kubernetes/Flux combinations, Argo CD delivery, future CRD versions and
incompatible binary migrations need their own evidence. The separate provider
acceptance also covers OpenTofu; this combined operator/GitOps run uses Terraform.

See the [operator guide](kubernetes-identity-operator.md),
[Flux Kustomization RBAC](https://fluxcd.io/flux/components/kustomize/kustomizations/#role-based-access-control),
[Flux 2.9.6 release](https://github.com/fluxcd/flux2/releases/tag/v2.9.6), and
[Helm CRD upgrade limitations](https://helm.sh/docs/chart_best_practices/custom_resource_definitions/).
