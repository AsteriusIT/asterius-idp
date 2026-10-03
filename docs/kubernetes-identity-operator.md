# Kubernetes identity operator

The namespace-scoped Go controller uses the existing declarative management v1
API and provider FAPI client. Its schema and trust boundary are defined by
[the CRD decision](adr/kubernetes-identity-resources.md). It manages Application,
Resource and Policy only; it creates no tenants, users or credentials.

Build the executable or operator-reviewed image from the repository root:

```sh
cd providers/terraform
go build -o /tmp/asterius-operator ./cmd/asterius-operator
cd ../..
docker build -f deploy/operator/Dockerfile -t your-registry/asterius-operator:0.1.0 .
```

Publish images only through your authorized release process. The Helm chart
requires an explicit image repository **and digest**, namespace tenant/issuer,
service client ID, public signing key ID, immutable binding UID and cluster ID.
It has no reusable default credential or implicit deployment-tenant authority.
Provision the `default` binding and named Secrets first; obtain its UID with
`kubectl -n <namespace> get asteriustenantbinding default -o jsonpath='{.metadata.uid}'`.
The configured UID must match every reconcile, including after restart. Recreating
the binding requires an explicit administrator rollout with the new UID.

The tenant's service registration must authorize the exact resource audience
`<issuer>/admin/api/v1` and these scopes:

```text
admin.session:read
admin.clients:read admin.clients:write
admin.resource_servers:read admin.resource_servers:write
admin.policies:read admin.policies:write
```

The controller reads that registered management resource before accepting new
service credentials, verifying that the issuer routes to the configured tenant
before any mutation, including custom hosts that do not encode a tenant ID.

Use a distinct confidential FAPI `client_credentials` client with public ES256
JWKS and `private_key_jwt`; its tenant reach remains enforced by Asterius.
Private authentication and DPoP Secret values are single PKCS8 P-256 PEM keys.
The optional issuer CA Secret contains PEM certificates. Application public JWKS
references contain JSON with public keys only. All Secret references are local
and must be in the chart's explicit `secretNames` list; an empty list is refused.
No remote credential material is written to disk, CRD status, events or logs.
Only parsed private keys remain in process memory; this is not a claim of
guaranteed memory zeroization.

Apply the reviewed CRDs first, provision the binding and selected Secrets,
then install with reviewed values:

```sh
kubectl apply -f deploy/operator/crds.json
kubectl wait --for=condition=Established --timeout=60s \
  crd/applications.identity.asterius.io crd/resources.identity.asterius.io \
  crd/policies.identity.asterius.io crd/asteriustenantbindings.identity.asterius.io
helm upgrade --install asterius-operator charts/asterius-operator \
  --namespace identity-acme --values reviewed-operator-values.yaml --skip-crds
```

The chart installs bounded namespaced Roles, a precreated Lease and fail-closed
admission. `gitopsGroup` is optional; when set, it grants only the managed CRD
writes and `default` binding read needed for admission. GitOps cannot get Secrets,
mutate bindings/status or remove the controller finalizer. Finalizer removal is
limited to the exact controller service account or an administrator authorized
to update that namespace's binding. Admission does not replace runtime checks.
The chart disables service-account automount and explicitly projects a renewed
600-second Kubernetes token and API-server CA. The container is nonroot with a
read-only filesystem, no capabilities and no privilege escalation. Explicitly
validate and apply updated CRDs before upgrading the controller with `--skip-crds`. Never temporarily turn off admission to bypass errors.

## Reconciliation and recovery

The controller polls/resyncs the selected namespace, serializes operations and
uses a 30-second Lease with resourceVersion compare-and-swap. It renews before
each object and limits that object's work to ten seconds; network operations
have a five-second timeout. A standby writes no Asterius state. A replacement
Pod with another holder waits for the Lease to expire; a container restart in the
same Pod can resume using the same UID. Healthy resync is two seconds; failures
use bounded exponential backoff up to ten seconds. Inventory pages contain at
most twenty objects and each kind is limited to twenty pages; response size is
bounded to two MiB. Size/capacity errors refuse work and require operator action.

Before remote creation/adoption/update, persist
`identity.asterius.io/remote-resource` as a finalizer. External creation identity
includes cluster, namespace, kind and immutable CRD UID. A lost create response
is recovered by the authenticated owner's exact logical-key lookup; restarting
never invents a new identity. Strong remote revisions and Kubernetes resource
versions protect different concurrent writers. Metadata/status use conditional
merge patches, preserving GitOps labels, annotations and other finalizers.

Ready reflects the last confirmed canonical remote state and its desired
generation. A new desired generation is not ready until confirmed. Remote
changes at the same observed generation produce `Drifted=True`, `Ready=False`
without an overwrite. Submit a reviewed new desired spec generation to resolve
drift; the controller refreshes, plans and applies at the current ETag. There is
no force or silent auto-adoption. Readable foreign ownership produces an explicit
OwnershipConflict. Policy permits one CRD per namespace; competing policy objects
all report conflict. RuleSet JSON is validated through the authoritative planner
before any mutation, retaining order and complete conditions.

Secret content is read each cycle. A changed authentication/DPoP/CA bundle
discards cached service credentials and constructs a new client. Invalid or
unavailable keys refuse requests and expose only a fixed bounded condition.
Register new public signing keys before rotating the corresponding private key;
allow the OP's configured public-key cache overlap. Change `keyID` in an explicit
rollout when its public kid changes. The live acceptance checks a real DPoP key
rotation and sender-constrained client-credentials authentication afterward.

Retain is the default: release ownership and preserve live remote state before
removing the finalizer. Delete requires a distinct successful generation that
confirmed `deletionProtection=false` and the same strong remote revision. The
API server increments generation when marking a finalizer-bearing CRD for
deletion, so that confirmed generation must be `metadata.generation - 1`.
Disable-and-delete without that reconciliation is refused. Dependency or
protection errors keep the finalizer; remove dependent references through their
actual owner's explicit deprovisioning policy. Durable delete receipts and
owner-free retained reads recover lost finalizer responses without recreating or
re-adopting resources. Administrator finalizer stripping or namespace destruction
can orphan authority; recover through explicit import and current-owner release,
never by reusing a name or overriding an ownership conflict.

The controller is not an API-server authentication adapter and has no impact on
native JWT revocation bounds. Its health/status do not constitute a live
authorization decision. A Kubernetes outage can prevent status writes; use
generation and condition timestamps when diagnosing stale state.

## Verification

Run focused checks and the disposable real integration:

```sh
cd providers/terraform
go test ./internal/operator ./internal/client -run '^Test' -count=1
go vet ./internal/operator ./internal/client ./cmd/asterius-operator
cd ../..
ASTERIUS_BIN=/path/to/verified/asterius \
ASTERIUS_ACCEPTANCE_DB_CONTAINER=your-disposable-postgres-container \
  bash scripts/operator-acceptance.sh
```

The runner uses port 9457 by default, rejects occupied ports/existing cluster
names, creates a UUID database and fresh Kubernetes 1.35 kind cluster, and uses
only explicit kubeconfigs. It obtains a real service-account TokenRequest for
the restricted controller and authenticates real FAPI/DPoP calls against the
verified binary. It demonstrates three-kind create, committed-response-loss
recovery, stable identity after restart, real dual-owner denial, Secret rotation,
immutable binding isolation, standby Lease, actual server timeout/recovery,
ordinary-writer drift and conditional resolution, Retain and protected Delete.
The response-loss case intentionally discards the result after a real committed
request; the timeout case pauses only the owned real server. No mock OP or fake
clock supplies interoperability evidence. Private fixture files, the database,
server and cluster are removed on exit. No existing deployment is changed.

The final local run passed on 2026-10-03: all eighteen real checks in
[the public evidence](testing/kubernetes-operator-evidence.json), two focused Go
packages plus vet, 55,159 bounded parser fuzz executions, Helm lint, and twenty-five
real API-server schema/RBAC/admission checks including GitOps finalizer denial.
Remote CI has not been run locally; the workflow reproduces the real checks.

Primary target behavior: Kubernetes 1.35
[Lease MicroTime wire format](https://github.com/kubernetes/apimachinery/blob/v0.35.0/pkg/apis/meta/v1/micro_time.go)
and [deletion generation bump](https://github.com/kubernetes/apiserver/blob/v0.35.0/pkg/registry/generic/registry/store.go#L932).

The [GitOps interoperability and recovery guide](kubernetes-identity-gitops.md)
covers actual Flux delivery, Terraform ownership conflicts and compatible
image upgrade/rollback without changing remote identity references.
