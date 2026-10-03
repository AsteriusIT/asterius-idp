# Kubernetes identity resources are namespaced and tenant pinned

- **Status:** Chosen; schemas, examples, RBAC and admission verified on Kubernetes 1.35
- **Date:** 2026-10-03
- **Bead:** ast-dd1y.3.4
- **Depends on:** [Declarative management v1](declarative-management-contract.md)

## Decision

Use `identity.asterius.io/v1alpha1` namespaced `Application`, `Resource` and
`Policy`, plus an administrator-owned `AsteriusTenantBinding` named `default`.
Run a controller instance for one explicitly configured namespace, tenant,
canonical issuer and binding UID, using a distinct tenant service credential.
There is no tenant-creation CRD, cluster-wide tenant credential, automatic
credential provisioning, user/password, group/membership, session or token CRD.
Multiple tenants use separate namespaces, instances and credentials. Version 1
does not permit cross-namespace object or Secret references.

This chooses stronger operational isolation than a cluster-scoped tenant CRD or
one deployment-wide service client. Cluster administrators remain trusted to
install CRDs, RBAC and admission and provision tenant bindings. A namespace writer
cannot select the target issuer, tenant or service principal. The controller
must recheck its configured namespace, immutable binding identity and tenant on
each reconcile; namespace labels or admission alone are not authorization.

Schemas, namespace RBAC and parameterized fail-closed CEL admission are generated
by `tools/identity-operator/schema.mjs` into `deploy/operator/*.json`. JSON lists
are Kubernetes manifests. Application exposes a bounded initial FAPI subset:
client name, HTTPS redirect URIs, grant types, scopes, resources and one public
JWKS URI or same-namespace Secret reference containing **public** JWKS only.
The controller supplies confidential `private_key_jwt`, FAPI and DPoP defaults;
specification cannot select an OIDC/public/bearer exception. A private JWK in the
referenced public document is refused before remote plan/apply. Supporting
another registration field requires a versioned schema change, not an arbitrary
admin endpoint mirror.

Resource maps to the exact declarative resource spec: immutable audience URL,
nullable scope list, nullable 1..86400-second token lifetime, and introspection
clients. `null` scopes and `[]` retain their distinct meanings. Policy carries a
bounded `rulesJson` string containing the existing complete RuleSet version 1.
This prevents Kubernetes pruning conditions from an extensible nested document.
The controller parses JSON and validates through the existing Asterius planning
contract before applying; CRD string validation alone is not policy validation.
Rule order is retained. One policy object per tenant is supported; the controller
rejects competing objects instead of making an arbitrary policy winner.

## References, authentication and admission

Binding issuer, tenant, service client, cluster ID and credential Secret names
are immutable. Private authentication/DPoP keys and optional issuer CA are
referenced by same-namespace Secret name and key; no literal secret enters CRD
spec/status. Credential rotation updates Secret content and retains the binding
identity. Controller secret `get` privileges name only administrator-selected
Secrets; it cannot list Secrets. Public-JWKS Secret names must also be explicitly
authorized, never expanded automatically by reading untrusted manifests.

The GitOps Role writes only the three managed kinds and reads the public
`default` binding required for admission parameter authorization. It cannot
read Secrets, mutate bindings or status, create Pods or change RBAC, namespaces,
admission policies or CRDs. The controller Role mutates managed objects/status,
reads the binding and selected Secrets, and updates an administrator-created
leader-election Lease; it cannot create/delete tenant bindings. A deployment
must explicitly project its API-server service-account token; automount is off.

Each namespace has a ValidatingAdmissionPolicy and binding pinned to that
namespace and its `default` parameter. Admission enforces same-namespace tenant
reference. Missing parameter or evaluation error denies; `failurePolicy=Ignore`
is not supported. Structural schemas prohibit a different tenantRef and immutable
audience/import identity changes. Namespaced RBAC prohibits writing another
tenant's objects. APIs can prune unknown fields; use strict server field
validation in tooling, and the controller must independently validate every
specification before any Asterius request.

## Ownership, conflicts and deletion

Map supported objects to the existing declarative v1 API. The remote owner is
always the authenticated issuer tenant and client ID, never a Kubernetes label
or a desired owner field. Generate `external_key` from cluster ID, namespace,
kind and immutable Kubernetes UID, so deleting and recreating the same name
creates a new remote incarnation. Resolve a lost create response by that exact
key before retrying. Restart resumes using remote ID and strong revision; stale
revision refreshes and replans. Never force a write or claim another owner.

`importId` is optional and immutable, using the existing canonical import-ID
format. `adoptionPolicy=Never` defaults to read/plan and report ownership conflict;
`AdoptUnowned` explicitly permits the existing conditional adopt operation only
for an unowned identity at the current ETag. SCIM/LDAP/builder ownership and a
different automation owner cannot be adopted. Remote tenant/kind identity must
match the object's pinned binding before any read or mutation.

Install finalizer `identity.asterius.io/remote-resource` **before** creating,
adopting or mutating remote ownership. Deletion defaults to `Retain`, releasing
this controller's ownership and keeping live state. `Delete` requires a prior
successful reconciliation of `deletionProtection=false` in a separate generation,
then an exact conditional delete. Protection, dependencies, ownership conflict,
storage error and changed incarnation retain the finalizer and expose a bounded
condition. Lost-delete retries use remote tombstone receipts. The finalizer is
removed only after confirmed release/delete, or after proving no remote owned
identity was ever created. Manually stripping it or deleting the namespace is
an administrator break-glass action that can orphan remote state and must be
resolved through explicit import/release; no silent adoption on recreation.

## Status and controller acceptance

Status includes `observedGeneration`, opaque remote ID, strong revision and
bounded conditions `Ready`, `Reconciling`, `Drifted`, `OwnershipConflict` and
`Deleting`. Each condition has its own observedGeneration and transition time.
Top-level observedGeneration records the latest successfully processed desired
generation, never a stale success while a new generation is pending. Ready=True
requires confirmed canonical remote state. Console drift is reported; correction
uses a fresh plan and ETag. Conflict does not erase prior remote identity.
Messages use fixed categories; no raw error body, policy literal, secret,
credential, token or private key reaches status/events/logs. Leader election and
per-object serialization are required; conditions are not an authority source.

This decision adds CRD schemas and admission/RBAC configuration, without changing
an OAuth/OIDC cryptographic profile. The existing declarative API remains the
authoritative runtime validator. Operator reconciliation acceptance belongs to
ast-dd1y.3.5 and GitOps recovery to ast-dd1y.3.6. Validate generated manifests
against the target Kubernetes 1.35 API server, including positive examples,
wrong-tenant/namespace denial, secret access denial, immutable identity and
missing-binding denial; record actual results before closing this decision.

Primary specifications consulted: Kubernetes
[structural schemas and CEL validation](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#validation-rules),
[admission parameters and their authorization](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/#parameter-resources),
[namespace RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#rolebinding-and-clusterrolebinding),
and [finalizers](https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/).
