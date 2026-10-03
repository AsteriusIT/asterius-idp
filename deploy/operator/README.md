# Kubernetes identity resources v1alpha1

These manifests implement the schema, namespace admission and RBAC decision in
[the ADR](../../docs/adr/kubernetes-identity-resources.md). They do not install a
running controller; reconciliation is implemented by ast-dd1y.3.5.

Generate reproducible manifests with:

```sh
node tools/identity-operator/schema.mjs --write
node --test tools/identity-operator/test/admission.test.mjs
bash scripts/kubernetes-crd-tests.sh
```

The last command creates and removes its own distinct Kubernetes 1.35 kind
cluster with an explicit private kubeconfig. It never uses your default context.
It validates structural schemas/CEL, examples, admission typechecking, actual
GitOps impersonation, cross-namespace/tenant denial, selected Secret denial,
immutable issuer/audience, unknown credential fields, conflicting JWKS sources,
status write denial and missing-parameter failure. The first real run passed all
23 recorded checks on 2026-10-03; both Node tests passed. This is local acceptance,
not an assertion that remote CI has run.

For an operator-reviewed deployment, install CRDs first and wait for Established.
Provision the namespace, administrator-owned `default` AsteriusTenantBinding,
existing least-privilege FAPI tenant service registration and named Secrets.
Install that namespace's generated RBAC/admission **before** granting GitOps
write permission. `namespace-acme.json` is an example for `identity-acme`; call
the exported `namespaceDocuments(namespace, secretNames)` generator for your
actual namespace and exact Secret names. Do not apply one namespace's admission
binding to another namespace or grant writers a cluster-wide identity Role.
Secret names are administrator-chosen; the controller cannot widen them itself.

GitOps can read the public binding because Kubernetes authorizes admission
parameter access; it cannot mutate it or read any credential/public-JWKS Secret.
The controller can get only configured Secrets, update its precreated Lease and
write managed objects/status. It cannot create the Lease or bootstrap credentials.
Project its Kubernetes service-account credential explicitly with the API-server
audience and renewal rather than turning on a broad Secret-based token.

Apply managed objects with strict server field validation. Public JWKS references
contain only public keys and must pass Asterius key validation. TLS verification,
FAPI `private_key_jwt` and DPoP are mandatory on the Asterius administration hop.
No private application key belongs in these manifests. The example policy is an
empty rule set and grants nothing; review a real policy before applying it.

Retain and deletion protection default on. Opting into Delete does not bypass
protection: reconcile a distinct prior generation with protection disabled, then
delete using the confirmed revision. Removing finalizers manually or destroying
the namespace can orphan remote resources. Recovery requires explicit import
and current-owner release/adoption, never recreating by object name. Recreated
objects receive a new UID/external key and cannot commandeer an earlier remote
incarnation. See the ADR for status, conflict and restart semantics.
