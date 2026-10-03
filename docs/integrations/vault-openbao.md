# Vault and OpenBao: tested human and workload authentication

This recipe supports OpenBao 2.7.1 and Vault 2.1.1 with two separate trust
profiles. Human login uses Asterius's explicitly enabled standard OIDC client
profile. Workloads authenticate directly with a projected Kubernetes JWT under
an explicitly pinned cluster trust. Asterius sender-constrained access tokens
are not a supported Bearer input to either product's JWT auth method: these
methods do not validate the accompanying DPoP proof.

The [versioned evidence](evidence/vault-openbao-2026-10-03.json) records native
product HTTP outcomes against Asterius main `904a1d86` and Kubernetes v1.35.0.
No production deployment, cloud trust or reusable credential is included.

## Human OIDC login

Use a distinct application and auth mount for humans. A tenant administrator must
explicitly enable `allow_non_fapi_clients` and create an application whose
`compliance_profile` is `oidc`, `token_endpoint_auth_method` is
`client_secret_basic`, grant/response types are `authorization_code`/`code`,
scopes are `openid email`, and ID-token signing algorithm is `ES256`. Register
the exact product HTTPS callback, for example:

```text
https://secrets.example.org/ui/vault/auth/asterius/oidc/callback
```

Select both token-binding flags as false for this conventional client. The
application then receives Bearer access tokens under the accepted
[standard OIDC opt-in](../adr/0014-explicitly-gated-standard-oidc-clients.md).
FAPI clients retain their existing profile. Asterius still requires S256 PKCE;
the tested native clients supply it. PAR and private-key JWT are not used by
this recipe. The ordinary CLI HTTP loopback callback is incompatible with
Asterius's exact HTTPS web redirects; use the HTTPS UI callback instead.
The fixture completes the native callback API after real browser authentication;
it does not claim to test either product's complete UI or CLI shell.

Create the application through Asterius's administrative API/console, capture its
server-generated secret once, and configure the product through a private file.
Use a deployment secret store for that credential; do not put it in a committed
JSON, shell history or diagnostic output. Rotate the Asterius application secret
and replace the product's configured secret together. Standard OIDC is a
confidential client integration, not a workload without stored credentials.

Enable the product's OIDC auth method at `asterius`. The versioned JSON templates
are under [`integrations/secret-systems`](../../integrations/secret-systems/).
Configure the exact Asterius issuer, pinned TLS CA if private, client ID and
server-generated client secret using `human-config.json.in`. The configured
signing allow-list is ES256. Never enable `verbose_oidc_logging`.

Use `human-role.json.in` to bind a role to an approved stable `sub`, exact client
ID audience and `email_verified=true`. Asterius subjects are opaque and differ
from internal user UUIDs: obtain the subject through the verified OIDC identity
for this application, then approve that value. Never authorize a caller merely
because it supplies a role name or a desired subject. The fixture has a temporary
verified-email role solely to learn its disposable account's native subject;
it deletes that role before testing the subject-bound recipe. Production role
setup starts with the approved subject already supplied.

The supplied policy grants one KV read path and self-revocation only; it excludes
the default policy. A second KV path is explicitly refused in the fixture. Group
or custom claim mapping is not advertised by this profile. Add such mapping only
after separately testing the exact claims released to this application.

The templates contain placeholders, including PEM strings. Render them as JSON,
not with shell text substitution. The renderer safely escapes values and creates
a new output file with mode 0600; it refuses to overwrite an existing file or read
values accessible to group/others:

```bash
python3 scripts/integrations/render_secret_system.py \
  --template integrations/secret-systems/human-config.json.in \
  --values /private/human-values.json --output /private/human-config.json
```

The values file is private and has keys matching the template's `${...}` names.
Write the generated config to `auth/asterius/config` and the rendered role to
`auth/asterius/role/human` with an authenticated product API request using a
private request body. The same JSON config and role templates are rendered by
the actual acceptance fixture. Role TTL is five minutes with a five-minute
explicit maximum; the fixture shortens it to test expiry promptly.

[OpenBao's JWT/OIDC guide](https://openbao.org/docs/auth/jwt/) and
[Vault's auth API](https://developer.hashicorp.com/vault/api-docs/auth/jwt)
define the native auth URL/callback, role claims and exact redirect requirements.

## Workload Kubernetes JWT trust

The first workload recipe uses the same kind of projected ServiceAccount identity
verified by the [Asterius Kubernetes exchange](../kubernetes-workload-exchange.md),
but its destination is the product's own JWT auth mount. It does not pass an
Asterius access token through that mount or establish AWS/Azure/GCP trust.

Enable a separate JWT auth method at `kubernetes-jwt`. Pin the exact Kubernetes
issuer and public verification keys using `workload-config.json.in`. The public
key is not a shared secret. The tested profile permits RS256, binds the audience
`urn:asterius:secret-system:workload`, exact namespace, ServiceAccount name and
ServiceAccount UID, and binds `sub` to the corresponding Kubernetes subject.
Use `workload-role.json.in`; do not replace exact values with globs. Wrong issuer,
audience, namespace, ServiceAccount name and a replacement ServiceAccount UID
are refused by both named products.
An administrator must review and replace the public-key set during cluster key
rotation, overlapping only explicitly trusted old/new keys until outstanding
JWTs expire. Automatic JWKS rotation is not exercised by this pinned-key recipe.

`workload-projected-token.yaml.in` describes an audience-specific volume with a
600-second identity TTL and disables the default ServiceAccount token mount.
The workload reads that file afresh for each login at
`auth/kubernetes-jwt/login`, supplying the configured role and current JWT.
It must reload rotations rather than retain the initial file contents. No OAuth
client secret or product token belongs in the Pod manifest. Tokens returned by
the product stay in memory and authorize only the explicit read policy. The role
uses a batch token, 60-second TTL and explicit 60-second cap.

JWT roles use `-1` for all three leeway settings. In these products, `0` selects
their default leeway rather than disabling it; see the
[Vault role API](https://developer.hashicorp.com/vault/api-docs/auth/jwt).
Synchronize issuer and verifier clocks. The real fixture requests fresh Kubernetes
TokenRequest JWTs from its own disposable cluster and validates them against its
public keys; it does not manufacture the successful workload JWT.

This is offline JWT validation. It does not call TokenReview and cannot notice
pod/ServiceAccount deletion before the JWT expires. The fixture deletes its
ServiceAccount, proves that its old JWT still authenticates, then proves that a
new ServiceAccount with the same name cannot use the prior UID-bound role. Use short projected TTLs and
include that residual validity in the deployment's policy. A separate
TokenReview-based Kubernetes auth profile would have a different trust and
availability boundary and is not claimed here.
[OpenBao documents that distinction](https://openbao.org/docs/auth/jwt/oidc-providers/kubernetes/).

## Expiry, logout and secret leases

Asterius login establishes an identity; the product issues its own token. The
fixture verifies that Asterius logout clears its browser session while the
product token still reads the approved KV path. Product self-revocation then
causes that read to fail. A Kubernetes JWT can also obtain a new product token
after an earlier product token expires while the JWT remains valid. Identity
logout, source account disable and identity-token expiry are therefore not
revocation notifications for existing product tokens. Set short explicit product
TTLs and use the product's own token/entity revocation when immediate access
withdrawal is required.

These tests use KV v2, not a dynamic-secret engine. KV values have no renewable
credential lease, and a value already fetched cannot be taken back. Dynamic
secret lease TTLs, renewals and revocation belong to the selected engine and its
backend; they must be configured and verified separately. Do not describe the
identity token's expiry as expiring a database credential, cloud credential or
already issued lease. Batch-token behavior and source logout are not a universal
revocation bridge.

## Reproduction and limits

Provide already-built Asterius and checksum-verified official product binaries,
Docker, kind, kubectl, Python cryptography, Node and this repository's installed
Playwright/browser dependencies. The runner creates a unique kind v1.35.0 cluster
with its own kubeconfig, unique PostgreSQL databases and separate TLS processes.
It never modifies the current Kubernetes context or shared schema. Cleanup
removes only the cluster, databases, processes and private files that it created.
The product processes use their TLS development mode solely inside this fixture;
production servers require their ordinary initialized storage and TLS setup.

```bash
ASTERIUS_BIN=/path/to/verified/asterius \
ASTERIUS_ACCEPTANCE_DB_CONTAINER=controlled-postgres-container \
ASTERIUS_OPENBAO_BIN=/path/to/verified/bao \
ASTERIUS_VAULT_BIN=/path/to/verified/vault \
  ./scripts/vault-openbao-acceptance.sh > /private/acceptance.json
```

The report contains statuses, named versions and an Asterius binary digest. It
contains no auth codes, cookies, JWTs, client/product tokens, private keys or
secret values. Successful human authentication, least-privilege read/deny,
subject refusal, logout/revocation, real projected-JWT trust refusals and product
token expiry are separate recorded checks. A refused OIDC subject may produce
HTTP 500 in a named product version; the fixture checks that no authority is
returned and preserves that exact status rather than calling it HTTP 403.
The credential-bearing discovery/bootstrap errors stay in private temporary
logs that cleanup removes. General OIDC/JWT compatibility, group policies,
TokenReview, cloud IAM trust and dynamic-secret leases remain outside the tested
profile.
