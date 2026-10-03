# Kubernetes confidential login broker and exec helper

This operator-run relying party implements the approved
[Kubernetes contract](../../docs/adr/kubernetes-human-access.md), separately from
Asterius's identity service. It needs Node **24.4.0 or newer** and the pinned
`jose` dependency (`npm ci --ignore-scripts`). Node 24.4 reports its SQLite API
as experimental; the CI job pins and checks this minimum version. SQLite stores broker rendezvous
state only; Asterius identity and authorization remain in its PostgreSQL store.
No Kubernetes deployment is performed by these tools.

## Register and run the broker

Create one OIDC confidential web client for each tenant/cluster in the existing
client administration UI. The tenant must explicitly allow OIDC compatibility.
Choose `private_key_jwt`, ES256 ID tokens, DPoP, authorization code + refresh,
`openid` and `offline_access`, and the profile's explicit managed-group release.
Publish the **public** half of a distinct P-256 client-authentication key in that
client's registered JWKS. Keep its private half only at the broker. Provision a
matching ES256 tenant signing key. FAPI clients/defaults are unchanged.

Set the sole exact redirect URI to:

```text
https://kube-login.example.com/callback/cluster-a
```

Set its back-channel logout URI to:

```text
https://kube-login.example.com/backchannel/cluster-a
```

Enable the client's back-channel session support. Without this registration,
OP browser logout cannot immediately invalidate the broker's handles; refresh
still checks the OP grant and Kubernetes JWT expiry remains bounded to five
minutes. Download and review the cluster authentication/RBAC configuration from
the Kubernetes profile panel before configuring your cluster.

Fill `broker.example.json` from the operator's secret store, including a random
32-byte AES storage key encoded as base64. Protect the actual broker config with
mode `0600`, owned by its service account. Use a dedicated `0700` directory on
local persistent storage for the database. Storage-key changes require deleting
sessions and reauthentication; never reuse a key across broker deployments.
Backups must protect both ciphertext and the independently stored key.

```sh
node tools/kubernetes-login/src/broker-main.mjs /etc/asterius/kube-broker.json
```

The listener binds only `127.0.0.1`. Put a trusted HTTPS reverse proxy in front
of it, preserving the exact external `Host` and browser `Origin`. Never expose
the plaintext listener or disable certificate validation. Proxy access logs
must exclude callback query strings, form bodies, proof headers and cookies.
The broker itself never logs protocol bodies/credentials. Keep the reverse
proxy on this host, set bounded request rates and body sizes, and restrict
network egress to the configured issuers. Discovery pins exact issuer and
same-origin HTTPS endpoints; the helper never supplies an issuer or callback.

Run **one process per database**; the broker acquires an exclusive `.lock` file.
After an unclean stop, verify the previous service is stopped, then remove its
stale `.lock` before restarting. Interrupted code exchanges and refreshes are
invalidated on startup rather than replayed. Horizontal replication is not
supported. Do not copy a live SQLite database or mount it over a network FS.
Per-session compare-and-swap plus an in-process shared promise serializes
refresh; concurrent callers receive the same newly verified identity.

## Install and invoke the helper

Install the package/launchers in an operator-controlled path. Review
`helper.example.json`, replace all placeholders with that cluster's actual
issuer, client ID, public JWKS URI and Kubernetes API server, and protect it
against group/world writes. When using a private cluster CA, add
`certificateAuthorityData` with that CA's base64 PEM; it must match the cluster
information kubectl supplies. Node and Kubernetes must independently trust the
issuer/broker CA; configure Node's `NODE_EXTRA_CA_CERTS` at launch for a private
CA instead of disabling TLS verification. Helper configuration contains no
private key, token or client-authentication credential.

```sh
node tools/kubernetes-login/src/helper.mjs kubeconfig \
  --config /etc/asterius/kube-helper.json --cluster cluster-a --account alice \
  > /path/to/reviewed-kubeconfig.json
kubectl --kubeconfig /path/to/reviewed-kubeconfig.json get pods
node tools/kubernetes-login/src/helper.mjs logout \
  --config /etc/asterius/kube-helper.json --cluster cluster-a --account alice
```

The generated JSON is valid kubeconfig YAML and invokes the executable helper
by absolute path, with `provideClusterInfo=true`, v1 ExecCredential and
`interactiveMode=IfAvailable`. It contains only public pins and invocation
arguments. The helper verifies API server/CA pins on every exec invocation.
Treat all kubeconfig exec stanzas as executable configuration.

On Linux, install `/usr/bin/secret-tool` and use an unlocked desktop Secret
Service. The helper stores only a broker handle and its own P-256 proof key,
partitioned by broker/issuer/client/cluster/API-server/account alias. Secrets
reach `secret-tool store` on stdin, never argv. A native keychain adapter for
macOS/Windows is not provided: those platforms and an unavailable/locked Linux
store use **memory only**, show that fact on stderr and require browser login
on the next invocation. There is no plaintext cache. A noninteractive exec
without a usable stored session exits `login_required_run_interactively`.

The account flag is a local credential-store partition, not an OAuth account
selector. Browser confirmation displays the stable account subject, cluster
and terminal reference. An optional `subject` in helper config further pins
an expected OP subject. Login opens the external browser; users can copy the
printed reference URL to another trusted device. Asterius performs its existing
browser/passkey authentication. Explicit approval is required after callback;
this custom rendezvous is not RFC 8628 device authorization.

Only ExecCredential JSON containing the **ID token** goes to stdout. Diagnostics
and the nonsecret confirmation reference URL go to stderr. The helper receives
neither OAuth access/refresh tokens nor confidential client keys. The broker
checks ES256 signature, issuer, single exact audience, subject, nonce, lifetime,
optional `azp`/`at_hash`, current bounded managed `group:<UUID>` identities and
refresh identity. UUID selection in the admin profile is rendered as the existing
typed `group:<UUID>` claim; bare UUID/name claims are not accepted.
The helper independently verifies the ID token against pinned public JWKS.

## Failure, refresh and logout behavior

Transactions expire in five minutes; delivery and callback are single-use.
Polling requires both the helper proof key and an independent random secret,
which is absent from the browser URL. Signed requests bind method, URL and
entire JSON body and use persisted one-use `jti` values. `SIGINT`/`SIGTERM` cancel
pending login; cancellation also attempts to invalidate its broker transaction.
A browser rejection cancels the transaction and attempts grant revocation.
If confirmation takes too long for the ID token, start a new login.

Handles have an eight-hour absolute expiry and a fifteen-minute idle limit.
Within the token's validity margin of thirty seconds the broker can return its
current verified ID token. Refresh checks current OP policy/groups; it never
reuses a cached group set for a newly issued token. It accepts the OP's refresh
policy: the default returns the same sender-bound refresh token, while an
explicit migration policy may rotate it. There is no assumed forced rotation.
An explicit `use_dpop_nonce` rejection is the only retried OAuth POST. Network
failure or malformed refresh invalidates the broker handle and requires fresh
browser login; an ambiguous rotation is never blindly replayed.

Parallel calls on an existing handle share one refresh. Two first-time helper
processes can create independent browser transactions; the last secure-store
write becomes that account partition's session and any other handle expires by
its idle limit. Failed result delivery requires login again. No credential
store update is needed during ordinary refresh, because its handle/key are
stable. This avoids local refresh-token read/write races.

Logout first erases the local credential, then invalidates its broker session
and attempts OP refresh-grant revocation. A broker/network outage produces an
error after local erasure; server-side idle/absolute expiry remains a bound.
Revocation endpoint failure never restores a removed broker session. Browser
logout and configured signed OP back-channel notifications invalidate matching
sessions. For an OP logout received during authorization, all pending cluster
transactions are cancelled conservatively because their subject is not yet
known. In-flight refresh/callback completion cannot resurrect removed sessions.

A previously issued native Kubernetes bearer JWT remains usable until expiry.
Neither helper logout nor OP revocation promises instant native JWT revocation;
operator RoleBinding removal is a separate authorization control.

## API and verification

[openapi.json](openapi.json) specifies this external broker's API; it does not
add routes to the Asterius IdP OpenAPI. Browser pages require HttpOnly Secure
SameSite cookies and explicit same-origin confirmation. Every response is
`no-store`, with no-referrer, no-sniff and restrictive CSP headers.

```sh
cd tools/kubernetes-login
npm ci --ignore-scripts
npm run check
npm test
```

Focused Node tests run the real HTTP broker and helper against signed OP
fixtures, exercise private-key assertions/DPoP/PAR/PKCE, rejection, cancellation,
20-way refresh concurrency, logout races, encrypted durable state, replay and a
bounded malformed-parser mutation corpus. They do not consume Rust nextest
runs. Full Asterius/browser/passkey/Kubernetes deployment verification belongs
to ast-dd1y.1.4; these tests do not claim a live-cluster deployment.

Protocol basis: [OIDC Core ID-token/refresh validation](https://openid.net/specs/openid-connect-core-1_0.html),
[DPoP nonce handling](https://www.rfc-editor.org/rfc/rfc9449.html),
[Kubernetes exec credentials](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins),
and [Node SQLite](https://nodejs.org/api/sqlite.html). The human-reviewed ADR
covers this implementation contract; a deployed integration remains separate
evidence.
