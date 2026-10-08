# Use the local Asterius playground

Open <https://desktop-cpbptqn-1.tailacbb15.ts.net:8446/> from a browser connected to the private tailnet. The portal links to two SSO applications, a financial example and the protocol lab. These applications use the existing **demo** tenant at `https://desktop-cpbptqn-1.tailacbb15.ts.net/t/demo` and run in the separate Kubernetes namespace **asterius-playground**. The identity provider remains in **asterius**.

The six workloads are deployed, healthy and connected to four verified registrations and two dedicated resource audiences. This document describes how to exercise them; it does not substitute for recorded rollout or human sign-in evidence. Existing accounts and credentials are preserved. Sample transfers never contact a bank.

## Create your disposable sign-in

Open the [setup page](https://desktop-cpbptqn-1.tailacbb15.ts.net/playground/setup/). The four application registrations are already complete. Sign in through its **administrator console** link, return and reload, then use **Create a disposable demo user**. Choose a unique `tour-*` username and its password. This uses the supported admin API to create an ordinary user in `demo`; it neither resets an existing account nor grants an administrator role. Passwords go directly from your browser to Asterius and are not kept in browser storage or copied to the applications. Save your chosen password privately.

Use that account for all application and protocol exercises. Your deployment administrator belongs to tenant `admin`, so it is not automatically a demo application's user. Enroll passkeys/TOTP on the disposable account only for those exercises. Disable the account and withdraw its grants when finished.

## Start with the browser applications

Keep the [demo console](https://desktop-cpbptqn-1.tailacbb15.ts.net/t/demo/admin/) open in one tab. Use a disposable account or a separate browser profile for changes that could end a session or withdraw a grant. A successful application login is stronger evidence than a healthy page or decoded JWT; inspect the resulting application state.

| Exercise | Action | Expected result and failure check | Finish |
| --- | --- | --- | --- |
| SSO between applications | Open `/demo-a/`, sign in, then open `/demo-b/` in the same browser and choose its sign-in action. | The second app can reuse the IdP session if its policy permits. Consent can still be required. Each app has its own session; pairwise subjects can differ. Compare displayed claims and the console's actual sessions/grants. | Use each app's revoke/logout control. Do not infer global logout merely from one local session ending. |
| Refresh and session state | In a signed-in SSO app, use **Refresh tokens** and **Check IdP session**. End its disposable session/grant through the console, then repeat the online check. | Valid current authority succeeds; a withdrawn grant or ended IdP session is reported by the relevant online check. Refresh must not silently broaden scope. | Revoke any remaining disposable grant. Offline JWT validation remains bounded by expiry. |
| Fresh authentication | In the SSO app use **Force reauthentication**. | The IdP follows the application's fresh-login request instead of treating a preexisting session as sufficient. | Sign out afterward. Do not publish the displayed user claims. |
| Passkey step-up | Use **Require passkey step-up** with a disposable enrolled user and attainable tenant assurance class. | Actual user-verified authenticator evidence satisfies the selected requirement. A missing credential or unattainable class must not be displayed as success. | Requires a passkey/browser fixture and appropriate policy; preserve another sign-in method. |
| Financial sign-in and protected read | Open `/financial/`, visit Accounts while signed out, then sign in and load accounts. | Signed-out state requests login. Authorized state displays the sample checking/savings accounts. An unauthenticated call to `/financial-api/api/accounts` must refuse protected data. | Sign out of the financial application. |
| Financial write | Submit a small valid sample transfer; then try an invalid amount or target through the application's supported inputs. | A permitted transfer changes the example ledger and returns its result. Rejected input leaves balances unchanged. This tests the sample service's implemented authorization; it is not evidence of an AuthZEN policy integration. | The ledger is in memory and resets when the API restarts. No real payment is made. |
| Protocol journeys | Open `/protocols/` and start device authorization or CIBA with a disposable login hint. Follow the device link or My account approvals; poll at the displayed interval, inspect UserInfo/introspection, revoke, then introspect again. | Inspect the actual successful or refused result. Approval is not inferred from reading a request. Device/CIBA expiry and polling behavior follow the configured protocol. | Use provided cleanup/revocation controls; let uncompleted short-lived requests expire. Clear forgets local lab state. Machine grants and token exchange are not implemented in this lab. |
| Trace an outcome | Open Users, Sessions, Connected apps and Audit trail in the demo console. Follow the application's actual user/client or displayed support reference. | A retained event reflects the real operation; a hypothetical simulation does not become a historical decision. Permission limits and diagnostic expiry remain visible. | Keep a sanitized scenario record; never copy cookies, assertions, tokens or private keys into a ticket. |

For the larger console/API inventory, follow the [98-scenario local feature tour](local-feature-tour.md). The playground supports the exercises above; it does not implement a browser control for every feature in that inventory.

## Try a namespace-scoped Kubernetes permission

The manifests include a `practice-resource` ConfigMap, a `playground-reader` ServiceAccount and a namespaced RoleBinding. The reader may get/list/watch Pods, Services and ConfigMaps in `asterius-playground`. It cannot write them or read Secrets. Applications use a separate `playground-app` ServiceAccount with automatic API-token mounting disabled.

An operator with permission to impersonate that ServiceAccount can perform these authorization checks without minting or printing a bearer token:

```sh
kubectl --context kind-asterius-local auth can-i get configmaps \
  --namespace asterius-playground \
  --as system:serviceaccount:asterius-playground:playground-reader
kubectl --context kind-asterius-local get configmap practice-resource \
  --namespace asterius-playground \
  --as system:serviceaccount:asterius-playground:playground-reader
kubectl --context kind-asterius-local auth can-i update configmaps \
  --namespace asterius-playground \
  --as system:serviceaccount:asterius-playground:playground-reader
kubectl --context kind-asterius-local auth can-i get secrets \
  --namespace asterius-playground \
  --as system:serviceaccount:asterius-playground:playground-reader
kubectl --context kind-asterius-local auth can-i get configmaps \
  --namespace asterius \
  --as system:serviceaccount:asterius-playground:playground-reader
```

Expected answers are **yes**, a successful fixture read, then **no**, **no**, **no**. These checks validate the ServiceAccount's namespace RBAC; they do not claim that a human OIDC `kubectl` login or online identity broker has been exercised. Follow [human Kubernetes access](../kubernetes-human-access.md) for that separate integration.

## Deployment evidence

[Recorded local verification](../deployment/evidence/local-playground-2026-10-08.json) records readiness, image identities, registration ownership, live PAR/device/CIBA requests, protected-resource refusals and namespace permission checks. The user completed the supported registration setup and created a disposable account. Human application sign-in, approval and sample-transfer completion are user exercises; healthy deployment alone does not claim they passed.

## Deployment contract

The operator owns builds, registration, private Secret creation, rollout and the HTTPS bridge. The reproducible source is `deploy/playground`. `prepare.py` generates four private keys plus a public setup plan in an explicit private operator directory. After the images have been built and loaded into kind, `install.py --stage` applies the portal/setup and keeps unregistered OAuth applications at zero replicas. The human administrator applies the reviewed plan through the setup page. `install.py` then verifies the public registrations by read-only lookup, checks that owned existing Secrets are identical, creates missing owned Secrets and applies all six workloads. It performs no SQL writes and refuses to overwrite foreign resources or differing keys.

For this deployment the private operator directory is `~/.local/share/asterius/playground-20261008`; it contains no committed source. A fresh plan deliberately requires another directory, so it cannot silently replace existing private keys. The owned persistent bridge is `asterius-playground-bridge.service` in the user's systemd configuration.

Render the checked-in manifests before applying:

```sh
kubectl kustomize deploy/playground
```

The six Deployments have one replica each, `Recreate` strategy and small CPU/memory requests. Node applications hold sessions/sample data in memory, so a restart ends local app sessions and resets the sample ledger. The namespace quota bounds the playground, rather than granting permission to modify the identity provider. Containers run as nonroot with no privilege escalation, dropped capabilities, read-only root filesystems and default seccomp. The nginx services use bounded writable `/tmp` volumes. There are no persistent volumes.

| Service | Image | Internal port / readiness | Public path |
| --- | --- | --- | --- |
| `gateway` | `asterius-playground-gateway:20261008` | 8080, `/healthz` | `/` and route proxy |
| `demo-a` | `asterius-playground-sso:ast-qzw6-20261008` | 8080, `/demo-a/healthz` | `/demo-a/` |
| `demo-b` | `asterius-playground-sso:ast-qzw6-20261008` | 8080, `/demo-b/healthz` | `/demo-b/` |
| `financial-web` | `asterius-playground-web:20261008` | 8080, `/financial/` | `/financial/` |
| `financial-api` | `asterius-playground-api:20261008` | 4000, `/health` | `/financial-api/` with prefix stripped upstream |
| `protocol-lab` | `asterius-playground-protocols:20261008` | 8080, `/health` | `/protocols/` with prefix stripped upstream |

Each Service exposes port 80. The gateway is a ClusterIP Service, not a public NodePort. An owned persistent loopback port-forward such as `127.0.0.1:18086 → gateway:80`, followed by private Tailscale Serve on HTTPS 8446, supplies the public origin. Preserve existing Serve routes on 443/8443/8444/8445. Do not use Funnel or bind the bridge to all host interfaces merely to make an application reachable.

Browser cookies are scoped to a host, not a port. The playground therefore uses distinct app cookie names and paths, and its gateway forwards only each app's own session/login cookies. IdP administrator cookies and the existing financial-demo cookies are not passed to these BFFs.

After a rollout, run `python3 deploy/playground/verify-live.py`. It checks the deployed cookie names, completed app rollouts, actual login handoff cookies and the protocol page's `same-origin` referrer policy. It requires no user credentials and prints no cookie values. The browser form regression is `node scripts/testing/playground-form-origin-browser.mjs`; strict Origin and CSRF checks remain enabled.

After an application restart, start sign-in again from its home page: pending login state is held in memory, so an old callback cannot finish. An IdP interaction page also requires its browser cookie; a copied interaction URL alone cannot resume sign-in. Report a fresh displayed support reference if a new journey fails, without sharing callback URLs or cookies.

Application returns use the trailing-slash home URL directly. Gateway slash redirects are relative and carry `Cache-Control: no-store`, preserving the public HTTPS port and avoiding new cached internal-port redirects. If an older browser cache still sends `/demo-a` to port 8080, open `/demo-a/` at port 8446 directly. Refresh and session checks return home with a visible operation result; reauthentication and passkey requests show their completed or refused result after the IdP callback.

The IdP's internal origin is `http://asterius.asterius.svc.cluster.local:9443/t/demo`. Client requests retain the canonical public issuer and expected protocol audience while using the internal connection path. Do not enable permissive TLS verification, rewrite the token issuer or use the internal service URL as the issuer in a registration.

### Registration and Secret references

Register distinct clients using guarded tenant administration, with public ES256 JWKS and the selected code/PAR/PKCE/DPoP and other grant metadata. Dynamic registration is not assumed open. Register these exact browser callbacks:

- `https://desktop-cpbptqn-1.tailacbb15.ts.net:8446/demo-a/callback`
- `https://desktop-cpbptqn-1.tailacbb15.ts.net:8446/demo-b/callback`
- `https://desktop-cpbptqn-1.tailacbb15.ts.net:8446/financial-api/auth/callback`

The financial resource audience is `https://desktop-cpbptqn-1.tailacbb15.ts.net:8446/financial-api`, with `accounts:read` and `accounts:write` as selected by its registration. Protocol-lab registration must match its actual implemented grants, callbacks and resource requests; inspect that application before registration rather than reusing another client's identity.

Create the owned Secrets `demo-a-oidc`, `demo-b-oidc`, `financial-api-oidc` and `protocol-lab-oidc` outside Git. Each needs public keys `CLIENT_ID` and `CLIENT_KEY_ID`, and a private JSON JWK under `CLIENT_PRIVATE_KEY_JWK`. The manifest exposes only the public values as environment variables and mounts the private JWK at `/run/oidc/CLIENT_PRIVATE_KEY_JWK`, read-only mode 0440 with the application group 1000. Node applications receive `CLIENT_PRIVATE_KEY_JWK_FILE` pointing there. Never include Secret YAML, plaintext private keys, access tokens or cookies in committed manifests or deployment evidence.

The `playground-connection` ConfigMap has only public issuer/internal-connection/origin values. Kustomize generates ConfigMaps for gateway routing and the static portal. The installer generates a separate setup ConfigMap containing only the public plan and browser administration code. The namespace-owned setup Ingress mounts `/playground/setup` on the canonical HTTPS443 host; the application portal uses private HTTPS8446. Applications do not call the Kubernetes API and receive no mounted ServiceAccount token. The manifests do not add a NetworkPolicy: namespace placement alone is not a network isolation claim. Select a supported network-policy implementation before adding an enforced egress policy.

## Fixtures that remain separate

The deployed IdP enables CIBA, device flow, grant management, token exchange, SSF, request objects and DPoP nonce globally. Actual clients still need permitted metadata/resources and applicable tenant/policy configuration. The playground's DPoP clients must respond to a server nonce challenge with a fresh proof.

OIDC upstream providers, SSF peers, SCIM receivers, SAML SPs, LDAPS, federation anchors, external workload issuers, claims providers and wallets need separately owned fixtures and explicit trust. Earlier temporary protocol peers were removed. Mail currently uses a local journal: an authorized operator retrieves only the disposable user's private invitation/verification/recovery links; SMTP inbox delivery is not implied. Passkey/TOTP exercises need an authenticator. IPSIE and Message Signing need selected clients and their specific profile setup. mTLS, AuthZEN and self-registration remain disabled until separately configured.

Full native Entra user/group provisioning remains a future separately scoped cloud exercise. The playground does not start a provisioning job or create source identities. A successful credentials check is not full lifecycle proof.

## Cleanup

For a normal exercise, sign out of the applications, withdraw disposable grants and end the disposable user's sessions. Remove only test assignments, groups or policies you created, and retain the operator's recovery access.

For playground removal, the operator first stops its owned loopback bridge and removes only the private Serve 8446 route, then revokes/deprovisions the four owned client registrations and exact resource assignment through supported administration. Remove only the `asterius-playground` namespace and owned build/fixture material after confirming no other user has added resources there. Never delete namespace `asterius`, its persistent database, existing user credentials, audit history or unrelated Tailscale services. Record an unresolved remote or registration cleanup rather than reporting a rollback that did not happen.
