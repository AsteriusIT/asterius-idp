# Kubernetes human-access interoperability

The approved [human-access contract](../adr/kubernetes-human-access.md) uses one
confidential OIDC client per cluster, ES256 ID tokens, explicit managed-group
release and native Kubernetes offline JWT validation. The broker implements PAR,
S256 PKCE, private_key_jwt and DPoP; kubectl receives only an ID token through a
v1 ExecCredential. Other signing algorithms are outside this onboarding profile.

Run the controlled integration with Docker, kind 0.31, kubectl, PostgreSQL, Node
24.4 or newer, psql, OpenSSL, Python 3 and ripgrep installed:

```sh
DATABASE_URL=postgres://asterius:asterius@127.0.0.1:5433/asterius \
ASTERIUS_BIN=/absolute/path/to/asterius ./scripts/kubernetes-e2e.sh
```

The supplied binary must embed the current console. CI builds that console and
the real server, then runs this same launcher. No Rust unit-test substitute or
mock OP serves the integration. The job creates a fresh `ast_dd1y14_*` database,
a named `asterius-dd1y14` kind cluster with Kubernetes v1.35.0, and two dedicated
containers. It refuses existing resources and occupied ports 9447/9449 rather
than modifying another deployment. Every kubectl command uses its explicit
fixture kubeconfig. Cleanup drops only the newly created database and resources.
`KUBE_E2E_KEEP_CLUSTER=1` transfers cleanup responsibility to the caller and prints
the admin kubeconfig for an explicit subsequent test lease.

The fixture uses a one-day self-signed TLS CA, open dynamic registration and
known browser-test credentials. These choices are confined to the disposable
server. Browser certificate-error bypass is confined to Chromium; OP requests,
helper ID-token/JWKS verification and Kubernetes issuer discovery verify the
fixture CA. A localhost issuer proxy runs inside the owned kind node's network
namespace, avoiding changes to its advertised issuer or any existing cluster.

The browser performs an actual WebAuthn ceremony through Chromium's virtual
CTAP2 resident authenticator. The helper executes inside a pinned Node 24.4 Linux
container with real libsecret and a GNOME Secret Service unlocked through stdin;
subsequent separate kubectl processes reuse its OS credential. No fixture adapter
stands in for credential storage. This exercises the supported Linux store;
unsupported or unavailable OS stores retain only memory and require a new browser
login in subsequent processes.

The runner checks namespace view access, rejected writes and secret reads,
separate real Asterius client and issuer tokens rejected by the API server, stable
and explicitly migrated refresh credentials, signing-key rotation through the
actual admin console, group changes, disabled accounts, logout and signed JWT
expiry. It changes the broker's cached-refresh margin to request a genuine early
OP refresh; it never edits a JWT, advances a clock or replaces its signed expiry.
Raw fixture policy writes wait for the actual 30-second tenant snapshot cache.
The local hardening `tenant.refresh.bind_to_dpop_key=true` is explicit; it does
not change Asterius's confidential-client default or existing FAPI registrations.

Refresh must re-read account eligibility before minting tokens or rotating the
refresh credential. Disabled, locked and missing users fail closed; storage
errors cannot cause issuance. The focused Rust regressions exercise disabled and
locked users in stable and migration modes, including low-level restoration
without consuming the refused refresh credential. Administrative deprovisioning
may additionally revoke sessions/grants permanently; this fixture status change
isolates the eligibility check instead of asserting that revocation is reversible.

Local helper logout deletes the OS handle, invalidates broker state and requests
real OP refresh-grant revocation. Native Kubernetes validation does not consult
those stores: an already issued JWT remains accepted until its actual `exp`.
Group removal likewise affects newly refreshed identity, rather than recalling
an existing JWT. The five-minute issuance bound limits these offline windows.
The runner waits for real signed expiry and records observed refresh-denial and
native-denial latencies in redacted JSON. This is measured evidence, not an
instantaneous revocation guarantee; operators needing online enforcement must
use the separately designed online authentication path.

The browser run also guards a web interoperability detail: the broker sends
`Referrer-Policy: strict-origin`. The WHATWG Fetch
[Origin-header algorithm](https://fetch.spec.whatwg.org/#append-a-request-origin-header)
sets a form POST's Origin to `null` under `no-referrer`, which would conflict with
strict same-origin confirmation. `strict-origin` preserves the secure origin
without disclosing rendezvous paths or queries. Origin validation remains strict.

CI publishes only `artifacts/kubernetes-e2e.json`; no JWTs, refresh tokens,
credential-store contents, client keys or admin kubeconfigs are artifacts.
