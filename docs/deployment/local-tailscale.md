# Local deployment and private remote access

The validated local deployment is available to computers connected to the same
tailnet at:

- Account: <https://desktop-cpbptqn-1.tailacbb15.ts.net/t/admin/account>
- Console: <https://desktop-cpbptqn-1.tailacbb15.ts.net/t/admin/admin/>

This uses private Tailscale Serve on port 443. Funnel is disabled. Existing Serve
routes on 8443 and 8444 remain unchanged. Tailnet access does not confer an
Asterius role: the existing admin password and TOTP challenge still apply.

The user bridge is enabled and active, and `Linger=yes` is configured for
`qrodic` so the user service can remain active after the last session logs out.
The applied local command was `loginctl --no-ask-password enable-linger qrodic`.
This does not keep a powered-off host or stopped WSL VM online: the host,
Docker/Kubernetes and Tailscale must remain running. HTTPS readiness passed
after the change; logout/reboot itself was not exercised. See
[the persistence check](evidence/local-tailscale-persistence-2026-10-03.json).


## Current verified deployment

The latest 2026-10-03 image includes the exact session-rotation correction from
local main `ccd98d6e`, alongside governance findings, access reviews and temporary
privileges. It uses binary SHA-256
`bf8fc000e345a4428f25c8fa13703e383189c96b56adc7120252ffbca9b4b03d`,
image `asterius-idp:local-ast-96u1-bf8fc000e345`, and image ID
`sha256:cd6ea8fdb62680da0995a8e980bd9e07b4d51a5deb75cac3bded27b00f1122e7`.
The rotation change passed composed strict linting, 92 targeted tests, 115
composed fuzz parser builds, owned full-schema SQL controls and a real controlled
rotation/refresh path before its local main merge. This main binary was rebuilt
successfully, then tested in the restricted runtime image against a restored
local database. The new optional protocol candidates remain isolated.

The fresh protected recovery snapshot is
`~/.local/share/asterius/backups/ast-96u1-20261003T213751Z-5ab867ed`
(directory 0700, files 0600). Both isolated restore and live upgrade preserved
exact account, credential and encrypted TOTP rows. Both databases have 111
successful migrations, including 0170 for private grant/session lineage.
Configuration and secret data, security contexts, durable loopback bridge and
private Serve routes are unchanged. The live deployment is ready; strict TLS
readiness, canonical discovery and protected account/console redirects pass.
No fresh successful TOTP ceremony is claimed by this deployment check.
The prior image and snapshots remain available; image-only downgrade is
unvalidated. See [the session update evidence](evidence/local-session-rotation-update-2026-10-03.json).

## Previous governance report update

The earlier 2026-10-03 image added the read-only **Governance findings** screen
in addition to temporary privileges, access reviews and the deadline correction.
It uses local main `4066e08f`, verified binary SHA-256
`c79b1caedc1ce9ff655b7d2c2adbc1498f26c7a501a50a4d66b3fe3b957c5cbd`,
and image `asterius-idp:local-ast-496l-c79b1caedc1c`, running image ID
`sha256:9d87b09c6657558a09d5f685d698676356b7eaeab612400a54851934109edb2c`.
The composed runtime passed 73 targeted tests, 113 fuzz targets and 18 real
HTTPS/browser controls before rollout. No Rust rebuild was performed.

A fresh private recovery snapshot is retained at
`~/.local/share/asterius/backups/ast-496l-20261003T191746Z-201a6c4f`
(directory 0700, files 0600). The isolated restricted-image restore and live
update preserved the exact account, credential and encrypted TOTP rows.
Both databases retain 110 successful migrations; this report update applied
no new migration. Configuration, secrets, security contexts, the loopback bridge
and private Serve routes remain unchanged. The live pod is ready and matches
the validated image ID. Strict HTTPS readiness, canonical discovery and protected
account/console redirects passed; the report rejects anonymous access with 401.
The preceding corrected image and earlier recovery snapshots are retained.
See [the governance report deployment evidence](evidence/local-governance-update-2026-10-03.json).

After signing in, open **Governance findings** under **People** in the console.
The report supplies evidence for review and performs no automatic cleanup.

## Previous privilege and review update

The follow-up 2026-10-03 update uses the corrected binary composed in local main
`94835e14`, SHA-256
`b5196af3f01c2b6b3762f6fbc03e2d55eeecaaa5abf40603a6fa93071b09d777`,
in `asterius-idp:local-ast-hb5b-b5196af3f01c`, image ID
`sha256:5c83731d00ad570a383117fddf422c6472de01743e07b14c8a57d0b1b07c7c39`.
This includes temporary privileges, standing-access reviews and the corrected
final checks of temporary authority deadlines. Before rollout, the composed
runtime passed 182 targeted tests, 112 fuzz targets and ten real HTTPS/browser
verification groups. The binary was reused without another Rust build.

A fresh private backup of the current database, canonical configuration, secrets,
deployment and Serve state is retained in
`~/.local/share/asterius/backups/ast-hb5b-20261003T183648Z-13b6d59f`.
The isolated restored database and restricted image passed readiness, both tenant
discovery documents and protected account/console redirects. Migrations 0163 and
0165 were applied, bringing both isolated and live databases to 110 successful
migrations. Exact account, password-credential and encrypted TOTP rows remained
identical to the pre-upgrade snapshot. Current configuration, secret values,
Kubernetes security contexts and all three private Serve routes are unchanged.

The live deployment has one ready replica. HTTPS certificate verification passed
for readiness, both canonical discovery documents and account/console redirects.
The previous validated 8.4 image remains available with the private backups;
image-only rollback after these migrations is not a validated recovery procedure.
The user's TOTP challenge was not completed by the agent.
See [the follow-up deployment evidence](evidence/local-update-2026-10-03.json).

## Previous verified deployment

The 2026-10-03 update uses the previously verified binary from `de43918a`, SHA-256
`7207b3b84d1e1b5b090cb57b036a38688ff6c2d0194acbea4810d60a8da78b92`, in local
image `asterius-idp:local-ast-h6fx-7207b3b84d1e`. The release Dockerfile remains
unchanged. This local GNU binary uses the pinned non-root distroless C++ Debian
13 runtime, with no shell or package manager. No Rust compilation was repeated.
The image was started against an isolated restored database with a read-only
filesystem, all capabilities dropped and privilege escalation disabled before
being loaded into the existing `asterius-local` kind cluster.

Before the rollout, private PostgreSQL custom and plain dumps and configuration,
deployment, secret and Serve snapshots were stored under
`/tmp/asterius-ast-h6fx-private`, directory mode 0700 and sensitive files 0600.
The custom dump was 395,597 bytes. PostgreSQL 18.4 data was restored to an owned
PostgreSQL 16 database using the plain dump, omitting only the unsupported
`SET transaction_timeout = 0` statement. The new binary successfully applied
the previously missing migration 0162, reaching 108 successful migrations.
Readiness and discovery passed before the live update.

The deployment remains non-root and read-only with its existing Kubernetes
security context. Exact comparisons confirm that the two account identities,
two password credentials and existing encrypted TOTP row were preserved.
There were no enrolled passkeys. Real Chromium, with certificate verification
enabled, reached the existing TOTP challenge after submitting the current admin
password. It received no failed HTTP responses. Completing the user's TOTP
challenge was not part of this check.

Public evidence is recorded in
[local-tailscale-2026-10-03.json](evidence/local-tailscale-2026-10-03.json).
Private dumps, passwords, cookies and request interaction identifiers are not
included in repository evidence.

## Canonical issuer and TLS bridge

Both tenant issuers now use `https://desktop-cpbptqn-1.tailacbb15.ts.net/t/{tenant}`.
Existing audience identifiers were preserved independently of the issuer.
Account and console redirects resolve to that HTTPS hostname and their cookies
remain Secure. The existing Grafana client's registered callback was preserved;
its consumer configuration must use the new canonical issuer before a new OIDC
login. Previously issued tokens still carry their original issuer. This is an
issuer migration, and consumers must not treat those two issuer identifiers as
interchangeable.

`scripts/local-tailscale-bridge.py` listens only on `127.0.0.1:9475`. Tailscale
terminates trusted external HTTPS and proxies to that listener. The bridge opens
a second TLS connection to the existing local ingress, verifies its private CA
and `auth.asterius.local` certificate identity, and sends the canonical HTTP Host
to the separately added `asterius-tailscale` ingress rule. It strips incoming
forwarded, Tailscale identity and client-certificate headers. Authentication
remains the application's responsibility. This route does not forward a remote
client's mTLS certificate; DPoP headers remain intact. Request bodies are bounded
to 2 MiB and buffered responses to 64 MiB for this development route.

The bridge is managed by the user service
`asterius-tailscale-bridge.service`; its script and public ingress CA are stored
in `~/.local/share/asterius/ast-h6fx`, independent of agent worktree cleanup.
Tailscale automatically obtains the external HTTPS certificate. See the official
[Serve reference](https://tailscale.com/docs/reference/tailscale-cli/serve) and
[distroless runtime documentation](https://github.com/GoogleContainerTools/distroless/blob/main/cc/README.md).

The old `auth.asterius.local` ingress object is retained for rollback. It is not
an alias for the new canonical issuer. WebAuthn derives its RP ID from the issuer
hostname; a credential enrolled for `auth.asterius.local` cannot authenticate on
the unrelated `ts.net` hostname. Existing passkey records must never be rewritten
to pretend otherwise. New passkeys can be enrolled after an ordinary authenticated
login on the canonical hostname. Existing passwords and TOTP remain usable.

## Preparing a later verified local update

`scripts/local-verified-upgrade-probe.py` takes an independently validated binary,
its exact SHA-256 and source commit. It captures fresh current database,
configuration, deployment, secret and Serve backups in a new private directory,
builds the same pinned runtime image, and restores into a nonce database.
The restricted image must become ready, preserve the exact account, credential
and TOTP rows, serve both canonical discovery documents and return canonical
protected account/console redirects. It also checks the expected migration count
and the required temporary-entitlement/access-review migrations 0163 and 0165.
The probe removes only its own container and database and seals retained backup
files to 0600. It performs no live rollout or Serve change.

The original `ast-h6fx` snapshots contain the issuer configuration from before
the tailnet migration. A subsequent rollout must retain its own fresh snapshots
of the current canonical configuration rather than substitute those older files.
Use only a corrected binary whose real runtime acceptance has completed before
loading and selecting the candidate image in the shared cluster.

## Recovery

The old image and private snapshots are retained. Durable backup copies are also
stored in `~/.local/share/asterius/backups/ast-h6fx` with directory mode 0700 and
file mode 0600; the temporary staging directory is not the only recovery copy.
An actual probe of the old
image against the upgraded isolated database did not become ready, so **changing
the image alone is not a validated rollback**. A full rollback requires stopping
the application, restoring the private database backup into a clean database,
restoring the saved configuration and deployment image, and checking readiness
before accepting traffic. Restore secrets only if their values changed; this
update did not rotate them. Backups contain credentials and must remain private.
Restoring a database loses changes made since the backup and requires an explicit
recovery decision.

To remove only this private route while retaining the unrelated Serve routes:

```sh
tailscale serve --https=443 off
systemctl --user disable --now asterius-tailscale-bridge.service
kubectl --context kind-asterius-local -n asterius delete ingress asterius-tailscale
```

Do not run `tailscale serve reset`: it would also remove the existing 8443 and
8444 routes. Do not delete the shared kind cluster, PostgreSQL PVC, secrets or
other applications. The disposable restore database was removed after validation;
the private recovery backup remains outside git.
