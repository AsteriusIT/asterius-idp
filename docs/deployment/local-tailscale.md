# Local deployment and private remote access

The validated local deployment is available to computers connected to the same
tailnet at:

- Account: <https://desktop-cpbptqn-1.tailacbb15.ts.net/t/admin/account>
- Console: <https://desktop-cpbptqn-1.tailacbb15.ts.net/t/admin/admin/>

This uses private Tailscale Serve on port 443. Funnel is disabled. Existing Serve
routes on 8443 and 8444 remain unchanged. Tailnet access does not confer an
Asterius role: the existing admin password and TOTP challenge still apply.

## Verified deployment

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
