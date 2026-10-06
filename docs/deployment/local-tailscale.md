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


## Current worktree deployment

The 2026-10-06 Access reviews update runs from uncommitted `claude/ast-hl81`,
carrying the previous redesign. Five owned patterns adopt ReUI comparison and
selection ideas on the existing shadcn/Base foundation: ownership table with
column controls, in-flow selected-record count/clear action, sortable review
history with actual state badges, a 1,000-character decision-reason counter,
and keyboard snapshot evidence accordions that start expanded. Actual affected
accounts, standing/temporary-source counts and account state remain visible.
Refused apply operations also show their error inside the retained confirmation.
The existing bounded IDs, cursor paging, permissions, raw reasons, explicit
snapshot creation and separate decision/apply requests remain authoritative.

Production build/typecheck and 88 unit checks pass. All 74 controlled Chromium
scenarios passed in the full run; four review scenarios passed again against the
final bundle after correcting a scoped evidence-header badge layout. Coverage
includes column choices/loaded sorting, exact selection IDs on refused creation,
disabled ownership records, clear selection with no write, read-only permissions,
actual review states, reason limits/raw rejected drafts, keyboard disclosure,
independent/protected evidence, retained apply confirmation, mobile/dark/WCAG/CSP.
Screenshots were reviewed. Registry source was inspected through the CLI; no
runtime dependencies or existing primitive overwrites were introduced.

Image `asterius-idp:local-ast-hl81-b57a71da9ab2` packages binary SHA-256
`b57a71da9ab2401039f9ff6b5d723c2c4d6d8b2971cd0871cb4be02faada8e48`.
Fresh private backup and isolated database restore passed before rollout. Live
canonical HTTPS readiness, discovery, protected redirects, all ten exact asset
hashes and identity/schema equality passed. Configuration, secrets and Tailscale
Serve remain unchanged. See [deployment evidence](evidence/local-access-review-components-2026-10-06.json).
Existing-account password/TOTP sign-in was not exercised. No Rust source changes,
commits, merges, pushes or remote CI.

## Previous empty/preferences/secret-input deployment

The 2026-10-06 component-adoption update runs from uncommitted `claude/ast-0c4o`,
carrying the previous redesign. Shared empty states use owned shadcn Empty
composition with accessible titles; filtered Users/Applications offer reset
actions. Preferences use owned Base ToggleGroup controls with keyboard selection
and existing browser persistence. SecretInput composes InputGroup/Input/Button
for initial user passwords and upstream OIDC secret replacement. Reveal is local,
remasks on blur, clearing or disabling, preserves exact raw drafts, and makes no
request. Blank replacement still omits the secret from the save command.

Production build/typecheck and 88 unit checks pass. All 70 unique controlled
Chromium scenarios pass against the final bundle: 68 passed in the full run and
two passed in a targeted rerun after correcting an ambiguous heading selector
and a missing fixture metadata-check response. New coverage includes empty-state
reset with no mutation, keyboard preference persistence/required selection,
secret reveal/remasking, raw rejected drafts, absent secret persistence and
pending-save reveal disabling. Mobile/light/dark screenshots were reviewed.
The design-system document records registry inspection and owned adaptations.
No runtime dependencies were added; existing primitives were preserved.

Image `asterius-idp:local-ast-0c4o-3f8c92739cde` packages binary SHA-256
`3f8c92739cde7ce148acf3572cbcedc5560f9ae9a9ef3d521d01717da63bb668`.
Fresh private backup and isolated database restore passed before rollout. Live
canonical HTTPS readiness, discovery, protected redirects, all ten exact asset
hashes and identity/schema equality passed. Configuration, secrets and Tailscale
Serve remain unchanged. See [deployment evidence](evidence/local-empty-preferences-secrets-2026-10-06.json).
Existing-account password/TOTP sign-in was not exercised. No Rust source changes,
commits, merges, pushes or remote CI.

## Previous directory/activity deployment

The 2026-10-06 five-workflow update runs from uncommitted `claude/ast-azwq`,
carrying the previous redesign. Users and Applications now show applied search
and status chips with individual removal and clear-all actions. Removing status
preserves an unfinished search draft, and filter changes reset the page cursor.
User Access overview shows recent visible sign-in outcomes and timestamps from
its existing bounded audit reads, with working event links and audit permission.
Sessions use the owned sortable table, loaded/active counts and an Active only
switch. Refused account mutations now use error alerts. JSON/YAML panels offer
keyboard-accessible line wrapping, preserving exact copied source. CopyValue
clears stale feedback and ignores clipboard completion after value replacement
or unmount; duplicate pending copy actions are disabled.

Production build/typecheck, 88 unit checks and all 66 controlled Chromium
scenarios passed, followed by the final audit-link navigation/permission check.
Screenshots were reviewed at mobile widths in both themes. Browser checks cover
applied versus draft filters, long filter text, sorted revocation targets and
server refusals, exact source copy in both wrapping modes, stale clipboard
completion, audit visibility and WCAG accessibility. Theme checks wait for the
input text color as well as its surface before measuring contrast.

Image `asterius-idp:local-ast-azwq-e3c85f9f683c` packages binary SHA-256
`e3c85f9f683cf1de0c56d7c8ce30a908f9a41bcb6f28af300b8b779acd7970f4`.
A fresh private backup includes database dumps, configuration/secrets, deployment,
Serve state, the tracked source patch and untracked source archive. An isolated
restore passed before rollout. Live canonical HTTPS readiness, discovery,
protected redirects, all ten exact asset hashes and identity/schema equality
passed. Configuration, secrets and Tailscale Serve remain unchanged. See
[deployment evidence](evidence/local-five-ui-improvements-2026-10-06.json).
Existing-account password/TOTP sign-in was not exercised. No Rust source changes,
commits, merges, pushes or remote CI.

## Previous code/rate-limit deployment

The 2026-10-06 code/rate-limit update runs from uncommitted `claude/ast-pf5f`,
carrying the previous redesign. JSON/YAML documents now use a labelled source
panel with format, line count, nonselectable line numbers, bounded keyboard
scrolling and exact copy. Saved policy source uses the same panel. Optional
rate limits use raw numeric drafts, explicit step controls and an Inherit action;
steps do not change settings until Save. Input groups dim only when their input
is disabled, including while a Save request is pending.

Production build/typecheck, 88 unit checks and all 62 controlled Chromium
scenarios passed. New checks cover Unicode/escaped source, exact JSON/YAML copy,
YAML separators/trailing newlines, clipboard denial, keyboard scrolling, raw
out-of-range/decimal drafts, inheritance omission in save payloads, deployment
ceilings, pending-save disabled controls, server refusals, mobile/dark and WCAG
accessibility. Browser fixture document/assets now specify UTF-8 like production.

Image `asterius-idp:local-ast-pf5f-77ec682eacae` packages binary SHA-256
`77ec682eacae8a6875557e27d24a9607f31e977481ff2ab7706b14e1cfc336fd`.
The fresh private backup and isolated database restore passed before rollout.
Live canonical HTTPS readiness, discovery, protected redirects, all ten asset
hashes and identity/schema equality passed. Two transient HTTPS 503 responses
during endpoint handover were retried with read-only requests.
Configuration, secrets and Tailscale Serve remain unchanged. See
[deployment evidence](evidence/local-code-rate-components-2026-10-06.json).
Existing-account password/TOTP sign-in was not exercised. No Rust source changes,
commits, merges, pushes or remote CI.

## Previous role/history/columns deployment

The 2026-10-06 role/history/columns update is built from the uncommitted
`claude/ast-a8bk` worktree, carrying the previous redesign. Role options show
actual catalogue descriptions, while scope switches invalidate old responses.
Policy publications use an ordered timeline with the existing revision-checked
restore confirmation. Account/application directories expose column visibility;
identity, status and actions remain visible, and choices survive cursor pages.

Production build/typecheck, 88 unit checks and 59 controlled Chromium scenarios
passed. The new regressions cover empty workspace values, retained refused role
assignments, stale catalogue responses, read-only publication history, column
preferences across cursor pages, keyboard focus, mobile and dark accessibility.

Image `asterius-idp:local-ast-a8bk-f0c32a43da6c` packages binary SHA-256
`f0c32a43da6c63c22a10d57346a51bb35af305670a0594f5de46135173995409`.
A private backup and isolated restore verified identity/schema equality,
readiness, discovery, protected redirects and exact console assets before rollout.
The immediate HTTPS readiness check returned 503 during endpoint handover;
the subsequent read-only live verifier passed.
See [deployment evidence](evidence/local-role-history-columns-2026-10-06.json).
Live checks cover canonical HTTPS and bundle integrity; existing-account
password/TOTP sign-in was not exercised. No Rust source changes, commits,
merges, pushes or remote CI.

## Previous workflow component deployment

The 2026-10-06 workflow component update is built from the uncommitted
`claude/ast-pr8l` worktree, carrying the previous redesign. A shared Base Combobox
now searches/selects stable user IDs for group membership. Audit filters expose
common fields, optional references, applied chips and explicit Apply behavior.
Guided setup uses numbered progress within its existing tablist. No runtime
packages or Rust source were added or changed by this iteration.

Production build/typecheck, 88 frontend tests and the final full suite of 55
controlled Chromium scenarios passed. The new scenarios cover duplicate-name
selection, failed writes retaining a choice, stale searches, cursor pages,
directory retry, Escape behavior, mobile/dark accessibility, applied audit/export
queries and stale audit responses, plus setup draft preservation.

Image `asterius-idp:local-ast-pr8l-e963ba3c9182` packages binary SHA-256
`e963ba3c918224c3a8d5e6b1531d8ebca2f7303f7bedd1460c681017c212adf6`.
A fresh private backup and isolated database restore verified readiness,
discovery, protected redirects, all console assets and unchanged identity/schema
before rollout. The first HTTPS protected-route check returned 503 during endpoint handover; the read-only live verifier was rerun afterward. Live verification is recorded in
[workflow component deployment evidence](evidence/local-workflow-components-2026-10-06.json).
Existing-account password/TOTP sign-in is outside these live checks. No commit,
merge, push or remote CI.

## Previous tenant settings width deployment

The 2026-10-06 tenant settings width update runs from the uncommitted
`claude/ast-ieh5` worktree, carrying the existing redesign from `claude/ast-lq9o`.
Tenant settings use the full workspace width. Authentication assurance has a
responsive ACR/method split, four method choices across wide screens, a split
TOTP policy explanation, and the shared Base UI token-method switch. Layout
alternatives and the responsive rules are recorded in the owned design system.

Production build/typecheck and 88 frontend tests passed. All 49 existing
controlled Chromium scenarios passed, followed by the new width regression:
390/768/1440/1920px, both themes, accessibility, keyboard reordering and draft
preservation. No Rust source changed; the binary was built to package assets.

Image `asterius-idp:local-ast-ieh5-0b7882053a71` uses binary SHA-256
`0b7882053a71f30c774b6909a46e177e23b875059d5fe6f00384c2e448be6af1`.
A fresh private backup and isolated restore passed before rollout. Live readiness,
canonical discovery, protected redirects, all console assets, identity and schema
checks passed. Configuration, secrets and Tailscale Serve are unchanged. The
first immediate HTTPS request returned 503 during endpoint handover; the read-only
live verifier passed afterward. Existing-account password/TOTP sign-in was not
exercised. No commit, merge, push or remote CI.

See [the full-width settings deployment evidence](evidence/local-full-width-settings-2026-10-06.json).

## Previous compact form deployment

The 2026-10-06 compact form update runs from the uncommitted `claude/ast-lq9o`
worktree, based on `9985ccdf` with the previous redesign carried forward. Owned
shadcn Field composition now groups labels, help and errors; application and
identity editors use shared inputs. Capability and consent switches use Base UI,
and lifetime inputs show their unit inside the control. Guided application setup
keeps progress and the full-editor action in one compact summary.

Controls are 36px on desktop and 44px on mobile/coarse pointers, with 16px mobile
input text. Desktop forms align labels and controls; mobile forms stack. Inter,
the owned light/dark palette, API payloads, draft protection and permission gates
remain in place. Production build/typecheck, 88 frontend tests and 49 distinct
controlled Chromium scenarios passed; the three affected guided-setup scenarios
were repeated after the final compact-summary change.

Image `asterius-idp:local-ast-lq9o-08d9dd35e7dc` uses binary SHA-256
`08d9dd35e7dc54d24e6dde0a15b8ee10040c0eef8c639926b9a7fcbc866f438b`.
A fresh protected backup and isolated restored-database probe precede rollout.
Live checks verify readiness, discovery, protected redirects, exact assets and
identity/schema preservation. Configuration, secrets and Tailscale Serve remain
unchanged. Existing-account password/TOTP sign-in was not exercised. Local HTTPS
checks pin the canonical hostname to the current Tailscale IP with hostname and
certificate verification retained because local DNS does not resolve it.
No commit, merge, push or remote CI.

See [the compact-form deployment evidence](evidence/local-compact-forms-2026-10-06.json)
and [the owned form system](../../console/DESIGN_SYSTEM.md).

## Previous Base UI migration deployment

The 2026-10-06 console update runs from the uncommitted `claude/ast-0aw2`
worktree, based on `9985ccdf`. All owned primitive wrappers and application
menus use Base UI, future shadcn installs default to `base-vega`, and the console
uses self-hosted Inter. The Untitled UI reference and repository-owned neutral
light/dark tokens from the redesign foundation remain in place.

Image `asterius-idp:local-ast-0aw2-1b8eed99ff58` uses binary SHA-256
`1b8eed99ff588b02e5a450bcfe8a1f8020dde224dafedf6375e6da0abb0136f7`.
Typecheck/production build, 88 frontend tests and 48 distinct controlled Chromium
scenarios passed. Browser checks cover strict CSP, keyboard focus restoration,
confirmations, pickers, dirty drafts, both themes and mobile navigation.
The account-menu axe check excludes only upstream Base UI focus guards; keyboard
behavior is directly asserted. No owned console wrapper imports Radix; cmdk
retains transitive Radix packages.

A fresh protected backup, restored-database probe and live HTTPS/asset checks
verify the deployment. Users, password credentials, encrypted TOTP enrollment and schema records
match the baseline; only the TOTP replay counter advanced during verification; schema remains at 118 successful migrations, latest 173.
Configuration, secrets and Tailscale Serve are unchanged. Local DNS could not
resolve the canonical hostname, so HTTPS checks pinned it to the current local
Tailscale IP while retaining hostname and certificate verification. Existing-account
password/TOTP sign-in was not exercised. No remote CI, commit, merge or push.
See [the migration deployment evidence](evidence/local-base-ui-migration-2026-10-06.json)
and [the design system](../../console/DESIGN_SYSTEM.md).

## Previous Kubernetes console deployment

The 2026-10-04 Kubernetes console update runs directly from the local
`claude/ast-1r9t` worktree, source `b72d9e03`, and then merged into local main.
Open **Kubernetes access** under **Applications** for the cluster directory,
group name picker, authentication status, saved copyable onboarding and owned
temporary access snapshots. See [the console guide](../kubernetes-console.md).

Image `asterius-idp:local-ast-1r9t-ffb6bb71bb15` uses binary SHA-256
`ffb6bb71bb153324a77a8d8bf92cb1a12c3a8e70a993625f4c0caa06b4b44a86`.
Typechecking/build, 86 frontend tests and ten controlled Chromium checks passed.
No Rust source or migration changed. A fresh protected backup and restricted
restored-database probe passed before rollout. Live HTTPS readiness, canonical
discovery, protected account/console redirects and all embedded asset comparisons
passed. Exact account, password and encrypted TOTP records matched the baseline;
schema remains at 117 successful migrations. Private Serve state was preserved.
The existing account's TOTP sign-in and remote cluster/controller health were
not exercised. No remote CI or git push was performed.

See [the Kubernetes console deployment evidence](evidence/local-kubernetes-console-2026-10-04.json).

## Previous menu icon update

The 2026-10-04 menu update is merged locally as `49b83f4a`. It adds matching
Lucide icons for temporary privileges, access reviews, governance findings,
outbound provisioning and workspace health. All 27 menu routes have icons.
Console typechecking and the production build passed.

The live image is `asterius-idp:local-ast-f342-ef0de44ffce7`, using binary SHA-256
`ef0de44ffce7cea7bfcbd20cc52fd3daf07c3af179f7ac994c3625195409ce3d`.
A fresh protected backup and isolated restore passed before rollout. Live HTTPS
readiness, discovery, protected account/console redirects and exact embedded
asset comparisons passed. Schema remains at 117 successful migrations and exact
account/password/TOTP records matched the baseline. Private Serve configuration
and bridge remain active. Authenticated sidebar interaction was not exercised.

See [the menu deployment evidence](evidence/local-navigation-icons-2026-10-04.json).

## Previous modern IdP update

The 2026-10-04 modern IdP update is merged into local main as `ab74aef7`,
with the user's explicit permission to merge locally without remote CI. The live
image is `asterius-idp:local-ast-dd1y-a4748106cb38`, using console-inclusive binary
SHA-256 `a4748106cb38c7ce75d3ceb6b617182998d1465c0cf7cb7858aa547ddbbae106`.
It includes Kubernetes online authentication, managed device posture, temporary
Kubernetes RBAC, outbound SCIM, SPIRE JWT-SVID exchange and parent permission
revision enforcement. Optional integrations require their documented setup.

The console build and 82 frontend tests passed. The final backend source passed
75 targeted library tests, strict linting and parser fuzz checks; the earlier
composed candidate passed 628 targeted tests. Native SPIRE interoperability was
repeated on this exact console-inclusive binary: all 20 controls passed.
Remote CI and ignored PostgreSQL concurrency tests were not run under the user's
explicit local merge exception.

A fresh protected backup is retained at
`~/.local/share/asterius/backups/ast-dd1y-20261004T133538Z-4fd365b4`
(directory 0700, files 0600). The isolated restore and live upgrade reached
117 successful migrations. Exact account, password credential and encrypted
TOTP records matched the pre-upgrade baseline. The live pod is ready, strict
HTTPS readiness and canonical discovery passed, and both tenant account and
console entrypoints retain their protected redirects. All four embedded console
assets matched the built files byte for byte. Private Serve configuration and
the active bridge were verified. The existing user's password/TOTP sign-in was
not exercised in this update.

See [the modern IdP delivery evidence](evidence/local-modern-idp-2026-10-04.json).

## Previous session rotation update

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

### Select consistency update — 6 October 2026 (`ast-858r`)

The next local-console update carries the earlier redesign and replaces every
remaining native console select with the owned Base UI FormSelect: Application
sensitivity, trusted-context example availability/value, and policy simulation
identity/resource/boundary controls. Empty required values now retain their raw
empty representation so browser validation blocks an incomplete simulation.
Highlighted option descriptions inherit accessible menu foreground color.
Classification confirmation, scope gates and stale revision reload remain intact.

The production bundle and 88 unit checks pass. All 74 prior controlled Chromium
scenarios pass against the final bundle; the new classification regression passes
in its focused final run after correcting assertions for the modal alertdialog
and awaiting the dark-theme heading state before axe runs. It covers exact
classification/revision payload, no write before confirmation, stale-disabled
control/reload, keyboard opening/Escape/focus return, mobile layout and light/dark
WCAG contrast. These are controlled API checks, not a real-account sign-in.

Current deployment evidence is
`docs/deployment/evidence/local-select-consistency-2026-10-06.json`. The owned
source and block exploration live in the `claude/ast-858r` worktree. No package
changes, Rust source edits, commits, pushes or remote CI were performed.

### Console hierarchy and editor update — 6 October 2026 (`ast-yvwx`)

This local rollout carries the entire earlier redesign and adds numbered guided
application steps, bounded value editors for applied audit filters, saved-schema
and session-metadata sheets, a wider audit inspector, visible-section navigation
for long pages, and a full-width authorization-details schema workspace. The JSON
draft toolbar is shared by schema/sample, policy draft and simulation context.
Syntax feedback and formatting never replace server validation or explicit Save.

All 29 destination hierarchies are documented in `console/DESIGN_SYSTEM.md`.
The console production build and 88 unit checks pass. All 79 controlled Chromium
scenarios pass, including the all-destination desktop/light and mobile/dark
unavailable-read sweep. Four new layout/interaction scenarios were repeated against
the final bundle after screenshot review added the selectable session ID beside
its Copy action. Loaded-record tests verify exact payloads, raw draft retention on
refusal, explicit filter application, scope behavior, keyboard/focus return,
section navigation, mobile sheet width and accessibility. The full route sweep
checks hierarchy/refusal layouts; it does not exercise every successful backend
workflow or real-account password/TOTP sign-in.

Deployment evidence:
`docs/deployment/evidence/local-page-hierarchy-2026-10-06.json`.
Source remains uncommitted in the `claude/ast-yvwx` worktree. No packages or Rust
sources changed. The binary embeds this worktree's final console bundle, built
from the identical Rust checkout used by the preceding rollout to reuse the shared
owned build cache. No remote CI, commit, merge or push occurred.


### Tenant settings alignment and TOTP illustration — 6 October 2026 (`ast-vum8`)

Tenant settings now shares the centered 1480px page container used by the other
console screens. Configuration panels and fieldsets retain full parent width.
The Authentication tab adds a small decorative phone-and-shield illustration and
an icon on the existing authenticator activation action. Activation still edits
the assurance draft; Save changes remains required to apply it.

The production build, 88 unit checks, and four focused Chromium scenarios pass.
These cover activation save/reload, keyboard controls, reflow, draft retention,
and four viewport widths in light/dark themes with accessibility checks.
Deployment evidence is recorded in
`docs/deployment/evidence/local-settings-width-totp-2026-10-06.json`.
The rollout carries the preceding redesign. No dependency or Rust source changes
were made. Source remains uncommitted in the `claude/ast-vum8` worktree; no remote
CI, merge or push occurred. Real-account password/TOTP sign-in was not exercised.


### Neutral dark theme and corrected card insets — 6 October 2026 (`ast-94so`)

The console dark theme now uses neutral grayscale tokens for navigation,
workspace, cards, controls, overlays, selection and focus. Semantic status colors
remain muted green, amber and red. Identity avatar surfaces and account-menu
shadows follow the shared palette. Light mode retains its existing accent.

A shared tab rule previously removed the padding and border of every card while
leaving the opaque background intact. Removing that rule restores the card
composition's 20px vertical padding and 24px horizontal insets (16px on narrow
screens), including Users → account → Profile → Access overview. Intentional
flat sections stay transparent, and application editor roots now do the same.

The production build and 88 unit checks pass. All 79 controlled Chromium scenarios pass across the full run (78 passed)
and a focused rerun after correcting the mobile inset expectation from 18px to
the existing 16px. These scenarios cover loaded records, draft retention, permission/refusal behavior,
keyboard operation, theme contrast/accessibility and responsive components.
All 29 routes are swept in light desktop and dark desktop/mobile refusal states.
The access-overview regression verifies actual card insets and surface color
in both themes at desktop/mobile widths. This is controlled frontend validation;
real-account password/TOTP sign-in was not exercised.

Evidence: `docs/deployment/evidence/local-neutral-dark-theme-2026-10-06.json`.
Source remains uncommitted in `claude/ast-94so`. No dependencies or Rust sources
changed, and no remote CI, commit, merge or push occurred. The unchanged Rust
checkout embeds this worktree's final console bundle using the owned build cache.


### Token tool, header illustrations and feature README — 6 October 2026 (`ast-d38s`)

The extra On this page navigation has been removed. Token test console is now a
scope-aware flask link in the top bar, with a keyboard/pointer tooltip, rather
than a sidebar destination. Its route and issuance authority are unchanged.
The redesigned tool uses a compact issuance panel and encoded/decoded cards at
the standard page width, searchable active-record pickers, local JSON/YAML
inspection, copy/clear, malformed-JWT feedback and explicit unverified wording.
It continues to issue only 60-second marked test ID tokens on an explicit action.

Page headers add small decorative illustrations from the shared route symbols;
account detail headers retain their identity avatars. The illustrations shrink
on mobile, follow both themes, and add no asset fetch, package or animation.
The concise feature guide is `docs/console/README.md`, linked from root and
console READMEs, covering all 29 destinations, account/settings tabs and optional
protocol capabilities with why/how instructions.

The production build, 88 unit checks and all 79 controlled Chromium scenarios
pass. A four-scenario final-bundle check covers the token workspace, loaded
account overview, schema workbench and all-destination sweep. Its token scenario
was repeated after adding an explicit computed-color wait before axe analysis
of direct theme-class changes; the final contrast checks pass in both themes.
A previously incomplete opaque audit-row fixture was corrected to match the API
envelope. All 29 routes were checked at light desktop, dark desktop and dark
mobile widths. These are frontend checks with controlled API responses;
real-account password/TOTP sign-in was not exercised.

Evidence: `docs/deployment/evidence/local-token-tools-guide-2026-10-06.json`.
Source remains uncommitted in `claude/ast-d38s`. No dependency or Rust source
changes, remote CI, commits, merges or pushes occurred. The unchanged Rust
checkout embeds this worktree's final console bundle using the owned build cache.
