# Kubernetes access in the console

Open **Kubernetes access** under **Applications**. The screen uses the existing
workspace-scoped administration APIs and requires `admin.clients:read`.

The directory reads applications in pages of 20, with at most four profile
lookups in flight. **Load more applications** continues the catalogue. Missing
profiles are eligible for setup; failed lookups remain visible and are not
presented as an absent profile. Register one confidential broker application per
cluster before choosing **Add cluster**. Backend registration checks remain the
authority for compatible OIDC, DPoP, ES256 and public-subject settings.

The detail screen edits the saved namespace and managed-group release policy.
Group read permission is required for the name picker; client write permission
is required to save. Search and group pagination preserve existing selections,
including groups outside the visible page. Missing group details remain in the
selection until explicitly removed. A saved cluster identifier cannot change.
Saves carry the exact profile revision; concurrent changes are refused. Reloading
a saved profile asks before discarding a draft. Unsaved changes never enter the
copyable onboarding examples.

Authentication displays the saved online reviewer state and its documented
cache limits. Temporary access shows at most 100 entitlements owned by the
current account, plus bounded request/activation snapshots and controller
bindings. Other owners' entitlements are not exposed. Refresh status after an
external change. Profile saves refresh both online and temporary configuration.
An enabled binding is configuration, not proof that a controller or cluster is
healthy. The console does not inspect live RoleBindings or configure a remote
cluster. A binding invalidated by a profile revision is displayed as an error.

Copyable structured authentication, legacy flags and namespace read-only RBAC
examples come from the saved profile. Temporary identity authentication is a
separate server-generated document when a binding is enabled. The terminal
commands use the existing [broker/helper](../tools/kubernetes-login/README.md):
install it and configure the trusted broker, cluster API server and CA pins
before invoking them. The helper account alias partitions local storage; it
does not select an OAuth account. Command arguments are shell quoted.

## Verification

`npm run build --prefix console` typechecks and builds the console.
`npm test --prefix console` includes revision preservation, path/shell encoding,
authentication labels and bounded profile lookup tests.

After installing the repository's pinned E2E dependencies, the built console
can be exercised in Chromium with controlled responses:

```sh
NODE_PATH="$PWD/e2e/node_modules" node scripts/kubernetes-console/acceptance.mjs
```

The fixture covers directory loading, partial API failures, group names,
authentication refresh, off-page selection preservation, concurrent revision
conflicts, mobile overflow and read-only permissions. It uses no live account
credentials and does not claim live cluster/controller interoperability.
