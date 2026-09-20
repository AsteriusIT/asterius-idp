# Console, groups and SSO administration

This runbook covers the tenant changes delivered by the console and SSO
milestone. Use a session for the tenant being changed: tenant data is isolated,
and a deployment administrator must still select the intended tenant before
opening a tenant screen. Read access makes a screen visible; its matching
`*:write` scope is required before the console enables a save or destructive
action.

## Managed groups and effective roles

Open **Groups** with `admin.groups:read`. A session with
`admin.groups:write` can create a group, edit its display or machine name, and
manage its direct members. Machine names are lowercase identifiers; display
names are operator-facing labels. Keep the generated group UUID when a group is
renamed: policies should use the stable `group:<uuid>` reference described in
[the managed-groups migration guide](../groups-migration.md).

Open a group and use its **Members** and **Roles** tabs to change membership and
application-role assignments. The **Users → Roles** tab shows the effective
union and identifies each direct or group source by display name and machine
name. From **Users → Groups**, search either name and select the labelled group;
the stable UUID stays internal to the API and is never an operator input.
Removing one source does not
remove a role that is still supplied by another source. If another operator
changes the group first, the saved revision no longer matches; reload the group,
review their change and apply yours again instead of overwriting it.

Membership and role edits apply to the next authorization decision, token
issuance, refresh or UserInfo response. They do not rewrite an already signed
JWT. When access must end immediately, also revoke the user's grants and
sessions; otherwise the JWT remains valid until its expiry.

## Policy changes

There are two distinct policy surfaces:

- **Access policy** (`admin.policies:read` and `admin.policies:write`) edits the
  tenant authorization document. Use the test bench before saving. A refused
  probe or save is shown as an error and must not be treated as an applied
  change. The server remains the validation authority even when the editor can
  identify a field locally.
- **Tenant settings → Authentication** (`admin.tenants:write`) edits the
  ordered authentication-assurance ladder and whether AMR is released in ID
  tokens. The supported methods, invariants and step-up behavior are documented
  in [Tenant authentication assurance](../tenant-assurance-policy.md).

Saved policy is used for the next decision. Authentication-setting writes
invalidate the writing process immediately; other replicas reload tenant
settings within 30 seconds. Discovery responses may retain their existing
five-minute HTTP cache. Policy changes do not revoke signed tokens, sessions or
grants, so use the relevant revocation operation when the change is intended to
terminate existing access. Both surfaces emit administrative audit events.

## Tenant branding

Open the tenant menu and choose **Branding**. Reading requires
`admin.theme:read`; saving or resetting requires `admin.theme:write`.

1. Edit the logo, colors, product name and support/privacy links. The preview is
   local and intentionally changes only the end-user card, never the console
   chrome.
2. Resolve every field error. Links and logos must use HTTPS; uploaded logos are
   restricted to PNG, JPEG or WebP, at most 200 KiB, and are decoded and
   re-encoded by the server.
3. Choose **Save** and wait for **Branding saved**. **Reload saved** discards
   unsaved edits. **Reset to defaults** is a server write and requires explicit
   confirmation; it does not merely reset the preview.
4. Reload a real sign-in page for the same tenant and verify the saved logo,
   colors, text and links. This checks the runtime renderer rather than only the
   console preview.

The writing process invalidates its theme cache immediately; another replica
may serve the preceding theme for at most 30 seconds. An already open sign-in
page is a rendered snapshot and must be reloaded. Tenant input supplies neither
HTML nor JavaScript, and a failed read or rejected save must never be worked
around by injecting either.

## Exercise browser SSO

Use the [two-application SSO demonstration](../sso-demo.md) after changing
groups, policy or branding. It starts two confidential BFFs against the example
deployment and demonstrates one browser session, independent consent, refresh,
UserInfo, step-up and logout. Follow that guide's registration and TLS steps,
then its cleanup section; its credentials, callback origins and in-memory state
are development fixtures, not production defaults.

Record the tenant, operator, time, affected group or policy revision and the
post-change browser result. For a release candidate, also follow the
[release-evidence procedure](../deployment/verifying-a-release.md); a successful
manual journey does not replace CI or FAPI conformance evidence.
