# Console redesign review

The console uses a neutral Asterius header, labelled navigation, restrained
borders and aligned 42px controls. User and application details now use real,
keyboard-accessible tabs. Inactive panels preserve unsaved form drafts; tabs
wrap on narrow screens without a scrollbar. Sessions and authorizations show
their tables directly. Roles use assignment tables and focused dialogs.
Preferences use segmented radio controls, grant types have readable labels and
icons, and selects use Radix/shadcn-style accessible primitives.

These PNGs show the production bundle in Chromium with fixture API responses.
They use sample identities and do not represent backend integration tests.
They cover user details, sessions, roles, assignment, grant types, selects,
light/dark preferences, and 390px mobile tabs. Existing API handlers and
permission checks are retained.

Validation: frontend build/typecheck and 3 unit tests passed. Fixture browser
checks verified equal control heights, preserved drafts, role assignment,
select interaction, and no page/tab overflow on mobile. Axe reported no
violations on reviewed sessions, role dialog, grant types, preferences in both
themes, and dark user details. No browser JavaScript errors were observed.
Six targeted Playwright tests passed against the refreshed Docker Compose
application: theme persistence, dark accessibility, mobile navigation,
sidebar collapse, user tabs/drafts/mobile layout, and application tabs/selects.
The full integration suite was not run locally.


## Workspace settings and role definitions

Tenant settings now live in the workspace menu; personal preferences live in
the account menu. Neither appears in the sidebar or overview shortcuts.
Capabilities use readable names, explanatory copy, icons and switches, with a
separate tab for token lifetimes. Unknown server feature flags are retained.
Role definitions live on the dedicated Roles page, with workspace/application
scope selection and a New role dialog. The application editor links to its
catalogue on that page. Creation, deletion, and server refusals retain the
existing API behavior and permission checks.

The tenant-capabilities, tenant-lifetimes, tenant-dark, tenant-mobile, roles,
new-role and role-mobile images document this revision. Fixture browser checks
passed for draft preservation, modal creation, scope selection, mobile width,
and accessible light/dark rendering; no JavaScript errors were observed.

Eight targeted Playwright tests passed against the refreshed Docker stack for
this revision, including role creation/deletion, workspace/profile navigation,
settings accessibility, server lifetime refusal, preference persistence, and
user/application tab regressions. The temporary verification role was deleted.
