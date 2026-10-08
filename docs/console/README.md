# Asterius console: what, why, and how

Open `/t/<tenant>/admin/` and sign in. Choose the tenant in the top bar; links and
actions follow your permissions. Sidebar entries manage records. Top-bar tools
include the token test console (flask), architecture builder (network), help
(book), and workspace health (pulse). Preferences are in the account menu;
Tenant settings and Branding are in the tenant menu.

For a complete set of sandbox exercises, including API and external-peer prerequisites, use [the local feature tour](local-feature-tour.md).

For the isolated application environment and hands-on SSO/financial exercises, use [the local playground](local-playground.md).

## Screens

| Feature | Why use it? | How to use it |
| --- | --- | --- |
| Overview | See the workspace and reach common tasks. | Review the available summaries, then open a directory or shortcut. |
| Users | Manage accounts, credentials and access. | Search or add a user; open the account and choose a tab below. |
| Groups | Grant access to a set of people. | Create/open a group, select members, then assign roles; managed memberships may restrict editing. |
| Roles | Describe tenant or application permissions. | Choose the role scope, define a role, then assign it to a user or group. |
| Temporary privileges | Approve time-limited elevated access. | Configure an entitlement and eligibility; review a request, activate or revoke it. Existing offline tokens retain their capped expiry. |
| Access reviews | Reassess existing standing access. | Assign ownership, select records, create a review, record retain/remove with a reason, then explicitly apply the decision. |
| Governance findings | Investigate recorded access-governance problems. | Refresh findings, inspect the evidence and affected source, then use the relevant management screen. |
| Applications | Connect an OIDC/OAuth client. | Add an application through guided setup; review callbacks, credentials, grants and claims before registration. Copy saved connection values for its owner. |
| Token test console | Inspect the ID token an integration would receive. | Open the flask in the top bar; choose an active application/user and issue a test token, or paste a JWT. Inspect/copy header and claims, then Clear. |
| Outbound provisioning | Synchronize selected identities to another Asterius workspace. | Configure a paused destination, select users/groups, run its authenticated preview, then enable it; inspect delivery and explicit deprovisioning controls. |
| SCIM provisioning | Let an external directory manage identities here. | Copy the SCIM endpoint, manage the provisioning client/token, and configure that connection in the external directory. |
| Kubernetes access | Prepare cluster authentication and group RBAC. | Select a registered application, set the cluster profile and groups, then copy the generated authentication configuration and RBAC YAML. |
| Resource servers | Register API audiences and scopes. | Add an exact resource identifier and scopes; configure token lifetime/introspection access where available. |
| Architecture builder | Model related apps, APIs, groups and roles together. | Open the network icon; use a preset or blank canvas, edit objects and connections, save a draft, inspect the provisioning preview, then explicitly apply it. |
| Sign-in providers | Delegate sign-in to an upstream OIDC provider. | Add the provider and client settings, check discovery metadata, configure mappings, then save. |
| Authorization details | Define structured authorization requests. | Register a type, edit its JSON Schema and consent wording, test a sample, then save. Format JSON checks syntax; the server validates the schema. |
| Access policy | Control authorization and evaluate proposed changes. | Read the saved policy; edit a draft, validate/simulate, then publish explicitly. Inspect history before restoring a revision. |
| Signing keys | Manage keys used to sign tokens. | Inspect active/pending keys; stage/rotate using the available action and follow the displayed activation/retirement controls. |
| Federation keys | Manage federation signing material and trust roots. | Inspect keys and pinned trust anchors; rotate using the available action. Trust roots are operator-configured. |
| SAML IdP key | Sign SAML responses and define trusted service providers. | Import/stage a key, activate its successor, and retire the former certificate after SP rollover; register exact SP entity IDs and ACS URLs. |
| Shared signals | Exchange security events with peers. | Manage outgoing streams and receiver state; set up/check/poll configured upstream transmitters and inspect delivery failures/dead letters. |
| Mail delivery | Diagnose invitations and message delivery. | Refresh delivery state, inspect recent invitations, and resend when permitted. Resending invalidates earlier invitation links. |
| Audit trail | Investigate recorded administrative and security activity. | Apply filters, edit/remove applied chips, inspect an event's details, or export the selected trail. |
| Tenants | Manage workspaces across the deployment. | With deployment permission, create/open a tenant, inspect its settings, or confirm suspension. |
| Tenant settings | Configure sign-in and token behavior. | Open the tenant menu, select a settings tab, edit, then Save changes. See the tabs below. |
| Branding | Customize end-user sign-in pages. | Open the tenant menu, edit the saved theme, inspect its preview, and save; console preferences are separate. |
| Preferences | Adjust this browser's console appearance. | Open the account menu; choose light/dark and table density. |
| Workspace health | Inspect workspace readiness and available diagnostics. | Open the pulse icon and review the displayed checks; refresh when offered. |
| Help & guides | Find task walkthroughs and integration guidance. | Open the book icon; choose/search a guide or open developer documentation. |

## Your own account

Open the account menu → My account to manage your profile, password, passkeys,
authenticator enrollment and sessions. Enrolling TOTP on an account and enabling
its challenges in Tenant settings are separate actions. Sign out ends the console
session; browser appearance/density preferences remain local.

## User account tabs

| Tab | Why / how |
| --- | --- |
| Profile | Inspect account state and recorded sign-in activity; edit profile fields or confirm disabling the account. |
| Identity data | Review stored claims; edit and save the identity data when permitted. |
| Sign-in methods | Manage password/passkey/authenticator state and inspect sign-in/email diagnosis; use the available credential actions. |
| Sessions | Inspect sign-in sessions and their recorded assurance; confirm End session to revoke a selected session. Inspect alone changes nothing. |
| Connected apps | Review the user's application grants and use the available grant-management actions. |
| Access roles | Inspect direct and group-inherited assignments; add/remove explicit assignments where permitted. |
| Groups | Review memberships and add/remove an explicit membership where permitted. |

## Tenant settings tabs

| Tab | Why / how |
| --- | --- |
| Capabilities | Enable/disable available protocol features using their switches, then save. Server bounds still apply. |
| Token lifetimes | Set authorization-code/access-token lifetimes within the displayed limits, then save. |
| Consent | Choose whether to always show consent on interactive authorization, then save. |
| Sessions | Configure session policies and durations, then save. |
| Authentication | Define/reorder assurance levels and required methods; configure the `amr` claim, then save. Enable authenticator codes adds a password + TOTP level to the draft. Enrolled accounts face code challenges on fresh sign-ins only after saving. |
| Rate limits | Where supported, configure explicit limits or leave values inherited; save to apply. |
| Protocol endpoints | Copy discovery/issuer and endpoint URLs for integrations. |

## Optional protocol capabilities

Enable available capabilities in Tenant settings → Capabilities, then configure
the participating application and use the protocol guide in Help. Enabling a
feature alone does not complete an integration.

| Capability | Why / how |
| --- | --- |
| Certificate-bound access (mTLS) | Bind application authentication/tokens to a certificate; configure the client and certificate-aware connection. |
| Consent management | Let applications manage standing grants; configure the client and use grant-management operations. |
| Decoupled authentication (CIBA) | Request approval on a separate device; configure the CIBA client and follow its backchannel flow. |
| Device sign-in | Sign in on a device through another browser; configure the client and follow the device-code flow. |
| Token exchange | Delegate between services; configure permitted actors/resources and request an exchange for the target audience. |
| Security event sharing (SSF) | Propagate relevant security events; configure a stream/peer in Shared signals. |
| Authorization decisions (AuthZEN) | Ask whether an action is allowed; define policy/resources and integrate the decision endpoint. |
| Proof replay protection (DPoP nonce) | Require a fresh server challenge for proofs; configure the client to handle nonce challenges and retry with a new proof. |

## Policy and integration tools

- **Conditional policy:** review a staged policy, choose report-only/enforcement
  settings, and activate explicitly. Staging and inspection do not publish it.
- **What-if simulation:** select real tenant records, provide hypothetical
  context where needed, and inspect the decision. Hypothetical evidence is not a
  real sign-in or live authorization event; inspections are audited.
- **JSON/YAML viewers:** inspect source and copy the exact document. JSON editor
  formatting is explicit and does not save or replace server validation.
- **Filters and tables:** apply search/filters, inspect applied chips, choose
  columns where offered, and follow cursor pages. Unapplied drafts stay separate
  from the currently displayed results.
- **Secrets:** use reveal/copy where offered and acknowledge one-time credentials
  before leaving. Copy failures leave a manual selection path.

## Important distinctions

Changes take effect through the page's Save, Publish, Apply, or confirmation
action. A preview, inspector or local decoder does not apply changes. Unsaved
edits can prompt you before leaving; a refused save retains the draft.

Test tokens expire after 60 seconds and contain `asterius_test: true`; they do
not assert that the user signed in. Pasted JWTs are decoded locally without
signature verification. The tool issues ID tokens, not access tokens or a live
login session. It requires `admin.test_tokens:write`; application/user lookup
still follows the server's permissions.

Assigned roles and grants do not alone guarantee an allow decision. Read-only
and deployment-wide authority differ, and the server authorizes every request.

For build and implementation details, see [console developer README](../../console/README.md).
