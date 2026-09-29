# UI/UX implementation — ast-1k13

This implementation refines the existing console and public templates. It does
not introduce a new UI framework or change authentication/authorization policy.
The source review baseline is `b8be1f3`. Bead `ast-1k13` remains the source of truth
for delivery status and outstanding acceptance; this document describes the
interaction contract and the scope of the evidence.

## Interaction contract

- Navigation: People, Applications, Sign-in & trust, Operations, Workspace and
  Help. Architecture has a labelled destination. Tenant settings and branding
  remain in the workspace menu; browser preferences remain in the account menu.
- User and application URLs carry the entity ID and selected tab. Tab changes
  keep mounted drafts. Secrets and search text do not enter those URLs.
- Registered dirty editors warn on sidebar navigation, browser history, tenant
  switching, sign-out and document exit. Drafts stay in component memory. Modal
  editors use an inline discard choice, not a second modal. A failed save keeps
  the draft; a 401 clears privileged content, including editors and dialogs.
- Dialogs return focus to their opener when it still exists. Destructive
  confirmations focus the safe action and remain open while a request is busy
  or fails. Resource and authorization-type withdrawal name the target, tenant
  and access consequence.
- Long schema work uses a page with a plain-text consent preview. Audit inspection
  uses a read-only drawer. Short resource and group forms remain dialogs.
- Table filters/sorts operate on loaded rows. The default labels state that
  limitation. Wide comparison tables scroll inside a labelled keyboard region.
- Copy feedback is explicit. Unacknowledged one-time application secrets remain
  visible across tabs and trigger the navigation warning. Copy success is not
  proof of secure storage; manual acknowledgement is available.
- The three formerly standalone account pages use the common tenant shell,
  English/French catalogue, escaped values, CSRF forms and no-store responses.
  TOTP setup uses an in-process QR encoder and manual key. Nothing is sent to a
  QR service. Removal uses a disclosed impact explanation plus required native
  acknowledgement. This is accidental-action protection, not authorization.

## Current layout specification

`tokens.css` supplies the shared baseline; `enterprise.css` is the final console
layer. Read their cascade together. Public pages use `templates/style.css` and
validated tenant tokens, with no automatic dark palette substitution.

| Element | Current choice |
| --- | --- |
| Console page gutters | 32px desktop, 24px tablet, 16px phone |
| Primary controls / navigation | 44px preferred target; compact table actions remain explicit |
| Form width | Up to 720px; long schema editor can use available space |
| Explanatory text | About 72 characters per line |
| Section separation | 32px |
| Essential small metadata | At least 12px in the refined chrome |
| Bottom clearance | 96px plus safe area in scrolling console content |
| Dialog height | At most viewport minus 32px, with internal scrolling |
| Authenticator QR | 240px maximum, responsive, white quiet zone |
| Motion | Reduced-motion preference suppresses transitions/animations |

The legacy `before/`, `after/` and `reference-redesign/` images remain historical.
The focused current captures are in `experience-review/`: schema at 390/1440px,
light/dark. The English/French authenticator captures use the actual template snapshots,
rather than an independently recreated mockup.

## Screen and state inventory

This is a source inventory, not a claim that every cell has been exercised in a
live deployment. State families: **Q** = loading, empty/no-results, request
failure/retry; **F** = editing, invalid/refused, saving/success; **D** = destructive
confirmation; **R** = read-only/scope denied. Every console route shares session
expiry recovery. A route without data has Q as not applicable. Public responses
are server-rendered: client-side loading/saving spinners are not applicable;
POST failure/success are separate responses and backend authorization applies.

| Registered console route | State families and behavior |
| --- | --- |
| overview | Q/R for independently authorized metrics; received timestamp and existing drill-downs |
| users | Q/F/D/R; addressable account tabs, guarded identity/create drafts, existing disable/session/role dialogs |
| groups | Q/F/D/R; guarded group form; authorized username/email search for membership; direct/inherited roles retained |
| roles | Q/F/D/R; existing catalogue, assignment and withdrawal dialogs retained |
| clients | Q/F/D/R; addressable tabs, guarded drafts, one-time secret, existing setup guide and checks |
| resources | Q/F/D/R; guarded short editor and contextual withdrawal refusal |
| authorization-details | Q/F/D/R; page editor, schema validation, safe consent preview, withdrawal confirmation |
| architecture | Q/F/D/R; existing draft/review/apply, canvas plus non-drag object/connection controls |
| scim | Q/R; configuration inspection; no claim of a live provisioning test; F/D not applicable |
| oidc-providers | Q/F/D/R; guarded provider draft; existing callback and mapping instructions |
| keys | Q/F/D/R; existing rotate/sign/retire lifecycle and refusal handling |
| federation | Q/F/D/R; existing trust/key configuration; no invented connectivity status |
| saml | Q/F/D/R; existing metadata/key/SP configuration |
| ssf | Q/F/D/R; existing inbound/outbound/dead-letter operations and per-row progress |
| mail | Q/F/D/R; existing delivery attempts, resend warning and privacy constraints |
| audit | Q/R; UTC presets, export scope explanation, read-only detail drawer; F/D not applicable |
| policy | Q/F/D/R; guarded draft, existing evaluator and document/rules views |
| tenants | Q/F/D/R; existing create/suspend scope and impact confirmations |
| settings | Q/F/R; guarded capability/lifetime edits; D not applicable |
| branding | Q/F/R; guarded existing preview/editor; D not applicable |
| preferences | F; browser-local appearance/density; Q/D not applicable |
| help | Role-aware static guides; Q/F/D not applicable |
| shell denied / signed out / unknown route | Existing explanatory recovery; 401 now reaches shell from any shared API request |

| Public/account page or response | Applicable states / boundaries |
| --- | --- |
| login / step-up | Fresh, invalid, provider choices, passkey progress/failure, cancel; native password fallback |
| totp_challenge | Fresh/invalid, numeric paste/autofill; error response does not autofocus past summary |
| consent | Required/optional scopes and details, approve/deny; existing redirect-host/account identity |
| passkey | Script-enhanced enrollment and native no-script explanation; not a password substitute |
| device | Empty/prefilled/invalid user code; native POST |
| device_confirm / device_done | Review/approve/deny; success/refusal; request-origin warning retained |
| approvals | Empty/list, pending decision, expiration, approve/deny; absolute UTC expiry alongside relative text |
| grants | Empty/list/revoke; existing app and permission descriptions |
| account | Authenticated identity; grouped sign-in, sessions, apps and providers; unauthenticated redirects |
| account_email | Current/pending address, invalid, requested/verified; native form |
| account_passkeys | Empty/list, rename/remove/refused, last-credential constraints; backend remains authoritative |
| account_password | Set/change, invalid/current-password refusal, success; existing session consequences |
| account_activity | Empty/list, pagination and safe security-event details; mutations not applicable |
| account_sessions | Current/other sessions, revoke/refused/success; no invented device/location data |
| account_totp | Not configured, pending/restart, QR/manual provisioning, confirmation invalid/success, active/remove/refused |
| account_providers | Configured/connected/expired/orphaned/empty, connect/refresh/revoke, stored claim details, refused/success |
| account_external_approvals | Empty/current approvals, eligible linked issuers only, scope choice/grant/revoke/refused/success |
| register | Policy-enabled form, invalid/success; entry availability remains tenant-controlled |
| verify_email | Invalid/expired/confirmed; no new account-enumeration information |
| password_reset / password_reset_sent / password_new | Generic request result, invalid/expired link, password policy refusal/success |
| invitation | Pending/invalid/expired/used/success; successful acceptance links to tenant-bound account/sign-in entry |
| logout_confirm / logged_out | Confirmation, completed, still-signed-in failure; no promise of global app logout |
| error / external_sign_in_error | Branded failure, safe reference/retry when available; support footer when configured |
| form_post | Protocol handoff; native submit fallback; no account editor/destructive state |

## Disposition of review recommendations

“Retained” means the existing implementation remains the chosen behavior, not
that an automated test proves all its states. “Deferred” identifies a boundary
rather than a hidden claim of completion. The single Bead records acceptance.

| Recommendation | Implementation / disposition |
| --- | --- |
| R01 | Converted all three inline account pages to shared templates. New page chrome/actions are EN/FR; existing server refusal messages remain as previously supplied. |
| R02 | Shared draft guards include administrative role, application-role creation and assignment dialogs; Cancel, Escape and outside dismissal use the same inline discard choice. |
| R03 | Resource/type withdrawal confirmed; shared dialog failure behavior fixed. New account removal disclosure/acknowledgement chosen instead of an extra GET/POST confirmation endpoint. Existing passkey/session security constraints retained. |
| R04 | Central 401 shell recovery and distinct fallback guidance for access/conflict/throttling/service/network failure. Writes are never automatically retried. Request URLs are explicitly restricted to the current-origin workspace API or read-only discovery documents. No expiry countdown without authoritative expiry data; no new return-URL parameter. |
| R05 | User/application IDs and tabs and audit event links are addressable. Users/Applications preserve search, server order, cursor and scroll in authenticated-shell memory, cleared on sign-out; personal search terms are not stored or put in URLs. |
| R06 | New labelled grouping and Architecture destination. Existing workspace/account menus retained; optional command palette declined to avoid competing Ctrl/Cmd+K shortcuts. |
| R07 | Users and Applications now search and sort before server pagination. Applications expose next/first page controls. Existing contained, keyboard-accessible table scrolling is retained. Other catalogues retain their existing loading/filter behavior, per the agreed first scope. |
| R08 | Persistent form errors and failed-dialog behavior are retained. Registration now maps typed backend validation failures to field links beside the shared error summary. Generic credential and account-conflict responses remain generic. Other public forms retain existing error handling. |
| R09 | Passkey live status, TOTP error focus, route heading focus, dialog focus return and non-drag architecture controls. Automated axe, keyboard and reflow/document-zoom checks cover representative new screens. Human screen-reader and moderated usability testing remain outstanding by agreement. |
| R10 | Tenant Help/Privacy/Terms and EN/FR public account templates retained. Console English only, as requested; no console language selector. |
| R11 | Shared final-layer dimensions and documentation reconciled; existing Geist/tenant palette preserved. No framework replacement. |
| R12 | Gutters, bottom clearance, modal viewport limits, reduced motion and a measured dark-hover contrast correction. Focused viewport/theme checks cover the schema editor; all-screen/palette qualification remains acceptance work. |
| R13 | Role-aware shortcuts, independent metrics and drill-downs plus an optional setup checklist based on authorized account, application and signing-key counts. Checklist completion is not a production-readiness claim. |
| R14 | User access overview links grants and direct/group-inherited roles, and reads the latest successful recorded sign-in with audit permission. The scan is bounded to the latest 1,000 sign-in attempts and states when older inspection is needed. This is not an effective-policy evaluator. |
| R15 | Optional six-step application setup wizard, review before registration, switch to full editor without losing the draft. Existing expert setup, one-time secret warning and connection configuration remain. |
| R16 | Schema sample evaluation uses the production backend validator without saving. Application Access & grants includes a registered authorization-detail type picker and preserves unknown existing types. |
| R17 | OIDC public discovery/JWKS checks run automatically once per minute while the provider page is visible, with manual retry. SAML, federation and email provide manual saved-configuration/status checks; SCIM retains configuration inspection. No client-secret exchange, live SAML/SCIM transaction or email delivery is claimed. |
| R18 | Existing API-backed lifecycle and confirmations retained. Timeline/expiry forecasting declined without authoritative overlap/expiry data. |
| R19 | Policy saves publish immediately. A database trigger atomically records every publication, including clear/restore, retaining the latest 100 versions per tenant. Existing policy is backfilled at migration; prior history cannot be reconstructed. Restore requires confirmation and publishes a new version. No policy-impact prediction is claimed. |
| R20 | Audit details have reloadable tenant-scoped links and copy-link action. Existing UTC filters, export and mail/signal operations remain. Dedicated mail-delivery URLs and asynchronous export progress are outside this implementation. |
| R21 | Saved branding can be previewed through the actual production login template in login, invalid-credentials and step-up modes. Preview controls are inert; saving is required before preview reflects changes. |
| R22 | Object/connection list offers inspect/add/remove without drag, preserving review/apply semantics. Existing responsive stacked inspector retained; full mobile editor qualification remains manual acceptance. |
| R23 | Existing role-aware guides retained. No extra documentation product area or optional navigation search. |
| R24 | Provider button treatment, passkey live status and existing password fallback retained. Optional password reveal and identifier-first flow declined; no new credential collection step. |
| R25 | Local QR/manual enrollment, confirmation/restart and removal retained. Settings → Authentication exposes authenticator policy activation, preserving existing assurance levels; the account page states whether tenant policy uses TOTP. Enrollment alone does not activate tenant policy. |
| R26 | Invitation completion continuation delivered. Existing anti-enumerating recovery responses and policy-driven entry paths retained; no unsupported cooldown or duration invented. |
| R27 | Absolute approval expiry added. Existing permission review, origin warnings, deny and terminal states retained. No auto-approval or assumed verified client display name. |
| R28 | Account links grouped and outlier security pages branded. Existing passkey/session/grant controls retained; no invented security score or device/IP facts. |
| R29 | Existing branded error/logout/terminal semantics retained, with optional support footer. No new all-application logout claim or unsafe redirect. |
| R30 | Page for schemas, drawer for audit, dialogs for short edits; shared safe dismissal/failure/focus behavior. Native disclosure plus acknowledgement is the chosen no-JS confirmation pattern for the newly themed account pages. |

## Evidence and remaining acceptance

The focused browser specification `e2e/tests/console-experience.spec.ts` uses the
real production bundle under a nonce CSP and deterministic API fixtures. It tests
failed/cancelled withdrawals, read/write expiry, draft discard/cancel, browser
history, persistent tabs, one-time secrets, dialog focus and responsive axe
checks. It does **not** prove backend authorization, live mail delivery, or an
actual external application connection.

Rust coverage includes typed-template escaping, redacted QR/page Debug output,
QR quiet-zone geometry, golden EN/FR renderings and the repository's source/
secret audits. Existing server account entry tests check tenant-relative routing.
The current branch's exact verification result is recorded in the Bead/PR.

A moderated administrator/support/end-user session cannot be simulated by source
review. Real assistive-technology checks and the full critical-journey acceptance
against a running configured tenant remain explicit acceptance gates. Existing
`e2e` backend journeys remain CI/deployment evidence, not claimed local results.

### Initial local verification, 2026-09-29

- Console production build/typecheck and 35 focused model/API tests passed.
- 13 focused browser scenarios passed: nine console behaviors plus the five new
  account state fixtures in both languages, with and without JavaScript.
- Responsive checks ran at 320/390/768/1440px; axe checks covered the new account
  pages and representative light/dark console schema views. Screenshots were
  inspected at phone size; the authenticator input was corrected to the shared
  44px styling and covered by a browser geometry assertion.
- `cargo check --all-targets` and strict all-target Clippy passed. The targeted
  nextest selection passed 175 tests; the golden-only verification passed five.
  The subsequent literal `type="text"` template/fixture correction was checked
  by cargo check/Clippy and browser tests; the three-run local nextest limit was
  respected. CI will recheck the exact final snapshot bytes.
- `git diff --check` passed. No full local Rust suite was run.

Reproduce browser evidence after building the console:

```sh
npm --prefix console run build
E2E_SHOTS=docs/console/experience-review ./e2e/node_modules/.bin/playwright test \
  --config=e2e/playwright.config.ts console-experience.spec.ts account-experience.spec.ts
```

### Follow-up scope agreed with the administrator

Keep the current brand and English console. Include backend support for the
application wizard, schema samples, policy versions, audit links and directory
sorting. Publish policy saves immediately; restore is another publication.
Start global directory search/order with Users and Applications. Use automatic
OIDC metadata checks and manual configuration checks for other integrations.
Keep human screen-reader and moderated usability testing explicitly outstanding.

Migration `0150` adds bounded policy history without changing the active policy.
The TOTP activation control changes a draft; **Save settings** publishes it.
Deployment does not automatically change any tenant's authenticator policy.
The latest verification counts and local deployment are recorded in `ast-1k13`.

Follow-up local evidence (2026-09-29): production console build/typecheck and
17 focused model tests passed. Twenty-five focused browser scenarios passed
across the main run and corrected targeted reruns, including tenant TOTP policy
save/reload, audit links, rollback refusal, guided setup, search/order memory,
OIDC automatic checks, manual configuration checks, and last-successful-sign-in
selection. Axe checks passed in both themes at 320/1440px for the wizard and
assurance settings; keyboard tab navigation and 200% document zoom also passed.
The earlier account/schema responsive checks remain covered.

All-target Clippy passed. The broad targeted Rust selection passed 502 tests;
the two failures (shared error-summary audit and missing-provider response)
were corrected, and the final 39-test selection passed, including exact golden
snapshots, whole-tree audits and application sorting before pagination.
Both new PostgreSQL tests passed against a migrated disposable PostgreSQL 16
instance: policy-history atomicity/retention/tenant isolation and descending
user search with tenant-scoped pagination. JSON sentinel inspection passed.
No full local Rust suite was run; remote CI was not invoked for this local-only
follow-up. Human screen-reader and moderated usability testing remain open.
