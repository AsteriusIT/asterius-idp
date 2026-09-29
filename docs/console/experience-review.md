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
| R02 | Shared guard for user identity/create, applications, settings, branding, providers, policy, schemas and group/resource dialogs. Existing architecture guard retained. Other short role/assignment dialogs retain existing behavior; extending them requires per-editor dirty semantics. |
| R03 | Resource/type withdrawal confirmed; shared dialog failure behavior fixed. New account removal disclosure/acknowledgement chosen instead of an extra GET/POST confirmation endpoint. Existing passkey/session security constraints retained. |
| R04 | Central 401 shell recovery and distinct fallback guidance for access/conflict/throttling/service/network failure. Writes are never automatically retried. Request URLs are explicitly restricted to the current-origin workspace API or read-only discovery documents. No expiry countdown without authoritative expiry data; no new return-URL parameter. |
| R05 | User/client ID and tab URLs, page titles and heading focus delivered. List scroll/filter history and links for every other entity are deferred; personal search terms are not persisted. |
| R06 | New labelled grouping and Architecture destination. Existing workspace/account menus retained; optional command palette declined to avoid competing Ctrl/Cmd+K shortcuts. |
| R07 | Loaded-row labels, contained accessible table scrolling and mobile minimum widths. Existing server pagination remains authoritative; global sort/search and alternative mobile cards require endpoint-specific work. |
| R08 | Existing Field associations retained; persistent errors and failed-dialog behavior fixed. Full field-linked public error summaries require typed backend field errors and are deferred. |
| R09 | Passkey live region, TOTP error-focus fix, route title/focus, dialog focus return and non-drag architecture controls delivered. Automated checks are limited evidence; real screen-reader/forced-colors/zoom checks remain acceptance work. |
| R10 | Tenant Help/Privacy/Terms connected end to end; new account templates translated. Console deliberately remains English; wider public translation and server-message catalogue migration are deferred, not labelled complete. |
| R11 | Shared final-layer dimensions and documentation reconciled; existing Geist/tenant palette preserved. No framework replacement. |
| R12 | Gutters, bottom clearance, modal viewport limits, reduced motion and a measured dark-hover contrast correction. Focused viewport/theme checks cover the schema editor; all-screen/palette qualification remains acceptance work. |
| R13 | Existing role-aware shortcuts, independent metrics and drill-downs retained; received timestamp added and oversized identity header reduced. Optional checklist deferred until real completion data exists. |
| R14 | Group member search replaces exact-username lookup; user summary width reduced. Existing role provenance and disable/identity confirmation retained. Effective access/last sign-in/cross-links are not inferred from incomplete data. |
| R15 | Existing expert creation/setup guide retained; optional additional wizard declined in this change. Secret copy feedback and exit warning delivered. Local checks remain distinct from actual sign-in. |
| R16 | Full-page schema editor, safe wording preview and withdrawal confirmations. Existing JSON validation remains; sample-payload evaluation and authorized client picker are deferred. Resource lifetime still shows exact seconds versus tenant default. |
| R17 | Existing provider callbacks, mapping instructions, SAML metadata and SCIM limitations retained. No new import/test/status endpoint or assumed connectivity. |
| R18 | Existing API-backed lifecycle and confirmations retained. Timeline/expiry forecasting declined without authoritative overlap/expiry data. |
| R19 | Dirty-state guard added; existing evaluator/rule/document editor and keyboard assurance ordering retained. Versioned publish/history/rollback and authoritative impact preview require backend work. |
| R20 | Audit UTC presets, export explanation and read-only inspection drawer delivered. Existing mail/signal retry/drop/resend behavior retained. Shareable event/delivery pages, cross-links and server-wide export progress are deferred. |
| R21 | Guarded tenant switching/settings/branding delivered. Existing capability tabs, creation next steps, suspend controls and local preferences retained. Additional production-rendered branding preview modes are deferred. |
| R22 | Object/connection list offers inspect/add/remove without drag, preserving review/apply semantics. Existing responsive stacked inspector retained; full mobile editor qualification remains manual acceptance. |
| R23 | Existing role-aware guides retained. No extra documentation product area or optional navigation search. |
| R24 | Provider button treatment, passkey live status and existing password fallback retained. Optional password reveal and identifier-first flow declined; no new credential collection step. |
| R25 | Local QR, manual key, confirm step, pending/restart and existing recovery constraints. No recovery-code capability invented. |
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

### Local verification, 2026-09-29

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
