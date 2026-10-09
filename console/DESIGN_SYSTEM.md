# Asterius console design system

Asterius is an identity administration workspace. Operators inspect users,
applications, credentials, access decisions, and Kubernetes permissions. Tenant
context, permission scope, and the consequence of an action must be clear.

## Reference priority and ownership

1. **shadcn / Base UI** supplies accessible primitives and source components.
2. **Untitled UI** is the primary product design reference for hierarchy,
   navigation, forms, spacing, and application surfaces.
3. **Shadcn Space and ReUI** supply component and composition patterns.
4. **This repository owns the resulting design system.** Imported source adopts
   our tokens, vocabulary, accessibility behavior, and CSP requirements.

Use [Untitled UI's theme documentation](https://untitledui.com/react/docs/theming)
as reference. Its React library is not a runtime dependency; Base UI is our
interaction foundation.

## Design direction

Keep tenant context above a navigation rail and a broad, left-aligned work
surface. Lists compare records; details group identity, credentials, and scope.
Actions sit beside the records they affect. Separate destructive decisions.

```text
Tenant context                                      Account
Navigation rail | Page title                      Primary action
                | Search and filters
                | Record table or grouped details
                | Pagination or contextual status
```

| Role | Light value | Purpose |
| --- | --- | --- |
| Canvas | #F9FAFB | Workspace backdrop |
| Surface | #FFFFFF | Forms, menus, and records |
| Text | #101828 | Primary information |
| Muted | #667085 | Supporting context |
| Border | #EAECF0 | Grouping and separation |
| Action | #4054E8 | Existing Asterius indigo |

Inter Variable is the interface font, self-hosted through Fontsource under the
SIL OFL with international Unicode subsets and weights 100–900. Technical values
use the system monospace stack. No remote font requests occur. Body text is
15px (the shared base size token is 16px), supporting text 14px, section headings 18–22px, and page headings 32px;
prefer weights 400, 500, and 600. Controls use an 8px radius, cards 10px, and
larger surfaces 15px. Spacing follows a 4px/8px rhythm. Shared requirements
include visible keyboard focus, dark mode, reduced motion, and 44px touch targets.

The plan was reviewed against the brief: keep Asterius's existing indigo instead
of copying a reference brand's purple; spend color on actions and access status;
favor tables and grouped sections over repeated metric cards. This foundation
changes tokens; individual screen information architecture remains to be designed.

## Repository ownership

- `src/tokens.css` owns colors, typography, spacing, radii, and table density.
- `src/tailwind.css` maps tokens to shadcn semantic utilities.
- `src/components/ui/` owns component behavior and variants.
- Screens compose these components without overriding their visual styles.

## Component sourcing

Run npm commands from `console/`. Inspect sources before installing:

```sh
npx shadcn@latest info --json
npx shadcn@latest search @shadcn-base -q field
npx shadcn@latest search @shadcn-space -q sidebar
npx shadcn@latest search @reui -q alert
npx shadcn@latest docs button
npx shadcn@latest view @shadcn-base/field
```

`components.json` configures the documented
[Shadcn Space registry](https://shadcnspace.com/docs/getting-started/how-to-use-shadcn-cli)
and [ReUI registry](https://reui.io/docs/registry). `@shadcn-base` explicitly
selects Base UI Vega components. ReUI also selects `base-vega` explicitly. Inspect imported source and licensing; use `@/` aliases, Lucide
icons, our tokens, and accessible composition. Registries are configured pattern
sources; no external block has been copied into a product screen in this change.

## Base UI foundation

All owned primitive wrappers and application menus now use Base UI. The default
shadcn style is `base-vega`. Legacy customized classes were preserved rather than
overwritten with stock components. Use `render` for element composition, with
`nativeButton={false}` and link semantics when a button renders an anchor.

`cmdk` and the repository's CSP-compatible toast are retained. There are no direct
Radix imports in console source or a direct `radix-ui` package dependency;
`cmdk` still brings transitive Radix packages. The entrypoint supplies its server
nonce through Base UI's CSPProvider. Portals share `console-overlay-portal` for
stacking above the navigation, with Positioner owning floating geometry.
Per-component migration evidence lives in `.migration/`; earlier reports record
the foundation step, while `project.md` records the completed migration.

Directory filter radio items explicitly close after a choice. Base UI's default
radio menu remains open, so this preserves the established one-choice workflow.
Dialog focus returns to its opener; failed destructive writes keep confirmations
open. FormSelect preserves API values including empty strings through its adapter.
Base UI focus guards immediately redirect keyboard focus. The account menu axe
check excludes only these guards (upstream issue mui/base-ui#4668); keyboard focus
return and navigation remain directly asserted.

Tabs follow Base UI's default manual activation: arrows move focus; Enter or
Space selects. `keepMounted` preserves editor state. Active and hidden styles
use `data-active` and `data-hidden`.

The admin console uses Inter. Server-rendered sign-in and branding font settings
retain their existing schema and are outside this console redesign.

## Compact forms

Owned shadcn Field/FieldGroup/FieldSet composition groups labels, controls, help
and errors. The shared `ui.tsx` Field adapter keeps existing IDs and validation
contracts. Application editors align labels in a 220px desktop column at widths
of 900px and above; smaller layouts stack naturally. Field groups use 16px gaps,
labels 13px, and helper/error text 12px. The guided setup summary keeps progress
and the full-editor action in one compact row. Existing content stays readable.

Controls are 36px high on desktop and 44px at mobile widths or with a coarse
pointer. Mobile input text is 16px to avoid focus zoom. Native fields and owned
Input/Textarea/Select wrappers share those dimensions. DurationInput composes
InputGroupInput and a noninteractive unit addon; labels retain the full unit.
Checkbox and Switch extend their pointer areas to 44px while keeping compact
visuals. Reduced-motion mode uses zero-duration transitions.

SettingSwitch uses Base UI's controlled checked/onCheckedChange API. Capability,
consent and managed-group toggles edit the draft; the existing Save action commits
it. Each control has an explicit label, associated description and disabled
state. Email verification remains a checkbox because it asserts verified identity
data. Rejected saves preserve inputs and expose associated errors.

New wrappers were adapted from CLI-inspected `@shadcn-base` Field, Label,
InputGroup, Textarea, Switch and Checkbox sources. Existing Button/Input/Separator
customizations were preserved when the CLI dry run proposed overwrites. Shadcn
Space's settings-form compositions informed grouping; no third-party product
block or paid Untitled UI code was copied. The repository owns tokens and density.

## Tenant settings layout

Tenant settings use the same centered 1480px page container as other screens; their configuration panels and inner fieldsets fill the parent width. The TOTP activation heading uses a small decorative phone and shield illustration from the existing icon set. Keep existing Inter typography and semantic neutral/accent tokens. Section introductions and explanatory copy retain readable line lengths; numeric duration controls remain compact within full-width rows.

Alternatives considered:

- Wide stacked sections: keeps tabs and assurance order visible, with ACR and methods side by side where space allows. Selected for fast policy review.
- Vertical settings navigation: would consume width beside the existing console navigation and requires changing established tab interactions.
- Collapsed assurance accordion: saves height but hides the method requirements administrators need to compare before saving.

Desktop assurance layout: `level header [reorder actions]` above `ACR value | four required-method choices`. Below 1200px the body stacks, and methods use two columns; below 600px choices stack. The authenticator policy splits status/actions from explanatory copy on wide screens. The token-method setting uses the same owned Base UI switch as other settings. All settings remain drafts until Save settings.

## Component exploration — 6 October 2026

Research scope: current official documentation, CLI registry source/dependency inspection, and the existing console source. These are adoption recommendations, not components already installed or browser-validated. Product source, dependencies and live deployment were not changed by this exploration.

### Recommended fit

| Priority | Component/pattern | Console workflow and benefit | Adoption decision |
| --- | --- | --- | --- |
| First | [shadcn Base Combobox](https://ui.shadcn.com/docs/components/base/combobox), informed by [ReUI Autocomplete](https://reui.io/docs/components/base/autocomplete) | Group membership, application owner and role selection: search and choose a real record in one control, showing username/email and scope together. | Own a shared EntityPicker. A record chooser requires a selected identity; free text alone is not a selection. Use autocomplete for suggestions where free text is valid. |
| First | [ReUI Filters](https://reui.io/docs/components/base/filters) pattern | Audit currently displays ten filter inputs. A compact Add filter menu and removable applied chips make the active query visible while preserving advanced references. | Compose a small filter bar from owned Popover/Field/Select/Input. Map only existing equality and date-range parameters; the API has no general boolean-query contract. |
| First | [ReUI Stepper](https://reui.io/docs/components/base/stepper) | Application guided setup: show completed/current/pending steps and provide a direct route back to a completed step. | Use controlled step state linked to existing setup tabs. Keep the compact header; mobile shows current step and count. Do not introduce a nested second tablist. |
| Next | [Shadcn Space role Select](https://shadcnspace.com/components/select) (`select-12`) | Group role assignment: explain Workspace versus application scope and show role context before assignment. | Adopt descriptive option rows using the owned Base Select. Actual role names/metadata come from the catalogue; demo Owner/Editor permissions must not be substituted. |
| Next | [ReUI Timeline](https://reui.io/docs/components/base/timeline) with [Untitled UI activity-feed hierarchy](https://www.untitledui.com/react/components/activity-feeds) | Policy publications and identity security events: scan actor, time, action and outcome; expand technical details on demand. | Adapt visual structure into an ordered read-only list. Keep policy restore confirmation and revision preconditions. Show only fields actually available from each endpoint. |
| Next | [ReUI Data Grid](https://reui.io/docs/components/base/data-grid) patterns | Users, applications and access reviews: column visibility, stable action column, compact rows and clear record status improve comparison. | Start with column visibility and table presentation in the owned DataTable. Server cursors remain authoritative. Sorting must be labelled as current-page-only unless the endpoint supports global ordering. Bulk actions require supported mutation semantics. |
| Later | [ReUI Code Block](https://reui.io/docs/components/base/code-block) patterns | Kubernetes YAML, OIDC JSON and policy revision comparisons: file labels, line numbers, bounded scrolling and exact-copy actions. | Enhance existing YamlView/JsonValue first. Inspect bundle and CSP behavior before adding Shiki; current YAML highlighting already avoids HTML injection. |
| Later | [ReUI Number Field](https://reui.io/docs/components/base/number-field) | Rate-limit values and durations: accessible increment/decrement controls can help repeat adjustments. | Pilot on an optional rate-limit field. Preserve empty-as-inherit, raw draft editing and server validation; avoid scrubbing security settings. Existing DurationInput remains sufficient for precise values. |

Priority reflects observed workflow friction and estimated integration effort, not a user study. Untitled UI remains the visual reference; these patterns inherit Asterius Inter, neutral surfaces, indigo actions, compact controls and full-width work areas.

### Evidence in the current console

- `src/groups.tsx` separates Find a user, a search action and a matching-users table. Application/role pickers use FormSelect. An entity picker can reduce steps while retaining the record ID used by mutations.
- `src/audit.tsx` renders agent, owner, user, grant, task, support reference, session reference, event type, from and until fields. `queryOf` sends nonempty existing parameters. A chip bar should distinguish draft edits from applied filters and retain UTC semantics.
- `src/clients.tsx` already has guided setup, a compact progress summary, tabs, draft protection and Previous/Continue behavior. A stepper should expose the existing state rather than add another state machine.
- `src/policy-history.tsx` uses expandable published versions and guards restore with the current revision. It already exposes version, rule count and updated time; actor data is not present in its Revision interface.
- Directory pages use opaque `next_cursor` values. A numbered-page pagination demo would imply information the API does not supply.
- `src/components/yaml-view.tsx` already supplies line count, exact-source copy, keyboard scrolling and React-rendered highlighting. A new code-block dependency needs a concrete improvement beyond those capabilities.

### Registry inspection findings

Sources were read through `npx shadcn@latest view`; nothing was installed. `components.json` selects ReUI `base-vega` and existing owned wrappers were preserved.

| Inspected item | Finding | Consequence |
| --- | --- | --- |
| `@reui/stepper` | 474 source lines; Base mergeProps/useRender; registry dependencies empty; internal list uses tablist semantics. | Relatively contained source, but adapt semantics to the existing guided navigation. Rewrite `cn` import to the owned utility. |
| `@reui/timeline` | 258 source lines; Base mergeProps/useRender; registry dependencies empty; includes active-step state. | Good layout source. Historical events should not imply workflow completion; use ordered event semantics. |
| `@reui/autocomplete` | Base Autocomplete; ScrollArea dependency; placeholder icon import and stock dark/size classes. | Resolve icon to Lucide, aliases to owned paths and density/colors to tokens. Distinguish free-text suggestions from record selection. |
| `@reui/data-grid` | Returned 12 source files, with TanStack Table/Virtual and dnd-kit dependencies; table, virtualization and cell-selection modules are substantial. | High integration cost. Inspect exact dependency versions and begin with selected patterns. Runtime geometry needs browser verification under our CSP; its presence alone does not prove incompatibility. |
| `@reui/filters` | Returned 14 files and dependencies including date-fns, Cascader, builder and drag modules. | The audit screen does not need the full boolean builder. A small repository-owned adapter fits the API better. |
| `@reui/code-block` | Shiki dependency and two substantial files, lazy grammar/theme loading and runtime styles. | Measure route chunk impact and validate exact-copy/CSP behavior before adoption. |
| `@reui/number-field` | 273 source lines; Base NumberField and Label dependency. | Small pilot candidate, with explicit handling of nullable/empty draft state. |
| `@shadcn-space/combobox-10` | Uses owned-style Command/Popover composition with inline creation and demo label colors. | Search/selection composition is useful. Do not enable implicit user or role creation in assignment workflows. |
| `@shadcn-space/select-12` | Descriptive role options; current demo setter drops falsy values; fixed demo colors and role permissions. | Preserve our empty Workspace option and actual catalogue values; use semantic styling and real metadata. |

Registry source sizes are inspection evidence, not bundled byte sizes or performance benchmarks. Public availability does not establish the license of every Pro block; use exact component licensing when copying source. Sources: [ReUI registry](https://reui.io/docs/registry), [Shadcn Space license](https://shadcnspace.com/license).

### First pilot definition

Start with EntityPicker in the existing group-membership add form. Input searches the current tenant directory; each result shows username, email and a secondary ID when names collide. Selection fills a stable user ID, and a separate Add member action commits it. Keep loading, no results, request failure and retry visible. A later query invalidates the prior selection; a stale response cannot overwrite a newer query. Existing membership and permission checks remain server-owned.

Compare it with the existing search-plus-table experience using task completion, incorrect-person selection and keyboard effort. Verify keyboard selection/Escape/focus return, duplicate display names, stale searches, permission denial, failed add preserving the chosen person, dark mode, narrow screens and the console CSP. That makes the first adoption a measurable workflow improvement.

For the second pilot, keep Audit's Apply filters action, collapse uncommon references into Add filter, and show chips for the applied query above results. For the third, map a compact setup stepper to existing guided tabs, preserving all drafts and the final review before registration.

## Adopted workflow components — ast-pr8l

The first exploration pilots are implemented as repository-owned compositions:

- `components/ui/combobox.tsx` adapts the inspected shadcn Base Vega Combobox input/list/positioner composition. Existing Input and Button wrappers were preserved when the CLI dry run proposed overwrites. The popup uses owned tokens and the existing portal stacking boundary.
- `components/entity-picker.tsx` owns asynchronous directory selection. Editing the query invalidates the selected ID and previous results. Search generations are scoped by effect cleanup; late responses cannot replace a newer query. Cursor pages load explicitly, with deduplication by ID. Failure, retry, loading and no-results states remain visible. Selection does not write; the group's explicit Add member action does. A rejected write retains the choice. Escape dismisses the picker before the parent dialog.
- `components/audit-filter-bar.tsx` adapts the ReUI filter-chip pattern to existing flat parameters. Event type, User, From and Until are immediately available; Add filter exposes the other references. Draft changes remain unapplied until Apply filters. Removing an applied chip clears only that parameter in the applied query and draft, preserving other draft edits. Export follows the applied query. Older list or cursor responses cannot replace a newer audit query.
- Guided application tabs adopt the ReUI stepper progression pattern: numbered steps, current-step emphasis and earlier-step tint, with the existing progress summary. One Base tablist owns keyboard navigation. Earlier steps are not marked validated/completed; progression is navigation, and registration still requires the final review action. Switching tabs or returning to the full editor retains drafts.

These changes add no runtime package dependencies, new endpoints or third-party product blocks. Inter, semantic light/dark tokens, compact controls and full-width tenant settings continue to define the product. The remaining research candidates have not been installed by this change.

### Role, publication and directory pilots (`ast-a8bk`)

Shadcn Space [select-12](https://shadcnspace.com/components/select) informed two-line role options. Owned `SelectItem` keeps description text outside `ItemText`, so triggers retain the role name. Only actual catalogue descriptions appear; workspace values still encode/decode the API's empty string. Group and account assignment catalogues clear while loading, reject older scope responses, expose retry and retain rejected selections. Existing searchable account role radios remain useful for large catalogues.

ReUI [Timeline](https://reui.io/docs/components/base/timeline) informed the publication rail. `PolicyHistory` uses a semantic ordered list, actual version IDs, rule counts and timestamps, and the latest-publication badge. It deliberately has no workflow step state or invented actor. Expandable JSON and revision-checked restore confirmation retain their original behavior.

ReUI [Data Grid](https://reui.io/docs/components/base/data-grid) column visibility informed an owned Base Popover/Checkbox control on account and application directories. Identity, status and actions stay visible. Choices live in the authenticated shell's `ViewMemory`, survive cursor pagination and reset on demand. Hiding the sorted column clears that sort. Visibility never changes server parameters, loaded-result sorting, permissions or cursor handling; no TanStack grid dependency was added. Keyboard Escape restores trigger focus; mobile controls retain 44px rows.

### Code and optional numeric pilots (`ast-pf5f`)

[ReUI Code Block](https://reui.io/docs/components/base/code-block) informed the document toolbar and quiet line-number gutter. The owned `CodePanel` composes existing Badge/Button components and existing React-rendered JSON/YAML tokenizers. It labels the actual document, shows format/line count, bounds source scrolling at 360px and retains keyboard focus. Gutter markers are hidden from assistive technology and text selection; Copy reads the original source including YAML document separators and trailing newlines. Existing clipboard refusal feedback remains explicit. `JsonSourceView` also preserves the already serialized saved policy revision. No Shiki runtime or HTML injection was introduced. The inspected registry code-block source comprised 3,404 lines across two files; this pilot needs only the presentation pattern.

[ReUI Number Field](https://reui.io/docs/components/base/number-field) and [Base Number Field](https://base-ui.com/react/components/number-field) informed explicit increment/decrement affordances. `OptionalNumberInput` composes owned InputGroup and Base-backed buttons. Its string-valued draft contract keeps incomplete, decimal and out-of-range edits visible; blur does not format or clamp them. Field errors and server Save refusals remain authoritative. Empty means inherit the deployment ceiling, decrement starts from that ceiling, and an increment at the ceiling is a no-op. An Inherit action clears an override. Invalid values disable stepping and remain manually editable. Input arrow keys use the same one-unit boundaries; wheel scrubbing and dragging do not change settings.

The rate-limit pilot sits in Tenant settings → Rate limits. A 36px desktop input and 44px mobile step buttons preserve compact forms while keeping deployment bounds and saved effective maxima visible. A shared InputGroup disabled selector now follows the input's disabled state: a ceiling-disabled step button must not dim an otherwise editable input. Neither step controls nor inheritance changes write until Save settings. No runtime dependencies were added or existing wrappers overwritten.

## Directory and activity inspection (ast-azwq)

Users and Applications show only applied search/status values as removable chips.
Clearing status preserves an unfinished search; clearing search resets its draft;
all filter changes start at the first cursor. Session tables sort loaded rows,
show loaded/active counts and offer an Active only Base switch. Revocation always
uses the selected row's original session key, including after sorting/filtering.
Refused account mutations use an error alert, never a success status.

Access overview includes up to five recent visible sign-in events from its
existing bounded audit reads. Actual outcomes and timestamps are retained;
opaque rows are omitted and audit permission is required. Last recorded sign-in
still means the latest successful event, even when newer failures are visible.

CodePanel has a labelled Base switch for wrapped versus horizontally scrollable
source. Wrapping starts enabled and never alters copied source. InlineSwitch
composes owned Field/FieldLabel/Switch with a 44px interaction row. CopyValue
resets feedback when its value changes, disables duplicate pending copies and
ignores completion after value replacement/unmount, including acknowledgements.

## Further component exploration and adoption — 6 October 2026 (`ast-0c4o`)

The original recommendations above describe the research snapshot; the adoption
sections record what now exists. This pass adds three small reusable patterns:

| Pattern | Evidence and adaptation | First product use |
| --- | --- | --- |
| Empty composition | CLI-inspected [shadcn Base Empty](https://ui.shadcn.com/docs/components/base/empty). Owned Empty/Header/Title/Description/Content replace bespoke EmptyState markup. Quiet compact spacing, semantic tokens and an accessible title; no stock illustrations or extra media. | Shared empty states; Users/Applications offer reset only when filters are applied. Reset clears query/draft/status/cursor and makes no mutation. |
| Segmented choices | CLI-inspected [Base Toggle Group](https://ui.shadcn.com/docs/components/base/toggle-group) and Toggle. Owned wrappers retain roving keyboard focus and pressed states. A controlled required preference ignores the empty value from deselecting its current choice. | Appearance and table density in Preferences; existing browser persistence and theme transition suppression remain authoritative. |
| Revealable secret entry | [Input Group](https://ui.shadcn.com/docs/components/base/input-group) action-addon composition with owned InputGroupInput/Button. Reveal changes only presentation, remasks on leaving the group, clearing or disabling, and retains exact raw drafts. | Initial user password and upstream OIDC client-secret replacement. Empty replacement still keeps the stored secret; stored credentials are never read back. |

Registry searches did not identify a focused ReUI empty/password component;
the Base foundations already fit these workflows. The CLI dry run proposed
three new source files and a registry `cn` dependency. We adapted imports to
our existing `@/lib/utils` and copied only inspected source: no dependency or
existing primitive was overwritten. ToggleGroup spacing uses bundled data-state
CSS instead of the registry's inline custom-property style, preserving strict CSP.

Keep Inter and left-aligned form hierarchy. Empty results explain the current
filter rather than implying a global directory count. Preferences show their two
choices directly rather than adding dropdowns. Secret inputs offer neither an
invented strength score nor automatic generation/copying; explicit Save remains
the write boundary. Mobile choice/reveal actions retain 44px interaction areas.

## Access-review component adoption (`ast-hl81`)

Five patterns extend the 6 October exploration into the existing governance workflow:

1. **Ownership comparison table.** ReUI [Data Grid](https://reui.io/docs/components/base/data-grid) column/selection patterns inform the owned DataTable. Standing source, subject, selection, state and actions remain visible; Owner may be hidden. Sorts apply only to loaded records, with no server order or cursor changes. The API's record key remains the selection identity.
2. **Selection bar.** A quiet in-flow group shows actual selected record count and a Clear selection action. Selection changes are local; the existing bounded Create review form remains the only snapshot write. Disabled ownership records cannot be selected. There is no all-pages select or bulk apply action.
3. **Review history table and state badge.** Created/deadline columns sort loaded timestamps; recorded cancelled/completed flags map to badges, otherwise Open. These labels describe review records, not whether an access decision will be authorized. Original Open review loading and item paging remain unchanged.
4. **Character-count textarea.** InputGroupTextarea and a footer counter show the existing 1,000-character browser limit for decision reasons. The label/hints/counter are associated, raw drafts are retained, and only reaching the limit creates a polite announcement. No truncation or normalization beyond the existing native maxLength behavior is added.
5. **Snapshot evidence accordion.** CLI-inspected [shadcn Base Accordion](https://ui.shadcn.com/docs/components/base/accordion) supplies keyboard disclosure. Each affected account starts expanded and shows actual standing/temporary-source counts and account state. Observed time, protected-source warning and independent-source explanation remain visible. Collapse affects presentation only and leaves reason drafts and apply confirmation intact. Apply refusals are also rendered inside the retained confirmation dialog for retry/cancel.

ReUI's complete grid introduces TanStack/virtualization/drag modules already
reviewed in the exploration; this pass reuses our smaller owned comparison table.
The queried ReUI textarea/accordion registry names did not resolve, so the owned
Textarea/InputGroup and CLI-inspected Base accordion supply the foundation.
The accordion dry run proposed one new file and `cn`; imports map to existing
utils and Lucide, with no registry placeholder icons or new dependency. Panel
animation/custom-height styles are omitted in favor of ordinary Base disclosure
and the console's reduced-motion/CSP requirements. Inter, semantic tokens,
compact spacing and contained mobile table scrolling remain the visual contract.

## Select consistency and further block exploration (`ast-858r`, 6 October 2026)

All console choice menus now compose the owned Base Select/FormSelect. Native
selects in Application sensitivity, hypothetical evidence availability/value,
and the four policy simulation selectors have been replaced. Keep exact API
values, classification revision checks, write scopes and explicit confirmation.
An empty choice remains the raw empty string in the Base control, which lets
browser required validation block an incomplete form and focus its visible
trigger. Never prefix the internal value: a nonempty sentinel defeats required
validation. The adapter's optional named hidden input still submits the raw value.

Retain Inter, the existing neutral surface/indigo focus tokens and compact menu
spacing; use option descriptions only when they explain a choice. Classification
has no speculative severity badge: Standard/Sensitive/Critical are stored policy
inputs, not live risk findings. The menu is read-only without client write scope,
and stale revision refusals disable editing until a successful reload.

Further block candidates were checked against current official docs and CLI source:

| Pattern/source | Best console fit | Adoption decision |
| --- | --- | --- |
| [ReUI Base Stepper](https://reui.io/docs/components/base/stepper) | Existing guided application setup: Registration, Credentials, Resources, Review. | Reuse its title/status layout with the current guided progress and Base Tabs. Inspected source derives completed from step position and uses global step IDs; completion must instead come from validated fields, and IDs must be unique per instance. Do not replace the current guards with positional success. |
| [ReUI Base Filters](https://reui.io/docs/components/base/filters) | Compact audit filter editors with visible applied chips. | Adapt the field → value → apply interaction to current supported query parameters. Source inspection found 14 files plus Cascader and date-fns dependencies; a full boolean builder exceeds the existing API. Keep the smaller owned FilterChips rather than add unsupported AND/OR groups or operators. |
| [shadcn Base Sheet](https://ui.shadcn.com/docs/components/base/sheet) | Read-only audit event and session metadata inspection beside a list. | Strong candidate for a future bounded record inspector. CLI source composes Base Dialog; use existing tokens/overlay conventions, a titled panel, contained scrolling and focus return. Full-width on mobile; only supplied record fields, with load/error/empty states. Keep credential flows and confirmation dialogs in their current explicit flows. |

No additional library or stock block is installed by this exploration. Existing
primitives remain repository-owned. Future block adoption must verify API support,
CSP, mobile overflow, keyboard navigation and draft retention before rollout.

## Page hierarchy implementation (`ast-yvwx`, 6 October 2026)

All 29 registered destinations were reviewed through route definitions, page
components, existing scenarios and a controlled unavailable-read sweep. Keep one
screen title, distinct section headings, then field labels. Persistent edits use
task pages, collections use tables, and read-only inspection uses titled sheets.
Inter and the shared semantic tokens remain the console identity. Light mode
retains indigo actions; the neutral dark theme uses grayscale actions and focus.

Screen no longer renders the “On this page” section navigation. Page headings,
tabs and existing task panels provide the hierarchy without an additional strip.

Authorization-details registration separates identity/consent fields, JSON schema
definition, sample validation and consent preview. An owned JSON input group offers
explicit formatting, syntax feedback and line count. Syntax is not schema validity:
server validation remains authoritative. Raw drafts survive refusals; formatting
is disabled for invalid, read-only or busy controls. The same editor improves the
policy draft and hypothetical simulation context. Registered schema table cells
now open a saved-document sheet rather than embedding a long JSON string.

The [ReUI Stepper](https://reui.io/docs/components/base/stepper) title/description
pattern is adapted to existing Base Tabs with one tab list and unique Base IDs.
The six steps are actual registration tasks. Position never means fields are
valid or saved. Review-before-registration, draft retention and full-editor
switching remain unchanged.

[ReUI Filters](https://reui.io/docs/components/base/filters) informs bounded,
explicit Apply/Cancel value editors on existing applied audit chips. Editing one
field preserves unrelated applied filters and unapplied drafts. The field chooser,
flat API serialization, stale-response guard and applied export remain authoritative.
Unsupported boolean-query operators are not introduced.

[Base Sheet](https://ui.shadcn.com/docs/components/base/sheet) is reused for schemas,
session metadata and the existing audit drawer. Sheets retain list context, use
contained scrolling/full mobile width, and preserve Base dismissal/focus return.
Session inspection reads only loaded metadata; revocation remains the separate
existing action. Credentials and token flows stay in their established task pages.

### Decisions for every screen

| Screen | Hierarchy and component decision |
| --- | --- |
| Overview | Scope-aware summaries and Start here precede supporting activity; summaries keep their own headings. Unknown aggregates remain unknown. |
| Users | Directory → account tabs. New loaded-session metadata sheet preserves exact-ID revocation in the table. |
| Temporary privileges | Inventory → entitlement → eligibility/activation evidence. Distinct panel headings organize long details; independent approval stays explicit. |
| Groups | Directory → profile → Details/Members/Application roles. Hidden tab headings never become section destinations. |
| Applications | Directory → focused editor. Numbered title/description workflow steps preserve one tab list and registration review. |
| Token test console | Actual application/user selection → explicit issuance → token inspection. Keep browser-only data and Clear; encoded tokens do not use JSON formatting. |
| Outbound provisioning | Destinations → connection state → selected sources → assignments. Section links help long pages without implying preview equals successful delivery. |
| SCIM provisioning | Connection values → stored client check → supported operations. Three tasks retain distinct headings and copyable endpoints. |
| Kubernetes access | Cluster inventory → authentication/profile → saved configuration/terminal → temporary access. Section links aid detail pages; saved-revision provenance remains visible. |
| Sign-in providers | Provider inventory → focused connection editor. Discovery status and actual sign-in remain distinct; replacement secrets stay separate. |
| Resource servers | Audience inventory → explicit registration/edit. Keep scopes and introspection clients as fields, with confirmed withdrawal. |
| Architecture builder | Flow inventory → specialized canvas/object/review/resources workspace. Retain specialized inspector/text alternative; generic navigation applies to the inventory. |
| Authorization details | Types → full-width registration workspace; separate schema/sample/consent panels, JSON toolbar and saved-schema sheet. |
| Access reviews | Ownership → history → selected evidence/decision/apply. Section links follow visible panels; bounded selection and independent-source context remain authoritative. |
| Governance findings | Scope → observed findings → human review proposal. Large finding collections intentionally omit the generic section menu. |
| Roles | Workspace/application scope → catalog → role editor. Keep actual descriptions and assignment provenance, without inferred state. |
| Tenants | Deployment directory → tenant settings. Keep reach/identity explicit and retain confirmed creation/suspension. |
| Signing keys | Key set → publication/rotation → staged lifecycle actions. Section links improve the long page; private material stays excluded. |
| Federation keys | Published metadata → pinned anchors. Keep public document panels and staged trust editing; publication does not imply peer validation. |
| SAML IdP key | Certificates → key setup → trusted providers. Three task sections become navigable; lifecycle/import confirmation remains separate. |
| Shared signals | Streams → receiver/upstream configuration → delivery evidence. Section links follow visible panels and original retry/write scopes. |
| Mail delivery | Invitations → message outcomes. Keep recipient/content privacy; two sections need no extra navigation layer. |
| Audit trail | Concise context → filters/applied chips → records → event sheet. Added isolated chip value editing and a wider read-only evidence inspector. |
| Access policy | Rules/document/history → focused draft → simulation. Shared JSON tooling preserves publication conflicts and hypothetical labels. |
| Tenant settings | Capability/lifetime/consent/session/authentication/rate-limit/endpoint tabs retain full-width fieldsets and one Save boundary. |
| Branding | Saved preview → explicit edit with identity/palette/layout/support sections. Section headings organize long edits; sign-in branding stays independent of console paint. |
| Preferences | Direct appearance/density ToggleGroups retain browser persistence. Two choices need no drawer or section menu. |
| Workspace health | Actual saved-configuration checklist and Refresh checks. Unknown/failed checks are never converted into readiness percentages. |
| Help & guides | Search/tasks → integrations → terms/failure guidance. Section links support long references while retaining scope-aware task links. |

Validation separates production-bundle interactions with controlled replies from
backend integration. Loaded-record edit/filter/sheet cases cover drafts, payloads
and refusals; the all-destination sweep checks hierarchy and mobile/dark refusal
states. It does not claim every production workflow was exercised. No dependency
or existing primitive was overwritten by registry installation.


## Neutral dark theme and surface spacing — 6 October 2026

Dark mode uses a grayscale surface hierarchy rather than blue-tinted neutrals.
Inter and existing compact dimensions remain unchanged. Light mode retains its
indigo accent; dark mode uses near-white actions and gray selection surfaces.
Muted green, amber and red remain reserved for outcome and warning information.

| Role | Dark token | Value |
| --- | --- | --- |
| Navigation and header | `--backdrop`, `--rail` | `#101010` |
| Workspace | `--bg` | `#141414` |
| Cards, fields and overlays | `--card`, `--surface` | `#1c1c1c` |
| Secondary surfaces | `--surface-sunken` | `#262626` |
| Boundaries | `--line` | `#3a3a3a` |
| Main / secondary text | `--fg`, `--muted` | `#fafafa` / `#a3a3a3` |
| Actions / focus | `--accent`, `--info` | `#e5e5e5` / `#c4c4c4` |

Filled cards retain their border, 20px vertical padding, and 24px horizontal
header/content insets (16px on narrow screens). Being inside a tab does not strip
those insets. Intentional flat sections remain transparent with no card padding;
application editor roots follow the same rule. An opaque surface must never be
flattened simply because it appears inside a tab. Menu shadows and identity
avatars use shared tokens so they follow the theme.

The account Access overview regression checks the actual filled card's insets,
border and surface in both themes at mobile and desktop widths, alongside audit
outcomes and access guards. The complete console experience suite checks dark
forms, pickers, dialogs, sheets, warnings, keyboard operation and accessibility.
The destination sweep covers all 29 routes in light desktop and dark desktop /
mobile refusal states; it does not simulate every successful backend workflow.


## Tools and contextual page illustrations — 6 October 2026

Token test console is a top-bar tool, accessed through the flask icon and a
keyboard/pointer tooltip. The sidebar omits it; the route and issuance permission
remain unchanged. The tool uses the standard page width: a compact issuance
panel followed by encoded-source and decoded-claims cards. Searchable active
application/user pickers retain independent server searches and explicit
selection. Source editing uses the owned InputGroup textarea with copy/clear,
character count and malformed-JWT feedback. Decoded JSON/YAML stays local and
unverified; issuing remains a deliberate server action.

Shared PageHeader uses a small decorative layered line illustration derived
from the route's owned navigation symbol. All destination headers have a
contextual symbol; individual account headers retain their identity avatar.
The motif uses existing semantic surfaces and no external assets, animation or
new dependency. At narrow widths it shrinks and aligns beside the title; header
actions stay on a separate row. Meaning remains in titles and accessible links.

The concise user guide at `docs/console/README.md` covers all 29 destination
features, account/settings tabs and supporting integration tools, with why/how
instructions. Root and console READMEs link to it; developer documentation stays
separate from operator instructions.

## Conditional access builder (`ast-j9wd`)

The access-policy task page offers a structured conditional-scope builder and an
advanced JSON view over one canonical draft. Existing Edit policy opens JSON;
Build conditional access opens the builder. Switching views keeps the builder
mounted and retains draft text and scope selection. Base authorization rules
remain separate from conditional rules. The rollout table remains visible while
editing and distinguishes published mode from draft mode.

`ConditionalPolicyBuilder` owns scope targets, evidence requirements, network
zones and nested All/Any/Not rule compositions. It composes owned Field/FieldSet,
FormSelect, Checkbox, Combobox and DurationInput; it adds no primitive library or
parallel theme. Application choice uses registered IDs and cursor pagination.
Unresolved values and unsupported expressions remain visible and lossless; the
JSON editor is their explicit editing path. The tenant ladder supplies assurance
values. Age conditions follow the server's 60–86400-second bound, separate from
the wider hypothetical simulation-example range. Empty All/Any semantics are
stated, and removing a complete condition requires confirmation.

Simulation offers an explicit saved/draft policy choice, defaults to draft on
entering editing, and uses the existing server endpoint. Changed inputs invalidate
results and late responses cannot replace a current result. Hypothetical evidence
remains labelled. Publication review shows changed scope fields and expandable
complete before/after documents, binds the exact reviewed document and revision,
and retains drafts on conflicts. Client sensitivity remains a separate audited
application setting. No local evaluator or second policy-language validator is
introduced; the server owns permission and policy validity.


The refinement (`ast-xprt`) groups the builder into numbered target, condition,
and rollout sections within a readable 1120px maximum width. Checkbox choices
compose horizontal Field, Checkbox and FieldLabel rows; they must never use the
vertical text-field adapter, whose full-width children stretch checkbox roots.
A selected card has a checkbox and a border cue, and its label remains a large
click target. Protocol IDs are secondary text. Browser sign-in has an explicit
shortcut selecting both authorization and code redemption while retaining other
selected flows. Evidence/remedy/network settings and rule selectors/reasons use
native disclosures with configured-value summaries; collapsing preserves state.
Condition leaves use two columns only when their own container is wide enough.


Refinement verification (9 October 2026):

| Severity | Location | Before | After | Why |
| --- | --- | --- | --- | --- |
| HIGH, resolved | `src/conditional-policy-builder.tsx`, `src/styles.css` | Full-width checkbox children and overlapping labels | Horizontal 16px checkboxes, contained labels and 60px choice rows | Keep control geometry and hit areas independent of text-field sizing |
| MEDIUM, resolved | `src/conditional-policy-builder.tsx` | Advanced fields competed with applications and conditions | Three numbered sections, concise labels and native disclosures | Group by the operator’s task and show complexity when needed |
| LOW, resolved | `src/conditional-policy-builder.tsx`, `src/styles.css` | Long path labels and vertically stacked condition leaves | Short visible buttons, unique accessible names and container-aware paired fields | Preserve context while reducing visual noise |

Browser coverage includes empty and selected choices, keyboard focus/Space,
label clicks, application loading/retry/pagination, read-only access, malformed
and preserved JSON, nested groups, publication/conflict states, desktop light,
390px dark and WCAG A/AA scans. Checkbox/label geometry is asserted at 1792px,
1280px and 390px. No new animated transition was introduced. Pointer hover and
motion replay are not verified interactively. Approve the inspected coverage;
no blocking UI-polish finding remains in that coverage.
