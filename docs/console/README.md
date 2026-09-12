# The console's design

The admin console is drawn in the language `7f428d2` gave the user-facing
pages: one warm neutral backdrop, hairline borders, an 8px card and a 6px
control, 44px targets, and a single indigo accent spent on one decision per
view. This file says where the values live, what the pieces are called, and
what a screen is expected to do with them (`ast-fe39`, rebuilt on **shadcn/ui**
by `ast-gore`).

Four things changed in `ast-gore` and each has a section below: the components
are shadcn's, copied into `console/src/components/ui/`; the theme is **light by
default** with a remembered toggle; the navigation is **one sidebar** and
nothing else; and that sidebar carries a **tenant selector**. The policy the
whole thing is served under did not change, which took measuring — see
[Under the policy](#under-the-policy).

The pictures beside it are the same eight screens before the migration
(`before/`) and after it (`after/`), taken by the same browser at 1280×900 by
`e2e/tests/console-shots.spec.ts`. A ninth, `after/tenants.png`, has no
"before": the screen did not exist until `ast-l5bl`, and it is photographed as
the deployment administrator because nobody else is shown the link.

## The tokens

`console/src/tokens.css` is the whole palette, and it is a **checked copy** of
the `:root` rule of `crates/web/templates/style.css`.

A copy, because the two consumers cannot read the same bytes: `style.css` is
`include!`d into the one nonce-carrying `<style>` element of every
server-rendered page, while the console's CSS is bundled by Vite into a
content-hashed file the entry document links with the response's nonce. One is
a Rust `include_str!` at `cargo build` time, the other an import resolved by a
bundler that is not running then.

Checked, because `asterius_web::theme`'s
`the_console_declares_the_same_design_tokens` parses the first `:root` rule of
both files and fails on any drift. A duplicate nobody compares is a fork; a
duplicate a test compares is a cache.

| Layer | Tokens |
| --- | --- |
| Shared with the pages | `--fg` `--bg` `--muted` `--line` `--accent` `--accent-fg` `--danger` `--card` `--backdrop` `--radius` `--ctl` `--tap` `--space` `--shadow` `--font` |
| Spacing | `--space-1` … `--space-6`, all multiples of the shared 8px step |
| Radii | `--radius-lg`, `--radius-pill` |
| Type | `--text-xs` … `--text-2xl` |
| Surfaces | `--surface`, `--surface-sunken`, `--rail`, `--overlay` |
| State | `--success` `--warning` `--info` and their `--tint-*` |
| Elevation | `--shadow-sm`, `--shadow-lg` |
| Motion | `--motion-fast` `--motion` `--ease` |
| Layout | `--rail-width`, `--content-max` |

Two deliberate differences from `style.css`:

* **`--font`** is the page stack *without* Geist. The pages are served that face
  from this deployment's own origin at a hashed path whose URL carries the
  request's mount prefix (`asterius_web::brand`), and the `@font-face` for it
  lives in `base.html` — a URL a bundle cannot know. The console takes the tail
  of the same stack, so nothing is fetched from an outside origin;
  `font-src 'self'` would refuse it anyway. The test asserts exactly this
  relationship rather than skipping the token.
* **A dark scheme, behind a class.** `style.css` has none on purpose
  (`ast-vn7`): a tenant's palette is appended to it, and a
  `prefers-color-scheme` block would substitute colours that tenant's contrast
  check never saw. The console is not themed by a tenant — it is this
  deployment's own tool — so it carries one, in the console layer only. Since
  `ast-gore` it is a `.dark` **class** rather than a media query: the scheme is
  a choice this administrator made, not a setting their operating system made
  for them. See [The theme](#the-theme).

## The constraints

* **Nothing inline.** The policy is `script-src 'nonce-…' 'strict-dynamic'` and
  `style-src 'nonce-…'` (ADR-0009). One stylesheet, linked by the entry document
  with the response's nonce, and no `style=` attribute anywhere in the bundle.
* **No `@import`, no `url(`.** `tokens.css` is imported by `main.tsx` so Vite
  concatenates it into that one file; an `@import` that survived bundling would
  be a stylesheet fetched by a stylesheet, carrying no nonce. `url(` would be a
  request to an origin nobody reviewed.
* **No *runtime* dependency this repository has not read.** `ast-fe39` wrote
  the components by hand and gave the reason: "a UI library is a dependency
  tree inside the most privileged page this deployment serves". `ast-gore`
  keeps the reason and changes the answer, because shadcn/ui is not a
  dependency — the components are **copied into `console/src/components/ui/`**,
  reviewed like the rest of the tree and edited where this deployment
  disagrees. Two such edits so far: the sidebar's `sidebar_state` **cookie** is
  gone (it would have been written at `path=/` on the origin that serves the
  token endpoint, without the `__Host-` prefix every other cookie here carries)
  and lives in `localStorage`; and Sonner is not installed at all, for the
  reason [Under the policy](#under-the-policy) gives.

  What is underneath is Radix, and Radix is **behaviour, not paint**: focus
  traps, roving tab indexes, `aria-*` wiring, dismiss semantics. That is the
  half `ConfirmDialog` had to get right by hand, and the half every dialog
  after it would have had to get right again.

## Tailwind, and where the colours come from

`console/src/tailwind.css` is the only place shadcn's vocabulary meets this
deployment's palette, and every entry in its `@theme inline` block is a
`var(--token)` rather than a value:

| shadcn says | it reads |
| --- | --- |
| `background` / `foreground` | `--bg` / `--fg` |
| `card`, `popover` | `--card`, `--surface` |
| `primary` / `primary-foreground` | `--accent` / `--accent-fg` |
| `muted` / `muted-foreground` | `--surface-sunken` / `--muted` |
| `destructive`, `success`, `warning`, `info` | `--danger`, `--success`, `--warning`, `--info` |
| `border`, `input`, `ring` | `--line`, `--line`, `--accent` |
| `sidebar*` | `--rail`, `--fg`, `--accent`, `--tint-accent`, `--line` |
| `radius-sm/md`, `radius-lg/xl` | `--ctl`, `--radius` / `--radius-lg` |

shadcn's own `globals.css` ships *values* for those names — a neutral palette
that is not this product's — and `npx shadcn add sidebar` appended a set of
them; they were deleted. `@theme inline` is what makes the mapping a reference
rather than a copy, so a palette change in `style.css` still moves the console,
and `the_console_declares_the_same_design_tokens` still fails if the two drift.

`--muted` is the one name that collides: it is quiet *text* in `tokens.css` and
a quiet *surface* in shadcn. The mapping is where they are told apart; neither
file redefines the other's.

The purge is Tailwind v4's own content detection over `console/src`, and
`cssCodeSplit: false` keeps the output one file — which is what lets the entry
document link one stylesheet with one nonce.

`styles.css` — the screen-level classes nine screens still use (`.stack`,
`.muted`, `.detail`, `.table-wrap`, the form rules) — is wrapped in
`@layer components`. Cascade layers, and the rule that an *unlayered*
declaration beats every layered one: a `button { … }` outside any layer would
have won against `bg-primary` on a shadcn `Button`, and the console would have
had two button designs fighting with the loser being the one that was chosen.

## The components

The app-level six are in `console/src/ui.tsx`, built on the copies in
`console/src/components/ui/`. None of them talks to the network; a component
takes what to draw and gives back what was pressed, which is what made both
migrations a change of markup rather than a change of behaviour.

| Component | What it is |
| --- | --- |
| `Screen` | One screen: `<h2>`, a sentence, and the actions that apply to all of it. The shell owns the `<h1>`. |
| `Panel` | One section, as a card, labelled by its own `<h3>` through `aria-labelledby`. |
| `CenteredCard` | The pages' centred card, for the three views that are one sentence: loading, signed out, could not start. |
| `Button` | `primary` (once per view), `secondary` (the default), `danger`, `ghost`; `small` for a table row. |
| `Actions` | A row of controls, the decisive one last. |
| `Field` | Label, control, help, and the server's refusal at the field — wired with `aria-describedby` and `aria-invalid`. |
| `Message` | `success` and `info` are `role="status"`, `error` is `role="alert"`. Mark, tint and rule, never colour alone. |
| `Badge` | A state as a word first: `ok`, `warn`, `bad`, `accent`, neutral. |
| `DataTable` | shadcn `Table`. Columns, one client-side sort with `aria-sort`, an optional client-side filter with a “3 of 20 shown” count, an empty state, right-aligned actions. |
| `EmptyState` | Nothing to show, and what to do about it. |
| `Skeleton` | The shape of what is arriving. `aria-live`, and deliberately *not* `role="status"`. |
| `LoadFailure` | A read that did not answer, and the way to ask again. |
| `ConfirmDialog` | The question before something irreversible, on Radix `AlertDialog`. |
| `toast` / `Toaster` | The announcement of an act that succeeded, in `components/ui/toast.tsx`. First-party; see [Under the policy](#under-the-policy). |

### Two rules that are easy to undo by accident

**`Skeleton` has no `role="status"`.** The role is what the browser sweep
searches for to tell a saved change from a refused one; a loading placeholder
that answered that question would be a second status beside the one the screen
meant. It keeps `aria-live`, which is the part doing the work.

**`ConfirmDialog` replaced `window.confirm`, and is now Radix's.** It is
`role="alertdialog"` since `ast-gore` — the correct role for a modal that
interrupts to ask a question, and the one change a browser test can see — with
`aria-modal="true"`, labelled by its heading and described by its sentence;
focus moves to the *cancelling* control when it opens, so a stray Return does
nothing; Tab and Shift+Tab cycle inside it; Escape and a click on the scrim
cancel; and the focus returns to whatever opened it. Four acts use it: disabling
an account, forcing a password reset, withdrawing a grant, removing a policy.
A fifth since `ast-l5bl`: suspending or restoring a tenant, where the dialog's
sentence is doing the most work it does anywhere — it is the one act on this
console that stops a whole tenant answering, for every client and every user it
has.

## The shell

**One navigation, and it is the sidebar** (`ast-gore` (3)). The sticky header
is gone: everything it carried — the mark, the wordmark, which tenant, who is
signed in, how to leave — is in the rail, because a console with two
navigations has two tab orders to walk and two places to look, and the header's
row was the half that broke first on a narrow window. What is left above the
content is a bar with the fold control and a breadcrumb, which says where you
are and nothing else.

The rail is shadcn's `Sidebar`, and it:

* **groups** the nine destinations under five headings — Overview; Identities;
  Security; Signals; Deployment (`navigation.ts`, `Group`). A heading with
  nothing under it is not drawn, so a caller who reaches neither Tenants nor
  Tenant settings sees no "Deployment";
* **folds to icons** with `Ctrl`/`⌘`+`B` or the rail's own edge control, and
  every label survives as the button's accessible name and as a tooltip;
* **becomes a drawer** (`Sheet`) below the mobile breakpoint;
* remembers whether it was folded in `localStorage` — *not* in the
  `sidebar_state` cookie shadcn ships, which would have been an unprefixed
  cookie at `path=/` on the origin that also serves the token endpoint;
* carries the **tenant selector** at the top and the **theme toggle**, the
  signed-in user and the sign-out at the bottom.

`visibleTo` still decides what appears, and is still a courtesy rather than a
control: the server re-checks every route (`crates/admin-api/src/rbac.rs`).
Routing stays on the fragment, so the document URL — and therefore every
relative asset and API URL — never moves.

A fragment may carry parameters since `ast-l5bl`: `#/settings?tenant=acme` is
the tenant settings screen pointed at a tenant that is not the session's own.
It exists for one link — the Tenants screen's hand-off to the settings of the
row an operator is reading — and it is trusted for nothing: the parameter
becomes the `{tenant_id}` of a path the server re-authorises, so a fragment
naming a tenant this caller may not read is a 403 drawn as a failed load. The
same screen hides the tenant's application-role catalogue when it is pointed
elsewhere, because that catalogue's route names no tenant and would be showing
the *session's* roles under another tenant's heading.

### The theme

Light is the default and the browser is not asked (`ast-gore` (2)). Until this
bead the palette hung off `prefers-color-scheme`, so an administrator whose
operating system was dark got a dark console they had never chosen and could
not turn off. Now `.dark` on `<html>` is the whole switch, `console/src/theme.ts`
is what puts it there, and `localStorage` is what remembers it. There is
deliberately no third "system" value: that value is how the console got dark in
the first place.

### The tenant selector

A combobox in the sidebar's header (`Popover` over `Command`), opened from
anywhere with `Ctrl`/`⌘`+`K`: the tenant this session is in, and the tenants it
may reach.

* A **deployment administrator** holds `admin.tenants:read` at deployment
  reach, so the list is `GET /tenants` — the call the Tenants screen already
  makes, read when the menu opens and not before.
* A **tenant administrator** holds that scope over their own tenant only. The
  call is *not made*: it would be a 403 drawn as a broken menu. The control
  names the one tenant they administer and says so.

Choosing a tenant **navigates to that tenant's own console**:
`{issuer}/admin/#/overview`, built by `tenantConsoleUrl` from the issuer the
API reports and from nothing this page knows about itself — a tenant reached
through a custom host has no `/t/{id}` prefix to copy.

It is a navigation rather than a change of state, and that is the decision
worth writing down. A session belongs to exactly one tenant (ADR-0010,
`ast-1cj`), the console is mounted beneath the tenant it serves, and every
admin API call it makes is relative to *its own* document URL. A selector that
swapped a tenant id into this page's state would leave those calls pointing at
the first tenant's API with the first tenant's session — a 403 per screen at
best, and at worst a cross-tenant read from a session never authorised for it.
Sending the browser to the other console makes the tenant a property of the
document again, and the session for it is opened by the login flow that already
exists (`ast-wr4`): a browser with no session there meets the ordinary sign-in
page, which is the correct outcome and not an error.

**The landing screen is Overview**, deliberately, and not the screen the
operator was on. What this administrator may reach in the other tenant is
decided by the roles they hold *there*, which this page does not know; Overview
is the one screen certain to answer, and it answers with exactly that — who you
are here, and what it lets you reach.

## Under the policy

`ast-gore` put a component framework inside the most privileged page this
deployment serves, and the question the bead asked first was what that costs
under ADR-0009's policy. The answer, measured: **nothing**. `script-src` and
`style-src` are unchanged, no route has a policy of its own, and
`the_console_widened_style_src_for_nobody` (`crates/web/src/csp.rs`) fails if
one grows.

What was measured, and what it turned on:

* **Radix's positioned layers are fine.** Popper, Dialog and the sidebar write
  positions and widths as inline styles — but React applies them through the
  **CSSOM** (`node.style.setProperty`), and `style-src` governs `<style>`
  elements and `style=` *attributes*, not CSSOM mutation. The sweep confirms
  it: `console.spec.ts` watches for violations on every screen and reports
  none.
* **One dependency does inject a `<style>` element**: `react-remove-scroll`,
  which is how Radix stops the page scrolling behind a modal. It reads a nonce
  from `get-nonce`, so `main.tsx` gives it one, taken from the entry script's
  `element.nonce`. The **IDL property and not the attribute**: a browser blanks
  the attribute after parsing precisely so that an injection able to read the
  DOM cannot read the nonce out of it (CSP Level 3 §5.2), and reading it this
  way keeps that protection — nothing is added to the document to scrape.
  `crates/admin-api/templates/console.html` carries the `id` that finds it, and
  a unit test fails if it is removed.
* **Sonner was refused.** shadcn's toast of choice ships its stylesheet inside
  its JavaScript and inserts it at import time with a `<style>` element it
  offers no way to nonce. Under this policy that is one violation per load and
  an unstyled toast — broken *and* noisy. The alternative was
  `style-src 'self' 'unsafe-inline'` scoped to the console's route, which is a
  bad trade for a notification strip, so the strip is written instead:
  `console/src/components/ui/toast.tsx`, the same `toast.success(…)` call shape,
  drawn with the console's own classes. Adopting Sonner later is a decision
  about widening `style-src`, and should be taken as one.

The two older rules still hold and are now checked against the built bytes by
`the_embedded_bundle_carries_nothing_the_style_policy_would_refuse`: no
`@import` survives into the stylesheet (Tailwind's own two are resolved at
build time), no `url(`, and no `style=` written into markup by a chunk.


## Taking the pictures again

```sh
E2E_SHOTS=docs/console/after ./scripts/browser-tests.sh \
  --project=js tests/console-shots.spec.ts
```

`E2E_SHOTS` is a directory relative to the repository root; without it the spec
skips, because it asserts nothing and every console criterion is asserted by
`e2e/tests/console.spec.ts`.
