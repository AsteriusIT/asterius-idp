# The console's design

The admin console is drawn in the language `7f428d2` gave the user-facing
pages: one warm neutral backdrop, hairline borders, an 8px card and a 6px
control, 44px targets, and a single indigo accent spent on one decision per
view. This file says where the values live, what the pieces are called, and
what a screen is expected to do with them (`ast-fe39`).

The pictures beside it are the same eight screens before the migration
(`before/`) and after it (`after/`), taken by the same browser at 1280×900 by
`e2e/tests/console-shots.spec.ts`.

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
* **A dark scheme.** `style.css` has none on purpose (`ast-vn7`): a tenant's
  palette is appended to it, and a `prefers-color-scheme` block would substitute
  colours that tenant's contrast check never saw. The console is not themed by a
  tenant — it is this deployment's own tool — so it carries one, in the console
  layer only.

## The constraints

* **Nothing inline.** The policy is `script-src 'nonce-…' 'strict-dynamic'` and
  `style-src 'nonce-…'` (ADR-0009). One stylesheet, linked by the entry document
  with the response's nonce, and no `style=` attribute anywhere in the bundle.
* **No `@import`, no `url(`.** `tokens.css` is imported by `main.tsx` so Vite
  concatenates it into that one file; an `@import` that survived bundling would
  be a stylesheet fetched by a stylesheet, carrying no nonce. `url(` would be a
  request to an origin nobody reviewed.
* **No component framework.** A UI library is a dependency tree inside the most
  privileged page this deployment serves, shipped to every browser that opens
  it, for a table, a dialog and six wrappers. `react` and `react-dom` remain the
  console's only runtime dependencies.

## The components

All in `console/src/ui.tsx`. None of them talks to the network; a component
takes what to draw and gives back what was pressed, which is what made the
migration a change of markup rather than a change of behaviour.

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
| `DataTable` | Columns, one client-side sort with `aria-sort`, an empty state, right-aligned actions. |
| `EmptyState` | Nothing to show, and what to do about it. |
| `Skeleton` | The shape of what is arriving. `aria-live`, and deliberately *not* `role="status"`. |
| `LoadFailure` | A read that did not answer, and the way to ask again. |
| `ConfirmDialog` | The question before something irreversible. |

### Two rules that are easy to undo by accident

**`Skeleton` has no `role="status"`.** The role is what the browser sweep
searches for to tell a saved change from a refused one; a loading placeholder
that answered that question would be a second status beside the one the screen
meant. It keeps `aria-live`, which is the part doing the work.

**`ConfirmDialog` replaced `window.confirm`.** It is `role="dialog"` with
`aria-modal="true"`, labelled by its heading and described by its sentence;
focus moves to the *cancelling* control when it opens, so a stray Return does
nothing; Tab and Shift+Tab cycle inside it; Escape and a click on the scrim
cancel; and the focus returns to whatever opened it. Four acts use it: disabling
an account, forcing a password reset, withdrawing a grant, removing a policy.

## The shell

A sticky header carrying the mark, the wordmark and the session; a rail of the
destinations this session's scopes reach (`navigation.ts`, unchanged — the
server re-checks every one of them); and a content column capped at
`--content-max`. Below 60rem the rail becomes a scrolling row above the content,
which is what makes a tablet usable. Routing stays on the fragment, so the
document URL — and therefore every relative asset and API URL — never moves.

## Taking the pictures again

```sh
E2E_SHOTS=docs/console/after ./scripts/browser-tests.sh \
  --project=js tests/console-shots.spec.ts
```

`E2E_SHOTS` is a directory relative to the repository root; without it the spec
skips, because it asserts nothing and every console criterion is asserted by
`e2e/tests/console.spec.ts`.
