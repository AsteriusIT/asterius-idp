# tabs

2026-10-05, engine with CLI Base UI reference, migrated with local design preserved; frontend build and focused browser checks pass.

## Changed

console/src/components/ui/tabs.tsx:2 uses Base UI Root/List/Tab/Panel. keepMounted retains inactive editors. console/src/enterprise.css uses data-active/data-hidden. e2e/tests/console-experience.spec.ts verifies draft preservation and manual activation.

The scan for radix-ui / @radix-ui in this component wrapper is clean.

Validation: production build/typecheck, 88 frontend tests, and eight distinct
controlled Chromium scenarios passed after fixing topbar link semantics.
Keyboard/reflow/zoom and dark-mode checks include axe accessibility assertions.
These checks use deterministic API responses, not a live authenticated backend.

## Left alone

Screen data fetching and field logic are unchanged.

## Behavior changes

Tabs use manual keyboard activation: arrows move focus, Enter/Space selects. This intentionally differs from Radix automatic activation.

## Verify by hand

Edit a field, change tabs, and return to verify its value. Use arrow keys and Enter/Space. Confirm exactly one panel remains visible.
