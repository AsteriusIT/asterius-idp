# separator

2026-10-05, engine with CLI Base UI reference, migrated with local design preserved; frontend build and focused browser checks pass.

## Changed

console/src/components/ui/separator.tsx:3 uses Base UI and orientation presence attributes. The existing decorative option maps to role=presentation; semantic separators keep role=separator.

The scan for radix-ui / @radix-ui in this component wrapper is clean.

Validation: production build/typecheck, 88 frontend tests, and eight distinct
controlled Chromium scenarios passed after fixing topbar link semantics.
Keyboard/reflow/zoom and dark-mode checks include axe accessibility assertions.
These checks use deterministic API responses, not a live authenticated backend.

## Left alone

Sidebar layout and other primitives retain existing behavior.

## Behavior changes

Orientation attributes are data-horizontal/data-vertical. The wrapper preserves decorative semantics.

## Verify by hand

Check horizontal/vertical dividers. Confirm decorative dividers are absent from the semantic separator tree.
