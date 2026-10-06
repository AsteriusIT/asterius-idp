# button

2026-10-05, engine with CLI Base UI reference, migrated with local design preserved; frontend build and focused browser checks pass.

## Changed

console/src/components/ui/button.tsx:1 uses the real Base UI Button while retaining Asterius variants and static motion. console/src/components/app-topbar.tsx:51 uses render, nativeButton=false, and role=link for navigation anchors. console/src/components/ui/alert-dialog.tsx:167 composes its existing Radix actions with Button render.

The scan for radix-ui / @radix-ui in this component wrapper is clean.

Validation: production build/typecheck, 88 frontend tests, and eight distinct
controlled Chromium scenarios passed after fixing topbar link semantics.
Keyboard/reflow/zoom and dark-mode checks include axe accessibility assertions.
These checks use deterministic API responses, not a live authenticated backend.

## Left alone

Existing alert dialog focus/dismissal and sidebar behavior retain Radix. Other wrappers are outside this progressive step.

## Behavior changes

Navigation links explicitly use non-native button semantics. Native buttons now use Base UI keyboard and disabled-state handling.

## Verify by hand

Activate topbar links with Enter. Open a confirmation, cancel and confirm it, and ensure disabled actions cannot run.
