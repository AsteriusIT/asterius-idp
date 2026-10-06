# sidebar

2026-10-06, transformation engine with CLI Base Vega reference; migrated with customized visual styles preserved.

## Changed

console/src/components/ui/sidebar.tsx:1: Base Button and useRender replace Slot; console/src/components/app-sidebar.tsx composes anchor render props and Tooltip.Trigger.

The scan for radix-ui / @radix-ui in these component files is clean.
Production typecheck/build and targeted controlled Chromium checks validate the migration.

## Left alone

The cmdk command wrapper and repository toast remain unchanged; they are outside this primitive migration. Server-rendered sign-in and branding font settings remain unchanged.

## Behavior changes

Anchor buttons explicitly use nativeButton=false with link semantics. Provider uses delay instead of delayDuration.

## Verify by hand

Collapse navigation, hover/focus a link for its tooltip, activate with Enter, then test mobile navigation.
