# popover

2026-10-06, transformation engine with CLI Base Vega reference; migrated with customized visual styles preserved.

## Changed

console/src/components/ui/popover.tsx:1: Base Portal/Positioner/Popup with forwarded geometry; console/src/{scim,kubernetes-access,token-console}.tsx and components/tenant-switcher.tsx use render triggers.

The scan for radix-ui / @radix-ui in these component files is clean.
Production typecheck/build and targeted controlled Chromium checks validate the migration.

## Left alone

The cmdk command wrapper and repository toast remain unchanged; they are outside this primitive migration. Server-rendered sign-in and branding font settings remain unchanged.

## Behavior changes

Unused PopoverAnchor export removed: no Base equivalent and no application consumers.

## Verify by hand

Open a searchable picker, use arrows and Escape, then inspect edge collision behavior on mobile.
