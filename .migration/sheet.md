# sheet

2026-10-06, transformation engine with CLI Base Vega reference; migrated with customized visual styles preserved.

## Changed

console/src/components/ui/sheet.tsx:1: Base Dialog Popup/Backdrop and render Close with presence transition attributes and shared portal stacking.

The scan for radix-ui / @radix-ui in these component files is clean.
Production typecheck/build and targeted controlled Chromium checks validate the migration.

## Left alone

The cmdk command wrapper and repository toast remain unchanged; they are outside this primitive migration. Server-rendered sign-in and branding font settings remain unchanged.

## Behavior changes

Base presence attributes replace Radix state animation selectors.

## Verify by hand

At a narrow viewport open navigation, follow a route, and close with Escape; verify no horizontal overflow.
