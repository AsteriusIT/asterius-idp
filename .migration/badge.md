# badge

2026-10-06, transformation engine with CLI Base Vega reference; migrated with customized visual styles preserved.

## Changed

console/src/components/ui/badge.tsx:1: Base useRender replaces Slot through console/src/lib/render-element.tsx; existing variants remain.

The scan for radix-ui / @radix-ui in these component files is clean.
Production typecheck/build and targeted controlled Chromium checks validate the migration.

## Left alone

The cmdk command wrapper and repository toast remain unchanged; they are outside this primitive migration. Server-rendered sign-in and branding font settings remain unchanged.

## Behavior changes

Composition uses render instead of asChild.

## Verify by hand

Inspect status badges in both themes and confirm their labels remain readable.
