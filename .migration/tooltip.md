# tooltip

2026-10-06, transformation engine with CLI Base Vega reference; migrated with customized visual styles preserved.

## Changed

console/src/components/ui/tooltip.tsx:1: Base Portal/Positioner/Popup/Arrow with forwarded placement props and semantic token classes; console/src/enterprise.css positions the arrow outside each popup edge.

The scan for radix-ui / @radix-ui in these component files is clean.
Production typecheck/build and targeted controlled Chromium checks validate the migration.

## Left alone

The cmdk command wrapper and repository toast remain unchanged; they are outside this primitive migration. Server-rendered sign-in and branding font settings remain unchanged.

## Behavior changes

Provider uses delay; hidden content is not mounted. Base tooltips are visual labels without a tooltip role; existing navigation link text supplies accessible names.

## Verify by hand

Hover and keyboard-focus collapsed navigation links; check arrow placement and tooltip dismissal.
