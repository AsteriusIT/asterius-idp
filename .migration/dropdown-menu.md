# dropdown-menu

2026-10-06, transformation engine with CLI Base Vega reference; migrated with customized visual styles preserved.

## Changed

console/src/components/ui/dropdown-menu.tsx:1: New console/src/components/ui/dropdown-menu.tsx owns Base Menu composition; console/src/{directory-controls.tsx,components/app-topbar.tsx} migrate direct menus; enterprise.css uses data-popup-open.

The scan for radix-ui / @radix-ui in these component files is clean.
Production typecheck/build and targeted controlled Chromium checks validate the migration.

## Left alone

The cmdk command wrapper and repository toast remain unchanged; they are outside this primitive migration. Server-rendered sign-in and branding font settings remain unchanged.

## Behavior changes

Radio items default to staying open in Base UI; directory controls explicitly closeOnClick to retain the filter workflow. LinkItem renders actual links. Axe excludes only upstream focus guards and Shift+Tab focus restoration is asserted.

## Verify by hand

Use ArrowDown/ArrowUp and Enter in account actions, Escape/Shift+Tab back to trigger, and choose a status filter before opening a record.
