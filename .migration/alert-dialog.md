# alert-dialog

2026-10-06, transformation engine with CLI Base Vega reference; migrated with customized visual styles preserved.

## Changed

console/src/components/ui/alert-dialog.tsx:1: Base AlertDialog Popup/Backdrop, Button actions and render composition; console/src/ui.tsx composes confirmation descriptions and asynchronous actions.

The scan for radix-ui / @radix-ui in these component files is clean.
Production typecheck/build and targeted controlled Chromium checks validate the migration.

## Left alone

The cmdk command wrapper and repository toast remain unchanged; they are outside this primitive migration. Server-rendered sign-in and branding font settings remain unchanged.

## Behavior changes

Confirm is an owned Button so the caller controls dismissal after a successful write; Cancel uses Base Close. Failed writes retain the confirmation.

## Verify by hand

Open a destructive confirmation, cancel, then simulate a rejected write and confirm the dialog stays open.
