# dialog

2026-10-06, transformation engine with CLI Base Vega reference; migrated with customized visual styles preserved.

## Changed

console/src/components/ui/dialog.tsx:1: Base Dialog Popup/Backdrop and render-based Close retain styling; initialFocus/finalFocus preserve opener restoration.

The scan for radix-ui / @radix-ui in these component files is clean.
Production typecheck/build and targeted controlled Chromium checks validate the migration.

## Left alone

The cmdk command wrapper and repository toast remain unchanged; they are outside this primitive migration. Server-rendered sign-in and branding font settings remain unchanged.

## Behavior changes

Base focus APIs replace Radix autofocus callbacks. No consumers used the removed callbacks.

## Verify by hand

Open an editor, cancel with Escape, and verify the launching control regains focus; test rejected writes.
