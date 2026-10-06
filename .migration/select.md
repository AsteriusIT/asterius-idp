# select

2026-10-06, transformation engine with CLI Base Vega reference; migrated with customized visual styles preserved.

## Changed

console/src/components/ui/select.tsx:1: Base Select List, ItemText and indicators; FormSelect maps labels and preserves raw hidden-input API values; console/src/enterprise.css uses Base state/geometry attributes.

The scan for radix-ui / @radix-ui in these component files is clean.
Production typecheck/build and targeted controlled Chromium checks validate the migration.

## Left alone

The cmdk command wrapper and repository toast remain unchanged; they are outside this primitive migration. Server-rendered sign-in and branding font settings remain unchanged.

## Behavior changes

Popup sits below the trigger using alignItemWithTrigger=false. Null change events are ignored; empty strings remain valid adapter values.

## Verify by hand

Select a nonempty and empty option, verify displayed labels and submitted API values; test typeahead and Escape.
