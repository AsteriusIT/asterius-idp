# project

2026-10-06, transformation engine for customized legacy new-york wrappers with CLI Base Vega references; owned console primitive migration complete.

## Changed

All ten remaining wrappers plus direct application menus now use Base UI. components.json defaults to base-vega; console/package.json and package-lock.json remove direct radix-ui and get-nonce dependencies. console/src/main.tsx supplies the server nonce through CSPProvider. Shared portal stacking and Base data attributes replace primitive-specific CSS. console/DESIGN_SYSTEM.md describes the resulting repository-owned foundation.

The console/src scan for radix-ui / @radix-ui / asChild / --radix- is clean. Typecheck/production build and 88 frontend tests pass. 48 distinct controlled Chromium checks pass and cover menus, editors, confirmations, dirty drafts, pickers, dark/light reflow and strict CSP. Earlier button/separator/tabs reports describe the preceding foundation step.

## Left alone

cmdk and the repository toast remain intact; cmdk retains transitive Radix dependencies. Rust source, server-rendered sign-in fonts and branding schema are unchanged. Source remains uncommitted in the ticket worktree under the active conservative profile.

## Behavior changes

Base radio menu choices stay open by default; directory filters explicitly preserve closing after selection. Tabs retain manual activation from the earlier migration. Dialogs use Base focus callbacks. Button/link composition uses render and explicit non-native semantics. The account-menu axe check excludes only Base UI focus guards (mui/base-ui#4668); direct keyboard checks verify guards do not retain focus.

## Verify by hand

Inspect users in both themes, use keyboard account actions and filter choices, open/cancel an editor, and test collapsed/mobile navigation. Verify failed destructive writes preserve their confirmation and that Escape restores focus.
