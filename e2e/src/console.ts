/**
 * Getting a browser into the admin console.
 *
 * `ast-wr4` put a door in front of the entry document: `GET /admin/` without a
 * usable session opens a first-party interaction and 303s to the ordinary
 * login page, so the shell is not a thing an unauthenticated visitor can make
 * this server draw. Every console spec therefore starts by walking that door,
 * and it is walked here rather than once per file: two copies of the sign-in
 * path are two places to forget that the door exists (`ast-rna`).
 */
import { type Page, expect } from '@playwright/test';
import {
  ADMIN_BASE_URL,
  ADMIN_PASSWORD,
  ADMIN_USERNAME,
  BASE_URL,
  PASSWORD,
  USERNAME,
} from './environment.js';

/** The entry document, with its trailing slash. */
export const CONSOLE_URL = `${BASE_URL}/admin/`;

/**
 * Walks the console's door: `/admin/` → login → back at `/admin/`.
 *
 * The credentials are the sweep fixture's, and the navigation is the server's
 * own: no URL is constructed here beyond the console's, so the redirect chain
 * under test is the one `ast-wr4` built.
 */
export async function signIn(page: Page): Promise<void> {
  await signInAt(page, CONSOLE_URL, USERNAME, PASSWORD);
}

/**
 * The console of the *reserved* tenant, as the deployment administrator
 * (`ast-f7m.6`).
 *
 * The gap `ast-895` left in this harness: every console spec until now signed
 * in as a `tenant_admin`, so the branch that decides what a deployment-scoped
 * caller may see — and the passkey rule that governs it — had never been in
 * front of a browser. The seeded administrator has a password and no passkey,
 * which `asterius_domain::admin_access_policy` admits precisely because there
 * is no passkey to demand yet; enrolling one and signing in on the password
 * again is the case that must be refused, and it belongs to `ast-895`'s own
 * spec rather than here.
 */
export const ADMIN_CONSOLE_URL = `${ADMIN_BASE_URL}/admin/`;

export async function signInAsDeploymentAdmin(page: Page): Promise<void> {
  await signInAt(page, ADMIN_CONSOLE_URL, ADMIN_USERNAME, ADMIN_PASSWORD);
}

/**
 * Walks the door at `entry` with `username` and `password`.
 *
 * One implementation for both callers: two copies of the sign-in path are two
 * places to forget that the door exists (`ast-rna`), which is the whole reason
 * this file was written.
 */
export async function signInAt(
  page: Page,
  entry: string,
  username: string,
  password: string,
): Promise<void> {
  await page.goto(entry);
  await page.locator('input[name="username"]').fill(username);
  await page.locator('input[name="password"]').fill(password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.waitForURL(entry);
}

/**
 * Opens one console screen through its navigation link.
 *
 * By the link and not by a fragment typed into the address bar: a screen that
 * exists but is unreachable through the navigation is a screen no
 * administrator can use, and a `goto` would assert the router while skipping
 * exactly that.
 */
export async function open(page: Page, link: string, heading: string): Promise<void> {
  await page.getByRole('link', { name: link }).click();
  await expect(page.getByRole('heading', { name: heading })).toBeVisible();
}
