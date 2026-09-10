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
import { BASE_URL, PASSWORD, USERNAME } from './environment.js';

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
  await page.goto(CONSOLE_URL);
  await page.locator('input[name="username"]').fill(USERNAME);
  await page.locator('input[name="password"]').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.waitForURL(CONSOLE_URL);
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
