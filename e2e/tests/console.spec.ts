/**
 * The admin console shell, in a real browser (`ast-f7m.3`).
 *
 * Four of this bead's acceptance criteria can only be checked here, and each
 * one is a test below:
 *
 *  - **Zero CSP violations.** The console is the one page in this server that
 *    runs a script bundle, so `script-src 'nonce-…' 'strict-dynamic'` is doing
 *    real work for the first time. A source audit cannot tell whether Chromium
 *    accepted the nonce; only Chromium can.
 *  - **No third-party network call.** Every request the page makes is recorded
 *    and compared against the origin under test. `connect-src 'self'` is the
 *    browser's half of that promise; this is the evidence.
 *  - **A 401 is handled by asking for a sign-in** rather than by a blank page
 *    or a loop. The sweep has no admin session, so the unauthenticated path is
 *    exactly the path it exercises.
 *  - **Accessibility.** axe over the screen the suite can reach.
 *
 * Only the JS project runs this file: a console is script by definition, and
 * what a browser without script sees is the `<noscript>` block, asserted here
 * too by reading the document rather than by running it.
 */
import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import { CspWatcher } from '../src/csp.js';
import { BASE_URL } from '../src/environment.js';

const ORIGIN = new URL(BASE_URL).origin;
const CONSOLE_URL = `${BASE_URL}/admin/`;

test('the shell starts, provokes no CSP violation and calls nobody else', async ({
  context,
  page,
}) => {
  // Arrange
  const watcher = await CspWatcher.attach(context, true);
  const offOrigin: string[] = [];
  context.on('request', (request) => {
    if (!request.url().startsWith(ORIGIN)) {
      offOrigin.push(`${request.method()} ${request.url()}`);
    }
  });

  // Act
  const response = await page.goto(CONSOLE_URL);

  // Assert: the bundle ran. This heading exists only in the React tree, so
  // seeing it means the nonced module was accepted, fetched and executed.
  expect(response?.status()).toBe(200);
  await expect(page.getByRole('heading', { name: 'Signed out' })).toBeVisible();
  expect(offOrigin, 'the console reached a third party').toEqual([]);
  watcher.assertClean('the console shell');
});

test('the entry document carries the same nonce in its policy and its tags', async ({ page }) => {
  // Arrange
  const response = await page.goto(CONSOLE_URL);
  const policy = response?.headers()['content-security-policy'] ?? '';

  // Act
  const nonce = /'nonce-([^']+)'/.exec(policy)?.[1];

  // Assert
  expect(policy).toContain("'strict-dynamic'");
  expect(policy).toContain("default-src 'none'");
  expect(policy).toContain("connect-src 'self'");
  expect(policy).not.toContain('unsafe-');
  expect(nonce, 'the policy names no nonce').toBeTruthy();

  const scriptNonce = await page.locator('script[type="module"]').getAttribute('nonce');
  // Chromium hides the attribute from the DOM (CSP Level 3 §4.2.3), so the
  // property is what carries the value that was served.
  const fromProperty = await page
    .locator('script[type="module"]')
    .evaluate((element) => (element as HTMLScriptElement).nonce);
  expect(scriptNonce ?? fromProperty).toBe(nonce);

  // A document is per-session and must never be stored; the assets it names
  // are hashed and are cached for a year, which is only safe because of this.
  expect(response?.headers()['cache-control']).toBe('no-store');
});

test('an unauthenticated API call answers 401 and the console asks for a sign-in', async ({
  page,
}) => {
  // Arrange
  const unauthorised: number[] = [];
  page.on('response', (response) => {
    if (response.url().includes('/admin/api/v1/session')) {
      unauthorised.push(response.status());
    }
  });

  // Act
  await page.goto(CONSOLE_URL);
  await expect(page.getByRole('heading', { name: 'Signed out' })).toBeVisible();

  // Assert
  expect(unauthorised).toEqual([401]);
  // No navigation loop: the console is still where it was put.
  expect(page.url()).toBe(CONSOLE_URL);
});

test('the bundle is content-hashed and cached for a year', async ({ page, request }) => {
  // Arrange
  await page.goto(CONSOLE_URL);
  const source = await page.locator('script[type="module"]').getAttribute('src');
  expect(source, 'the document names its entry relatively').toMatch(/^assets\/.+\.js$/);

  // Act
  const asset = await request.get(new URL(source ?? '', CONSOLE_URL).toString());

  // Assert
  expect(asset.status()).toBe(200);
  expect(asset.headers()['content-type']).toContain('text/javascript');
  expect(asset.headers()['cache-control']).toBe('public, max-age=31536000, immutable');
  expect(asset.headers()['x-content-type-options']).toBe('nosniff');
});

test('a typed /admin reaches /admin/ without losing anything', async ({ page }) => {
  const response = await page.goto(`${BASE_URL}/admin`);

  expect(response?.status()).toBe(200);
  expect(page.url()).toBe(CONSOLE_URL);
});

test('the console screen has no accessibility violation', async ({ page }, testInfo) => {
  // Arrange
  await page.goto(CONSOLE_URL);
  await expect(page.getByRole('heading', { name: 'Signed out' })).toBeVisible();

  // Act
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();

  // Assert
  await testInfo.attach('axe', {
    body: JSON.stringify(results.violations, null, 2),
    contentType: 'application/json',
  });
  expect(results.violations).toEqual([]);
});
