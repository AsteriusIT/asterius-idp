/**
 * The admin console shell, in a real browser (`ast-f7m.3`, run by `ast-xka`).
 *
 * Four of `ast-f7m.3`'s acceptance criteria can only be checked here, and each
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
 *    or a loop.
 *  - **Accessibility.** axe over the shell an administrator actually sees.
 *
 * # Why every test signs in first
 *
 * `ast-wr4` put a door in front of the entry document: `GET /admin/` without a
 * usable session opens a first-party interaction and 303s to the ordinary
 * login page (`crates/server/src/http/console.rs`), so the shell is not a
 * thing an unauthenticated visitor can make this server draw. The first run of
 * this file (`ast-xka`) failed all six tests on exactly that, because it was
 * written before the door existed and expected the unauthenticated console to
 * render its "Signed out" screen. Signing in is therefore not a convenience
 * here: it is the only path on which the console exists at all.
 *
 * # Why the 401 is a real one
 *
 * The signed-out screen is what the console shows when the session behind a
 * running shell has gone. The document is guarded, so a browser whose cookie
 * has been cleared never gets the shell back — it gets the login page — and
 * the only moment the screen exists is a shell that is already running when
 * the refusal arrives. So the refusal is *fetched from this server* with no
 * session (the `request` fixture is an isolated API context) and that exact
 * response is what the page is given: the status, the headers and the body
 * are the server's, and only their timing is arranged. A hand-written `401`
 * would have asserted the React branch against a fixture rather than against
 * this server, which is the half a browser test exists to add.
 *
 * Only the JS project runs this file: a console is script by definition, and
 * what a browser without script sees is the `<noscript>` block, asserted by
 * `crates/admin-api/src/console.rs` from the template side.
 */
import AxeBuilder from '@axe-core/playwright';
import { type APIRequestContext, type Page, expect, test } from '@playwright/test';
import { CspWatcher } from '../src/csp.js';
import { BASE_URL, PASSWORD, USERNAME } from '../src/environment.js';

const ORIGIN = new URL(BASE_URL).origin;
const CONSOLE_URL = `${BASE_URL}/admin/`;

/** Where the console reads who it is; the one API call the shell makes. */
const SESSION_ENDPOINT = '/admin/api/v1/session';

/**
 * Walks the console's door: `/admin/` → login → back at `/admin/`.
 *
 * The credentials are the sweep fixture's, and the navigation is the server's
 * own: no URL is constructed here beyond the console's, so the redirect chain
 * under test is the one `ast-wr4` built.
 */
async function signIn(page: Page): Promise<void> {
  await page.goto(CONSOLE_URL);
  await page.locator('input[name="username"]').fill(USERNAME);
  await page.locator('input[name="password"]').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.waitForURL(CONSOLE_URL);
}

/**
 * Puts the shell in front of this server's refusal, and returns its status.
 *
 * `api` is Playwright's isolated request context: it carries none of the
 * browser's cookies, so what it reads from the session endpoint is the answer
 * this server gives a caller with no session. That response — status, type and
 * body — is then what the reloaded document's script is served. The document
 * itself is left alone, because it is guarded: clearing the browser's cookie
 * would send the *navigation* to the login page and the shell would never run.
 */
async function refuseTheNextSessionRead(page: Page, api: APIRequestContext): Promise<number> {
  const refusal = await api.get(`${BASE_URL}${SESSION_ENDPOINT}`);
  const body = await refusal.body();
  const contentType = refusal.headers()['content-type'] ?? 'application/json';
  await page.route(`**${SESSION_ENDPOINT}`, (route) =>
    route.fulfill({ status: refusal.status(), contentType, body }),
  );
  await page.reload();
  return refusal.status();
}

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
  await signIn(page);

  // Assert: the bundle ran. This heading exists only in the React tree, so
  // seeing it means the nonced module was accepted, fetched and executed.
  await expect(page.getByRole('heading', { name: 'Asterius console' })).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Console sections' })).toBeVisible();
  expect(offOrigin, 'the console reached a third party').toEqual([]);
  watcher.assertClean('the console shell');
});

test('the entry document carries the same nonce in its policy and its tags', async ({ page }) => {
  // Arrange
  await signIn(page);
  const response = await page.goto(CONSOLE_URL);
  const policy = response?.headers()['content-security-policy'] ?? '';

  // Act
  const nonce = /'nonce-([^']+)'/.exec(policy)?.[1];

  // Assert
  expect(response?.status()).toBe(200);
  expect(policy).toContain("'strict-dynamic'");
  expect(policy).toContain("default-src 'none'");
  expect(policy).toContain("connect-src 'self'");
  expect(policy).not.toContain('unsafe-');
  expect(nonce, 'the policy names no nonce').toBeTruthy();

  // Chromium *empties* the content attribute rather than removing it (CSP
  // Level 3 §4.2.3 nonce hiding), so `getAttribute` answers `''` and not
  // `null`: the IDL property is the only channel that still carries the value
  // that was served, and an empty string has to fall through to it. The first
  // run of this file (`ast-xka`) failed here, on `??`, which does not.
  const scriptNonce = await page.locator('script[type="module"]').getAttribute('nonce');
  const fromProperty = await page
    .locator('script[type="module"]')
    .evaluate((element) => (element as HTMLScriptElement).nonce);
  expect(scriptNonce === null || scriptNonce === '' ? fromProperty : scriptNonce).toBe(nonce);

  // A document is per-session and must never be stored; the assets it names
  // are hashed and are cached for a year, which is only safe because of this.
  expect(response?.headers()['cache-control']).toBe('no-store');
});

test('a session that ends answers 401 and the console asks for a sign-in', async ({
  page,
  request,
}) => {
  // Arrange: a running shell, and a record of what the session endpoint says.
  const sessionStatuses: number[] = [];
  page.on('response', (response) => {
    if (response.url().includes(SESSION_ENDPOINT)) {
      sessionStatuses.push(response.status());
    }
  });
  await signIn(page);
  await expect(page.getByRole('heading', { name: 'Asterius console' })).toBeVisible();

  // Act
  const refused = await refuseTheNextSessionRead(page, request);

  // Assert
  expect(refused, 'the server does not refuse a session read without a cookie').toBe(401);
  await expect(page.getByRole('heading', { name: 'Signed out' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
  expect(sessionStatuses, 'the console did not see one 200 then one 401').toEqual([200, 401]);
  // No navigation loop: the console is still where it was put.
  expect(page.url()).toBe(CONSOLE_URL);
});

test('the bundle is content-hashed and cached for a year', async ({ page, request }) => {
  // Arrange
  await signIn(page);
  const source = await page.locator('script[type="module"]').getAttribute('src');
  expect(source, 'the document names its entry relatively').toMatch(/^assets\/.+\.js$/);

  // Act. The assets are unguarded (`asterius_admin_api::console::assets`), so
  // the API context's lack of a session cookie is not a hazard here.
  const asset = await request.get(new URL(source ?? '', CONSOLE_URL).toString());

  // Assert
  expect(asset.status()).toBe(200);
  expect(asset.headers()['content-type']).toContain('text/javascript');
  expect(asset.headers()['cache-control']).toBe('public, max-age=31536000, immutable');
  expect(asset.headers()['x-content-type-options']).toBe('nosniff');
});

test('a typed /admin reaches /admin/ without losing anything', async ({ page }) => {
  // Arrange
  await signIn(page);

  // Act
  const response = await page.goto(`${BASE_URL}/admin`);

  // Assert
  expect(response?.status()).toBe(200);
  expect(page.url()).toBe(CONSOLE_URL);
});

test('the console screen has no accessibility violation', async ({ page }, testInfo) => {
  // Arrange
  await signIn(page);
  await expect(page.getByRole('heading', { name: 'Asterius console' })).toBeVisible();

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

test('the signed-out screen has no accessibility violation either', async ({
  page,
  request,
}, testInfo) => {
  // Arrange: the screen a 401 produces is a screen, and WCAG applies to it.
  await signIn(page);
  await expect(page.getByRole('heading', { name: 'Asterius console' })).toBeVisible();
  expect(await refuseTheNextSessionRead(page, request)).toBe(401);
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
