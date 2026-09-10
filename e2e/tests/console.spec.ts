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

/**
 * Walks the navigation to the tenant settings screen (`ast-bfn`).
 *
 * By its link and not by a fragment typed into the address bar: the criterion
 * is that the screen is *reachable through the navigation*, and a `goto` would
 * assert the router while skipping the thing that was missing.
 */
async function openSettings(page: Page): Promise<void> {
  await page.getByRole('link', { name: 'Tenant settings' }).click();
  await expect(page.getByRole('heading', { name: 'Tenant settings' })).toBeVisible();
  // The form is drawn from the document the API answered with, so a visible
  // field means the read succeeded rather than that a skeleton rendered.
  await expect(page.getByLabel('Authorization code lifetime (seconds)')).toBeVisible();
}

test('the tenant settings screen is reachable and reads the admin API', async ({
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
  await signIn(page);

  // Act
  await openSettings(page);

  // Assert: values, not placeholders. The seeded tenant runs on the defaults,
  // and what matters here is that both lifetimes arrived as numbers.
  await expect(page.getByLabel('Authorization code lifetime (seconds)')).not.toHaveValue('');
  await expect(page.getByLabel('Access token lifetime (seconds)')).not.toHaveValue('');
  await expect(page.getByRole('checkbox', { name: 'device_flow' })).toBeVisible();
  expect(offOrigin, 'the settings screen reached a third party').toEqual([]);
  watcher.assertClean('the tenant settings screen');
});

/**
 * **The FAPI half of `ast-bfn`.**
 *
 * The ceiling is the server's — `asterius_domain::TenantSettings::validated`,
 * below the API — and the console's job is only to show what the server said.
 * The `max` attribute on the field is a courtesy, so the value is put in with
 * `fill` and the form submitted, which is what a `curl` would do too.
 */
test('a lifetime above the profile ceiling is refused and the reason is shown', async ({
  page,
}) => {
  // Arrange
  await signIn(page);
  await openSettings(page);
  const field = page.getByLabel('Authorization code lifetime (seconds)');
  const ceiling = Number(await field.getAttribute('max'));
  expect(ceiling, 'the server sent no ceiling with its document').toBeGreaterThan(0);

  // Act
  await field.fill(String(ceiling + 1));
  await page.getByRole('button', { name: 'Save settings' }).click();

  // Assert: the server's sentence, which names the profile clause, and no
  // claim that anything was saved.
  const refusal = page.getByRole('alert');
  await expect(refusal).toBeVisible();
  await expect(refusal).toContainText(/FAPI/i);
  // And no success notice: the screen's `status` region is where "Saved."
  // would appear, and it must not be there next to a refusal.
  await expect(page.getByRole('status')).toHaveCount(0);
});

test('the tenant settings screen has no accessibility violation', async ({ page }, testInfo) => {
  // Arrange
  await signIn(page);
  await openSettings(page);

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

/**
 * Walks the navigation to the clients screen (`ast-f7m.5`).
 *
 * By its link, like the settings screen above and for the same reason: the
 * criterion is that the screen is reachable through the navigation.
 */
async function openClients(page: Page): Promise<void> {
  await page.getByRole('link', { name: 'Clients' }).click();
  await expect(page.getByRole('heading', { name: 'Clients', exact: true })).toBeVisible();
  // Drawn from the document the API answered with, so a visible search box and
  // a settled table mean the read succeeded rather than that a skeleton
  // rendered.
  await expect(page.getByLabel('Search clients')).toBeVisible();
}

/** Opens the registration form and fills the fields every client needs. */
async function fillNewClient(page: Page, name: string, callback: string): Promise<void> {
  await page.getByRole('button', { name: 'Register a client' }).click();
  await expect(page.getByRole('heading', { name: 'New client' })).toBeVisible();
  await page.getByLabel('Client name').fill(name);
  await page.getByLabel('Redirect URIs (one per line)', { exact: true }).fill(callback);
  await page.getByLabel('JWK Set URL').fill('https://app.example.test/jwks.json');
}

test('the clients screen is reachable and reads the admin API', async ({ context, page }) => {
  // Arrange
  const watcher = await CspWatcher.attach(context, true);
  const offOrigin: string[] = [];
  context.on('request', (request) => {
    if (!request.url().startsWith(ORIGIN)) {
      offOrigin.push(`${request.method()} ${request.url()}`);
    }
  });
  await signIn(page);

  // Act
  await openClients(page);

  // Assert
  expect(offOrigin, 'the clients screen reached a third party').toEqual([]);
  watcher.assertClean('the clients screen');
});

/**
 * **The acceptance criterion of `ast-f7m.5`, in a browser.**
 *
 * The console must not be able to create a client dynamic client registration
 * would refuse. Both documents below are refused by
 * `asterius_domain::ClientMetadata::validate` — one for a plaintext callback
 * (ADR-0005, OAuth Security BCP §2.1), one for a signing algorithm outside the
 * profile's three (ADR-0003, FAPI 2.0 SP §5.4.1) — and the console reaches that
 * validator through the same call `POST /register` makes.
 *
 * What is asserted is the pair: the server's own sentence is shown, and no
 * client appears in the inventory. A screen that showed the refusal and created
 * the client anyway would pass half of this.
 */
test('the console cannot register a client dynamic registration would refuse', async ({
  page,
}) => {
  // Arrange
  await signIn(page);
  await openClients(page);

  // Act: a plaintext callback.
  await fillNewClient(page, 'Refused by the validator', 'http://app.example.test/callback');
  await page.getByRole('button', { name: 'Register client' }).click();

  // Assert: the server's refusal, and no claim that anything was registered.
  const refusal = page.getByRole('alert');
  await expect(refusal).toBeVisible();
  await expect(refusal).toContainText(/redirect_uri|https/i);
  await expect(page.getByRole('status')).toHaveCount(0);

  // Act: a client with no key source at all, which RFC 7591 §2 leaves this
  // server nothing to verify a `private_key_jwt` assertion with.
  await page.getByLabel('Redirect URIs (one per line)', { exact: true }).fill('https://app.example.test/callback');
  await page.getByLabel('JWK Set URL').fill('');
  await page.getByRole('button', { name: 'Register client' }).click();

  // Assert
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.getByRole('status')).toHaveCount(0);

  // And nothing was written under either attempt. The rest of the refusals —
  // an algorithm off the list, a shared secret, both key sources at once — are
  // asserted against the same validator in
  // `crates/admin-api/src/router.rs`, where a table costs one test rather than
  // one browser round trip each.
  await page.getByRole('button', { name: 'Close' }).click();
  await page.getByLabel('Search clients').fill('Refused by the validator');
  await page.getByRole('button', { name: 'Search', exact: true }).click();
  await expect(page.getByText('No client matches.')).toBeVisible();
});

/**
 * The other half: a document this profile *does* accept is registered, appears
 * in the inventory, and can be opened and saved again unchanged.
 *
 * The last step is the one that rots silently — a rendering that dropped a
 * member would leave every visit to the edit screen one "Save" away from
 * rewriting the client.
 */
test('a valid client can be registered, found and saved again unchanged', async ({ page }) => {
  // Arrange
  await signIn(page);
  await openClients(page);
  const name = `Sweep client ${Date.now()}`;

  // Act
  await fillNewClient(page, name, 'https://app.example.test/callback');
  await page.getByRole('button', { name: 'Register client' }).click();

  // Assert: the server's `client_id`, which the console did not choose.
  const notice = page.getByRole('status');
  await expect(notice).toBeVisible();
  await expect(notice).toContainText(/Registered as c\./);
  await expect(page.getByRole('alert')).toHaveCount(0);

  // It is in the inventory, and it is what the search finds.
  await page.getByRole('button', { name: 'Close' }).click();
  await page.getByLabel('Search clients').fill(name);
  await page.getByRole('button', { name: 'Search', exact: true }).click();
  await expect(page.getByRole('cell', { name, exact: true })).toBeVisible();

  // And an unedited save is accepted.
  await page.getByRole('button', { name: `Edit ${name}` }).click();
  await expect(page.getByRole('heading', { name: /^Editing c\./ })).toBeVisible();
  await page.getByRole('button', { name: 'Save client' }).click();
  await expect(page.getByRole('status')).toContainText('Saved.');
  await expect(page.getByRole('alert')).toHaveCount(0);
});

test('the clients screen has no accessibility violation', async ({ page }, testInfo) => {
  // Arrange
  await signIn(page);
  await openClients(page);
  await page.getByRole('button', { name: 'Register a client' }).click();
  await expect(page.getByRole('heading', { name: 'New client' })).toBeVisible();

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

/**
 * **The logout half of `ast-bfn`.**
 *
 * Before this bead the signed-out screen was reachable only by a session that
 * expired in flight (`ast-xka`): an administrator could not end their own. The
 * assertion is not that the console changed screens — it could do that by
 * forgetting — but that the session is gone *at the server*, checked with an
 * isolated request context carrying the browser's cookies.
 */
test('an administrator can sign out, and the session is dead afterwards', async ({
  context,
  page,
}) => {
  // Arrange
  await signIn(page);
  await expect(page.getByRole('heading', { name: 'Asterius console' })).toBeVisible();

  // Act
  await page.getByRole('button', { name: 'Sign out' }).click();

  // Assert: the screen an administrator lands on, and no navigation loop.
  await expect(page.getByRole('heading', { name: 'Signed out' })).toBeVisible();
  expect(page.url()).toBe(CONSOLE_URL);

  // And the credential itself: whatever cookies the browser still holds, the
  // server no longer knows this session.
  const after = await context.request.get(`${BASE_URL}${SESSION_ENDPOINT}`);
  expect(after.status(), 'the session survived a sign-out').toBe(401);
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
