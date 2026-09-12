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
import { type APIRequestContext, type Locator, type Page, expect, test } from '@playwright/test';
import {
  ADMIN_CONSOLE_URL,
  CONSOLE_URL,
  open as openScreen,
  signIn,
  signInAsDeploymentAdmin,
} from '../src/console.js';
import { CspWatcher } from '../src/csp.js';
import { ADMIN_BASE_URL, BASE_URL } from '../src/environment.js';

const ORIGIN = new URL(BASE_URL).origin;

/** Where the console reads who it is; the one API call the shell makes. */
const SESSION_ENDPOINT = '/admin/api/v1/session';

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

// ---------------------------------------------------------------------------
// The account screen (`ast-f7m.6`)
// ---------------------------------------------------------------------------

/**
 * A username nobody else in this run will use.
 *
 * The sweep runs against a database somebody keeps between runs, and creating
 * an account is not idempotent — the route answers 409 for a username this
 * tenant already holds, which is the behaviour a second run must not trip
 * over. A UUID rather than a counter, because the specs run in parallel.
 */
function freshUsername(): string {
  return `created-${crypto.randomUUID()}@example.test`;
}

/** The password the created accounts get; it passes the deployment's policy. */
const CREATED_PASSWORD = 'a created account passphrase';

/**
 * Creates an account through the screen and returns its username.
 *
 * Through the form and not through the API: what these tests are for is that
 * an administrator can do this in a browser, and a fixture inserted by `fetch`
 * would assert the route while skipping every part of that.
 */
async function createAccount(page: Page): Promise<string> {
  const username = freshUsername();
  await page.getByLabel('Username').fill(username);
  // Deliberately *not* the username. The directory renders both in the same
  // row, and an account whose two columns carry one string makes every locator
  // in this file ambiguous — which is how the first run of these tests failed,
  // on a strict-mode violation rather than on anything about the screen.
  await page.getByLabel('Email').fill(username.replace('created-', 'inbox-'));
  await page.getByLabel('Password').fill(CREATED_PASSWORD);
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByRole('cell', { name: username })).toBeVisible();
  return username;
}

/** Opens the account whose row names `username`. */
async function openAccount(page: Page, username: string): Promise<void> {
  await page
    .getByRole('row', { name: new RegExp(username.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) })
    .getByRole('button', { name: 'Open' })
    .click();
  await expect(page.getByRole('heading', { name: username })).toBeVisible();
}

test('the users screen is reachable from the navigation and creates an account', async ({
  page,
}) => {
  // Arrange
  await signIn(page);

  // Act
  await openScreen(page, 'Users', 'Users');
  const username = await createAccount(page);

  // Assert: the row is in the directory, and the search finds it.
  await page.getByLabel('Search').fill(username);
  await page.getByRole('button', { name: 'Search' }).click();
  await expect(page.getByRole('cell', { name: username })).toBeVisible();
});

test('an account can be disabled from the console', async ({ page }) => {
  // Arrange
  await signIn(page);
  await openScreen(page, 'Users', 'Users');
  const username = await createAccount(page);
  await openAccount(page, username);

  // Act: the console asks before it ends somebody's sessions (`ast-fe39`).
  // The question is the console's own dialog and no longer the browser's
  // `window.confirm`, so it is answered by clicking in it — which is also what
  // proves the dialog is reachable and its control is labelled.
  await page.getByRole('button', { name: 'Disable account' }).click();
  // `alertdialog` since `ast-gore`: the confirmation is Radix's `AlertDialog`,
  // which is the correct role for a modal that interrupts to ask a question —
  // an assistive technology announces its description immediately instead of
  // waiting to be asked. The rest of the claim is unchanged and still checked:
  // it is visible, it takes the focus, and its answer is a labelled control
  // inside it.
  const confirmation = page.getByRole('alertdialog');
  await expect(confirmation).toBeVisible();
  // The `aria-modal` attribute is gone with the hand-written dialog: Radix's
  // `AlertDialog` establishes modality by trapping focus and marking the rest
  // of the document, rather than by asserting it in an attribute. So what is
  // checked here is the behaviour that attribute stood in for, and it is the
  // half `ast-fe39` wrote down and never proved — **focus lands on the
  // cancelling control**, so that a stray Return answers "no" to a question
  // about disabling somebody's account.
  await expect(confirmation.getByRole('button', { name: 'Cancel' })).toBeFocused();
  await confirmation.getByRole('button', { name: 'Disable the account' }).click();

  // Assert: the account is off, and the screen says what the revocation did —
  // nothing, for an account that has never signed in, which is the honest
  // answer rather than a silent success.
  await expect(page.getByRole('button', { name: 'Enable account' })).toBeVisible();
  await expect(page.getByRole('definition').filter({ hasText: 'disabled' })).toBeVisible();
});

/**
 * The whole path the acceptance criterion names: a person signs in, an
 * administrator sees their session and ends it.
 *
 * The second browser context is what makes it real. The session under test has
 * to be somebody *else's* — an administrator ending their own would be signed
 * out mid-test, and the assertion would be about the shell rather than about
 * the revocation.
 */
test('a session belonging to somebody else can be ended from the console', async ({
  browser,
  page,
}) => {
  // Arrange: an account, and a browser signed in as it.
  await signIn(page);
  await openScreen(page, 'Users', 'Users');
  const username = await createAccount(page);

  const theirs = await browser.newContext({ ignoreHTTPSErrors: true });
  const theirPage = await theirs.newPage();
  await theirPage.goto(CONSOLE_URL);
  await theirPage.locator('input[name="username"]').fill(username);
  await theirPage.locator('input[name="password"]').fill(CREATED_PASSWORD);
  await theirPage.getByRole('button', { name: 'Sign in', exact: true }).click();
  // The account holds no role, so the shell starts and its first call —
  // `GET /session`, which is `Reach::Authenticated` and still demands *some*
  // authority — is a 403. What the person sees is the console refusing to
  // start, which is the honest outcome for somebody who is signed in and
  // administers nothing. The *session* exists either way, and that is the
  // whole point of this arrangement: the row the administrator is about to
  // end belongs to somebody else.
  await expect(theirPage.getByRole('heading', { name: 'The console could not start' })).toBeVisible();

  // Act
  await openAccount(page, username);
  await expect(page.getByRole('cell', { name: 'live' })).toBeVisible();
  await page.getByRole('button', { name: 'End session' }).click();

  // Assert: the row is no longer live, and the screen reports what was queued
  // for the relying parties that took part — none here, and it says so.
  await expect(page.getByRole('status')).toContainText('session ended');
  await expect(page.getByRole('button', { name: 'End session' })).toHaveCount(0);

  await theirs.close();
});

/**
 * The gap `ast-895` left in this harness, and the one `ast-axm` confirmed: the
 * fixture held `tenant_admin` only, so nothing here had ever put a
 * *deployment*-scoped console in front of a browser.
 *
 * The account is the one the `[admin]` table seeds, signing in on a password —
 * which `asterius_domain::admin_access_policy` admits because it has no
 * passkey to demand yet.
 */
test('a deployment administrator reaches the users screen', async ({ page }) => {
  // Arrange
  await signInAsDeploymentAdmin(page);

  // Assert: the shell is the deployment one — Tenants is a deployment-reach
  // destination and is hidden from a tenant admin.
  await expect(page.getByRole('link', { name: 'Tenants' })).toBeVisible();

  // Act
  await openScreen(page, 'Users', 'Users');

  // Assert: the directory answered rather than 403ing, so the screen shows its
  // list and its form rather than a refusal.
  await expect(page.getByRole('heading', { name: 'Add an account' })).toBeVisible();
});

test('the users screen provokes no CSP violation and passes axe', async ({ context, page }) => {
  // Arrange
  const watcher = await CspWatcher.attach(context, true);
  await signIn(page);

  // Act
  await openScreen(page, 'Users', 'Users');
  const username = await createAccount(page);
  await openAccount(page, username);

  // Assert
  const audit = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  expect(audit.violations, JSON.stringify(audit.violations, null, 2)).toEqual([]);
  watcher.assertClean('the users screen');
});

/** The entry document, so the deployment console is reachable at all. */
test('the reserved tenant serves a console of its own', async ({ page }) => {
  // Arrange / Act
  await signInAsDeploymentAdmin(page);
  const response = await page.goto(ADMIN_CONSOLE_URL);

  // Assert
  expect(response?.status()).toBe(200);
  await expect(page.getByRole('heading', { name: 'Asterius console' })).toBeVisible();
});

/**
 * Walks the navigation to the shared-signals screen (`ast-f7m.8`).
 *
 * By its link, like every screen above: the criterion is that the screen is
 * reachable through the navigation, and the tenant administrator the sweep
 * signs in as holds `admin.ssf:read`, which is what the link is gated on.
 */
async function openSharedSignals(page: Page): Promise<void> {
  await page.getByRole('link', { name: 'Shared signals' }).click();
  await expect(page.getByRole('heading', { name: 'Shared signals' })).toBeVisible();
  // Drawn from the two documents the API answered with: the streams table's
  // heading and the dead-letter table's, which the administrator may read.
  await expect(page.getByRole('heading', { name: 'Streams' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Dead letters' })).toBeVisible();
}

test('the shared-signals screen is reachable and reads the admin API', async ({
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
  await openSharedSignals(page);

  // Assert: the sweep's tenant has no receiver, so the honest answer is the
  // empty state, not a skeleton — and the read happened, or the sentence
  // would not be there.
  await expect(page.getByText('No stream.', { exact: false })).toBeVisible();
  expect(offOrigin, 'the shared-signals screen reached a third party').toEqual([]);
  watcher.assertClean('the shared-signals screen');
});

/**
 * Walks the navigation to the audit explorer (`ast-f7m.8`).
 */
async function openAudit(page: Page): Promise<void> {
  await page.getByRole('link', { name: 'Audit trail' }).click();
  await expect(page.getByRole('heading', { name: 'Audit trail' })).toBeVisible();
  await expect(page.getByLabel('Agent')).toBeVisible();
}

/**
 * **The export's RBAC, from the browser.** Provisioning the sweep's tenant
 * left `key.rotated` records (one per signing algorithm, written at boot), so
 * the trail is never empty whatever ran before this test; filtering it to
 * that type shows the rows with their chain, and the export link points at
 * the same filter and answers NDJSON to the session that holds
 * `admin.audit:read` — and a refusal to a request context that holds nothing.
 * (A password sign-in leaves no `auth.login` record today; only a passkey
 * sign-in does, which is why the filter is not on the login.)
 */
test('the audit explorer filters the trail and exports it as NDJSON', async ({
  page,
  request,
}) => {
  // Arrange
  await signIn(page);
  await openAudit(page);

  // Act
  await page.getByLabel('Event type').fill('key.rotated');
  await page.getByRole('button', { name: 'Apply filters' }).click();

  // Assert: the provisioning records, rendered with their chain.
  const rows = page.getByRole('row').filter({ hasText: 'key.rotated' });
  await expect(rows.first()).toBeVisible();
  await expect(rows.first().getByRole('list', { name: 'Delegation chain' })).toBeVisible();

  const link = page.getByRole('link', { name: 'Export as NDJSON' });
  await expect(link).toBeVisible();
  const href = await link.getAttribute('href');
  expect(href).toContain('type=key.rotated');

  // The export, fetched *with* the browser's cookies through the page's own
  // context: NDJSON, one JSON text per line, each naming its hash.
  const exported = await page.request.get(new URL(href ?? '', CONSOLE_URL).toString());
  expect(exported.status()).toBe(200);
  expect(exported.headers()['content-type']).toContain('application/x-ndjson');
  const lines = (await exported.text()).split('\n').filter((line) => line !== '');
  expect(lines.length).toBeGreaterThan(0);
  for (const line of lines) {
    const record = JSON.parse(line) as { hash?: unknown; type?: unknown };
    expect(record.hash).toEqual(expect.any(String));
    expect(record.type).toBe('key.rotated');
  }

  // And without a session — the isolated request context — the same URL is
  // refused, which is the server's decision and not this screen's.
  const refused = await request.get(new URL(href ?? '', CONSOLE_URL).toString());
  expect(refused.status()).toBe(401);
});

/** Walks the navigation to the policy editor (`ast-f7m.9`). */
async function openPolicy(page: Page): Promise<void> {
  await page.getByRole('link', { name: 'Policy' }).click();
  await expect(page.getByRole('heading', { name: 'Policy', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Try a request' })).toBeVisible();
}

/**
 * **The screen's whole loop, in a browser** (`ast-f7m.9`): write a document,
 * have the server refuse a bad one with the path it names, save a good one,
 * and ask the bench what it decides.
 *
 * The rules are deliberately ones whose answer does not depend on the sweep
 * tenant's directory: a `permit` on the action alone, and the default deny for
 * an action no rule names. A rule reading a group would be asserting what
 * somebody's account claims, which is another screen's business.
 *
 * The document is left removed at the end, which is the state every other test
 * in this file expects of the tenant: an evaluation denied.
 */
test('the policy editor refuses a bad document, saves a good one and answers the bench', async ({
  page,
}) => {
  // Arrange
  await signIn(page);
  await openPolicy(page);
  const document = page.getByLabel('The rule document, as the evaluator reads it');

  // Act: a condition no build of this server knows.
  await document.fill(
    JSON.stringify(
      { version: 1, rules: [{ id: 'bad', effect: 'permit', when: { eval: '1 + 1' } }] },
      null,
      2,
    ),
  );
  await page.getByRole('button', { name: 'Save policy' }).click();

  // Assert: the refusal names the path in the document, which is the whole
  // point of showing the server's message rather than "save failed".
  const refusal = page.getByRole('alert');
  await expect(refusal).toContainText('rules[0].when');

  // Act: a document this build does read.
  await document.fill(
    JSON.stringify(
      {
        version: 1,
        rules: [
          {
            id: 'anyone-may-read',
            effect: 'permit',
            actions: ['read'],
            reason_admin: 'reading is open to every subject',
          },
        ],
      },
      null,
      2,
    ),
  );
  await page.getByRole('button', { name: 'Save policy' }).click();
  await expect(page.getByText('The policy was replaced.')).toBeVisible();
  await expect(page.getByRole('cell', { name: 'anyone-may-read' })).toBeVisible();

  // Act: the bench, on a request the rule permits.
  await page.getByLabel('Subject', { exact: true }).fill('somebody');
  await page.getByLabel('Action').fill('read');
  await page.getByLabel('Resource type').fill('document');
  await page.getByLabel('Resource', { exact: true }).fill('42');
  await page.getByRole('button', { name: 'Ask the policy' }).click();

  // Assert: the decision, and the reason the rule carries — read out of the
  // decision itself and not off the page, where the document above spells the
  // same words.
  const decision = page.getByRole('region', { name: 'Decision' });
  await expect(decision.getByText('permit', { exact: true })).toBeVisible();
  await expect(decision.getByText('reading is open to every subject')).toBeVisible();
  await expect(decision.getByText('anyone-may-read')).toBeVisible();

  // Act: an action no rule names is the default deny.
  await page.getByLabel('Action').fill('delete');
  await page.getByRole('button', { name: 'Ask the policy' }).click();

  // Assert
  await expect(decision.getByText('deny', { exact: true })).toBeVisible();

  // The tenant goes back to denying everything, which is how this file's
  // other tests find it.
  await page.getByRole('button', { name: 'Remove policy' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Remove it' }).click();
  await expect(page.getByText('The policy was removed.', { exact: false })).toBeVisible();
});

test('the shared-signals, audit and policy screens have no accessibility violation', async (
  { page },
  testInfo,
) => {
  // Arrange
  await signIn(page);

  for (const [open, name] of [
    [openSharedSignals, 'shared-signals'],
    [openAudit, 'audit'],
    [openPolicy, 'policy'],
  ] as const) {
    await open(page);

    // Act
    const results = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
      .analyze();

    // Assert
    await testInfo.attach(`axe-${name}`, {
      body: JSON.stringify(results.violations, null, 2),
      contentType: 'application/json',
    });
    expect(results.violations, `${name} screen`).toEqual([]);
  }
});

/**
 * The tenants screen, walked by the only caller who can open it (`ast-l5bl`).
 *
 * `reach: 'deployment'` is not decoration: the link is absent for the
 * `tenant_admin` every other test in this file signs in as, and the routes
 * behind it refuse that caller as well. So this scenario is the deployment
 * administrator's from end to end — list, creation, suspension, restoration,
 * and the hand-off to that tenant's settings — and every step goes through the
 * screen's own controls, because a `fetch` would be asserting the API that
 * `crates/admin-api/src/router.rs` already covers.
 *
 * The tenant it creates is named `sweep-…`, and `e2e/fixtures/seed.sql` deletes
 * that prefix before each run: no route deletes a tenant, so a database kept
 * between runs would otherwise fill the first page of a cursor-paginated list
 * with the leftovers of previous ones.
 */
function sweepTenantId(): string {
  // `crypto.randomUUID`, reduced to the characters `TenantId::parse` accepts
  // (lowercase, digits, `-` and `_`) and short enough to read in a failure.
  return `sweep-${crypto.randomUUID().replace(/-/g, '').slice(0, 10)}`;
}

/**
 * The table row for one tenant, found by its issuer.
 *
 * By the issuer and not by the id, because the id cell also carries a display
 * name when the tenant has one — the reserved tenant does — and because an
 * issuer is exact where an id is a prefix of its siblings: a cell named `e2e`
 * matches the `e2e-admin` row too.
 */
function tenantRow(page: Page, issuer: string): Locator {
  return page
    .getByRole('row')
    .filter({ has: page.getByRole('cell', { name: issuer, exact: true }) });
}

test('a deployment administrator lists, creates, suspends and restores a tenant', async ({
  context,
  page,
}, testInfo) => {
  // Arrange
  const watcher = await CspWatcher.attach(context, true);
  await signInAsDeploymentAdmin(page);
  await openScreen(page, 'Tenants', 'Tenants');

  // Assert: the deployment's tenants are listed beside each other, the
  // reserved one included. This screen is the only place that happens.
  await expect(tenantRow(page, BASE_URL)).toBeVisible();
  await expect(tenantRow(page, ADMIN_BASE_URL)).toBeVisible();
  // The features column is filled in by a second read per row, so it starts as
  // an em dash and becomes a sentence. Either wording is an answer; an em dash
  // that never changes would mean the settings document never arrived.
  await expect(tenantRow(page, BASE_URL).getByText(/all on|off: /)).toBeVisible();

  // Act: create one, asking for nothing the provisioning route does not take.
  const id = sweepTenantId();
  const issuer = `${ORIGIN}/t/${id}`;
  await page.getByLabel('Tenant id').fill(id);
  await page.getByLabel('Issuer').fill(issuer);
  await page.getByRole('button', { name: 'Create tenant' }).click();

  // Assert: the server made it, with its signing keys, and it is in the list.
  await expect(page.getByRole('status').first()).toContainText('with its signing keys');
  await expect(tenantRow(page, issuer).getByText('active', { exact: true })).toBeVisible();

  // Act: suspend it, which is a confirmed act rather than a button press.
  await tenantRow(page, issuer).getByRole('button', { name: 'Suspend' }).click();
  const dialog = page.getByRole('alertdialog');
  await expect(dialog).toContainText('fails to obtain a token');
  await dialog.getByRole('button', { name: 'Suspend tenant' }).click();

  // Assert
  await expect(page.getByRole('status').first()).toContainText('is suspended');
  await expect(tenantRow(page, issuer).getByText('disabled', { exact: true })).toBeVisible();

  // Act: and back, because a suspension an operator cannot undo from the same
  // screen is a support ticket.
  await tenantRow(page, issuer).getByRole('button', { name: 'Restore' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Restore tenant' }).click();

  // Assert
  await expect(page.getByRole('status').first()).toContainText('serving again');
  await expect(tenantRow(page, issuer).getByText('active', { exact: true })).toBeVisible();

  // Act: the hand-off. A fragment on this same console, because the settings
  // routes name their tenant in the path and admit a deployment-scoped caller
  // for any of them.
  await tenantRow(page, issuer).getByRole('link', { name: 'Settings' }).click();

  // Assert: the settings screen, looking at the tenant just created, and
  // saying whose settings these are.
  await expect(page.getByRole('heading', { name: 'Tenant settings' })).toBeVisible();
  await expect(page.getByRole('status').first()).toContainText('opened from the tenant list');
  await expect(page.getByRole('status').first()).toContainText(id);

  // Assert: and no accessibility violation on the screen this test is about.
  await openScreen(page, 'Tenants', 'Tenants');
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  await testInfo.attach('axe-tenants', {
    body: JSON.stringify(results.violations, null, 2),
    contentType: 'application/json',
  });
  expect(results.violations, 'tenants screen').toEqual([]);
  watcher.assertClean('the tenants screen');
});

/**
 * The other half of `reach: 'deployment'`: the screen is not offered to a
 * tenant admin at all.
 *
 * Only the link is asserted here, deliberately. Whether the *routes* refuse a
 * tenant admin is not a browser question and is not left to one: the registry
 * walk in `crates/admin-api/src/router.rs`
 * (`a_tenant_admin_is_refused_exactly_the_deployment_scoped_routes`) asserts it
 * for every deployment-reach route there is, including the three this screen
 * calls. What a browser can add is that the navigation agrees with them.
 */
test('a tenant admin is offered no tenants screen', async ({ page }) => {
  // Arrange
  await signIn(page);
  await expect(page.getByRole('navigation', { name: 'Console sections' })).toBeVisible();

  // Act / Assert
  await expect(page.getByRole('link', { name: 'Tenants' })).toHaveCount(0);
});

/**
 * `ast-gore` (2): the console opens light, and remembers what it was told.
 *
 * The bead exists because it did neither. The owner's console rendered dark
 * with no way back, because the palette hung off `prefers-color-scheme` — a
 * browser setting answering a question nobody had asked it. So the two halves
 * are asserted here and in a browser, which is the only place a class on
 * `<html>` and a `localStorage` write that survives a reload can be seen.
 */
test('the console opens in the light theme and remembers the dark one', async ({
  page,
}) => {
  // Arrange: a browser that prefers dark, which is exactly the case that used
  // to decide for the administrator.
  await page.emulateMedia({ colorScheme: 'dark' });
  await signIn(page);

  // Assert: light all the same. `.dark` on the root element is the whole
  // switch (`console/src/tokens.css`).
  await expect(page.locator('html')).not.toHaveClass(/dark/);

  // Act
  await page.getByRole('button', { name: 'Switch to the dark theme' }).click();

  // Assert: applied…
  await expect(page.locator('html')).toHaveClass(/dark/);
  // …and remembered, which a reload is the only honest test of.
  await page.reload();
  await expect(page.locator('html')).toHaveClass(/dark/);
  await expect(page.getByRole('button', { name: 'Switch to the light theme' })).toBeVisible();
});

/**
 * `ast-gore` (3): the rail folds, and folding it loses no destination.
 *
 * The icon mode is where a sidebar usually stops being usable: the labels go,
 * and with them the accessible names, so a screen reader is left with nine
 * buttons called nothing. The shortcut is asserted alongside it because it is
 * the way back to the rail once it is folded, without a pointer.
 */
test('the sidebar folds to icons without losing a destination', async ({ page }) => {
  // Arrange
  await signIn(page);
  const sidebar = page.locator('[data-slot="sidebar"]').first();
  await expect(sidebar).toHaveAttribute('data-state', 'expanded');

  // Act: the documented shortcut, not the button.
  await page.keyboard.press('Control+b');

  // Assert: folded, and Users is still a link that says "Users".
  await expect(sidebar).toHaveAttribute('data-state', 'collapsed');
  await expect(page.getByRole('link', { name: 'Users' })).toBeVisible();

  // Act / Assert: and it comes back.
  await page.keyboard.press('Control+b');
  await expect(sidebar).toHaveAttribute('data-state', 'expanded');
});

/**
 * `ast-gore` (4): the tenant selector, as the caller who may use it.
 *
 * Two claims, and the second is the one worth a browser. The list is
 * `GET /tenants`, which only a deployment-scoped caller may read. And choosing
 * a tenant **navigates to that tenant's own console** — the console is mounted
 * beneath the tenant it serves and every admin API call it makes is relative
 * to its own document, so a selector that swapped an id into this page's state
 * would leave those calls pointing at the first tenant's API. The URL is built
 * from the issuer the API reports, which is why a tenant on a custom host
 * works and a URL assembled from this page's location would not.
 */
test('the tenant selector lists the deployment and hands over to the chosen console', async ({
  page,
}) => {
  // Arrange
  await signInAsDeploymentAdmin(page);

  // Act
  await page.getByRole('combobox', { name: /Switch tenant/ }).click();

  // Assert: the deployment's tenants, including the one this session is in.
  const options = page.getByRole('option');
  await expect(options.filter({ hasText: 'e2e-admin' })).toBeVisible();
  await expect(options.filter({ hasText: 'e2e-webauthn' })).toBeVisible();

  // Act: choose another one.
  await options.filter({ hasText: 'e2e-webauthn' }).first().click();

  // Assert: the browser is at *that tenant's* console, which — having no
  // session there — is the login door `ast-wr4` put in front of it. Landing on
  // a sign-in rather than on a shell is the correct outcome, and it is the
  // proof that the hand-off is a navigation and not a swapped variable.
  await page.waitForURL(/t\/e2e-webauthn\//);
});

/**
 * The other half: a tenant admin is offered no other tenant.
 *
 * `GET /tenants` is deployment-scoped, so the selector must not call it — a
 * 403 drawn as a broken menu is worse than no menu. It says so instead.
 */
test('a tenant admin is offered no other tenant to switch to', async ({ page }) => {
  // Arrange
  await signIn(page);

  // Act
  await page.getByRole('combobox', { name: /Switch tenant/ }).click();

  // Assert
  await expect(page.getByText('and no other tenant')).toBeVisible();
  await expect(page.getByRole('option')).toHaveCount(0);
});
