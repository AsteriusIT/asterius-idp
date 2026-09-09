/**
 * `ast-ndk.6`: zero CSP violations across the no-JS *and* the JS suite.
 *
 * Both projects in `playwright.config.ts` run this file. The JS one is not
 * redundant: `script-src 'nonce-…' 'strict-dynamic'` says nothing at all to a
 * browser that will not run script, so the no-JS suite cannot tell a correct
 * nonce from a missing one. Only a browser with script enabled can.
 *
 * The header itself is asserted alongside the browser's behaviour. A page that
 * provoked no violation because it was served *no policy* would otherwise pass
 * this sweep, which is the one way a CSP test can be vacuous.
 */
import { expect, test } from '../src/fixtures.js';
import { BASE_URL, PASSWORD, USERNAME } from '../src/environment.js';
import { startAuthorization } from '../src/flow.js';

/** Every directive `asterius_web::csp::Policy::strict` renders. */
const REQUIRED_DIRECTIVES = [
  "default-src 'none'",
  "style-src 'nonce-",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "object-src 'none'",
];

/** Asserts that a document was served the strict policy, nonce and all. */
async function expectStrictPolicy(header: string | null): Promise<void> {
  expect(header, 'the document was served no Content-Security-Policy').toBeTruthy();
  const policy = header ?? '';
  for (const directive of REQUIRED_DIRECTIVES) {
    expect(policy, `missing directive: ${directive}`).toContain(directive);
  }
  expect(policy, 'script-src carries no nonce').toMatch(/script-src 'nonce-[^']+' 'strict-dynamic'/);
}

test('the error page is served the strict policy and violates none of it', async ({ page }) => {
  // Arrange: an authorization request that names nothing this server knows.
  // RFC 6749 §4.1.2.1 makes that a page rather than a redirect, which is
  // precisely why the error page is reachable without a flow.
  const response = await page.goto(
    `${BASE_URL}/authorize?client_id=nobody&request_uri=urn:ietf:params:oauth:request_uri:absent`,
  );

  // Assert
  expect(response?.status()).toBeGreaterThanOrEqual(400);
  await expectStrictPolicy(response?.headers()['content-security-policy'] ?? null);
  expect(await page.locator('script').count()).toBe(0);
  // The fixture asserts the absence of violations at teardown.
});

test('the login page is served the strict policy and violates none of it', async ({
  page,
  request,
}) => {
  // Arrange
  const flow = await startAuthorization(request);

  // Act
  const response = await page.goto(flow.authorizationUrl);

  // Assert
  await expectStrictPolicy(response?.headers()['content-security-policy'] ?? null);
  await expect(page.locator('input[name="password"]')).toBeVisible();
});

test('the consent page is served the strict policy and violates none of it', async ({
  page,
  request,
}) => {
  // Arrange
  const flow = await startAuthorization(request);
  await page.goto(flow.authorizationUrl);
  await page.locator('input[name="username"]').fill(USERNAME);
  await page.locator('input[name="password"]').fill(PASSWORD);

  // Act: the consent screen is the *response* to the login POST, not a
  // redirect, so the header has to be read off that response.
  const [response] = await Promise.all([
    page.waitForResponse((candidate) => candidate.request().method() === 'POST'),
    page.getByRole('button', { name: 'Sign in' }).click(),
  ]);

  // Assert
  await expect(page.getByRole('button', { name: 'Allow' })).toBeVisible();
  await expectStrictPolicy(response.headers()['content-security-policy'] ?? null);
});

/**
 * The one page in the tree that runs script — `crates/web/templates/passkey.html`,
 * exempted by name in `SCRIPTED_TEMPLATES` — has no route yet: `ast-2vk.15`
 * owns `/passkeys/options` and `/passkeys/finish` and has not landed. Until it
 * does there is no URL at which a browser can be shown the page, so the JS
 * suite exercises `'strict-dynamic'` only through the negative proof in
 * `csp-gate.spec.ts`.
 *
 * Left as a `fixme` rather than deleted: it is the assertion the day the route
 * exists, and a skipped test that names its blocker is visible in every run.
 */
test.fixme(
  'the passkey page runs its nonced script and violates nothing (needs ast-2vk.15)',
  async () => {},
);
