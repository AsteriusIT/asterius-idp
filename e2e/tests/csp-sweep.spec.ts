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
import { BASE_URL, PASSWORD, REDIRECT_URI, USERNAME } from '../src/environment.js';
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

/**
 * Asserts that `form-action` names nothing but this server (`ast-jsq`).
 *
 * Only the consent screen may widen it, by exactly the origin of the
 * `redirect_uri` of the authorization in hand. Every other page keeps the
 * strict directive, and this is what fails if the widening ever leaks into a
 * page that has no redirect to deliver.
 */
function expectNoWidening(header: string | null): void {
  expect(header ?? '', 'form-action names an origin this page does not submit to').toContain(
    "form-action 'self';",
  );
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
  expectNoWidening(response?.headers()['content-security-policy'] ?? null);
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
  expectNoWidening(response?.headers()['content-security-policy'] ?? null);
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
  // The one documented widening: this page's form ends up, through the 303
  // that carries the code, at the client's callback origin and nowhere else
  // (`ast-jsq`).
  expect(response.headers()['content-security-policy'] ?? '').toContain(
    `form-action 'self' ${new URL(REDIRECT_URI).origin};`,
  );
});

/**
 * The one page in the tree that runs script — `crates/web/templates/passkey.html`,
 * exempted by name in `SCRIPTED_TEMPLATES` — and therefore the only place the
 * JS suite exercises `script-src 'nonce-…' 'strict-dynamic'` positively. Every
 * other assertion about that directive is a negative one: `csp-gate.spec.ts`
 * proves an *un*-nonced script is refused, which a page with no script at all
 * cannot distinguish from a policy that permits nothing.
 *
 * Reached with a session cookie, so the arrangement is a real sign-in. The
 * ceremony itself is not driven here: `navigator.credentials.create()` needs an
 * authenticator, and what this asserts is that the page is served, policed and
 * *runs*.
 */
test('the passkey page runs its nonced script and violates nothing', async ({ page, request }) => {
  // Arrange: enrolment hangs off a session, and a session comes from signing in.
  const flow = await startAuthorization(request);
  await page.goto(flow.authorizationUrl);
  await page.locator('input[name="username"]').fill(USERNAME);
  await page.locator('input[name="password"]').fill(PASSWORD);
  await Promise.all([
    page.waitForResponse((candidate) => candidate.request().method() === 'POST'),
    page.getByRole('button', { name: 'Sign in' }).click(),
  ]);

  // Act
  const response = await page.goto(`${BASE_URL}/passkeys`);

  // Assert
  expect(response?.status(), 'a signed-in user must be able to reach enrolment').toBe(200);
  await expectStrictPolicy(response?.headers()['content-security-policy'] ?? null);
  // Nothing here submits anywhere, so the consent screen's one widening
  // (`ast-jsq`) must not have followed the session onto this page.
  expectNoWidening(response?.headers()['content-security-policy'] ?? null);
  // `ast-ndk.7`'s no-JS requirement, asserted through the wiring rather than
  // through the template: the password path is in the markup either way.
  await expect(page.getByRole('link', { name: /password/i })).toBeVisible();

  if (test.info().project.name === 'js') {
    // The script ran. Either it revealed the button, or it found no WebAuthn
    // API and said so — both are it executing under the nonce, and which one
    // depends on the browser rather than on this server.
    const revealed = await page.locator('#passkey-register').isVisible();
    const explained = (await page.locator('#passkey-status').innerText()).trim().length > 0;
    expect(revealed || explained, 'the nonced inline script did not run').toBe(true);
  } else {
    // With scripting off there is no button that cannot work — which is the
    // whole reason it starts `hidden` and is revealed rather than disabled.
    await expect(page.locator('#passkey-register')).toBeHidden();
  }
  // The fixture asserts the absence of violations at teardown.
});
