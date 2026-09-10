/**
 * The allowlist, swept (`ast-ndk.4`).
 *
 * The product rule is that the pages work without JavaScript, with a documented
 * list of exceptions. `crates/web/src/source_audit.rs` keeps that list from the
 * source side and fails the build for a template that acquires a `<script>`
 * without joining it. This is the other half, and it is not the same claim:
 * the audit reads templates, and a page is a template *plus* whatever the
 * handler decided to render — a partial, a widget, a future inclusion. Only a
 * browser sees the document that was actually sent.
 *
 * So this walks the pages a person reaches by opening a URL, in the no-JS
 * project, and holds each against `src/no-script.ts`. The pages that need a
 * whole flow to reach are held against the same list where they are already
 * walked, one call per page and no page asserted twice:
 *
 *  * `form_post.html` — `form-post.spec.ts`;
 *  * `device.html`, `device_confirm.html`, `device_done.html` — `no-js-device.spec.ts`;
 *  * `logout_confirm.html`, `logged_out.html`, `password_reset*.html`,
 *    `password_new.html` — `no-js-account.spec.ts`.
 *
 * The last test here is the negative proof, in the shape `csp-gate.spec.ts`
 * uses: a sweep whose gate never fires is a sweep that would pass over a page
 * that had quietly grown a script.
 */
import { expect, test } from '../src/fixtures.js';
import { BASE_URL, PASSWORD, USERNAME } from '../src/environment.js';
import { startAuthorization } from '../src/flow.js';
import { expectUsableWithoutScript, expectWithinScriptAllowlist } from '../src/no-script.js';

test('the error page carries no script', async ({ page }) => {
  // Arrange & Act: an authorization request naming nothing this server knows,
  // which RFC 6749 §4.1.2.1 makes a page rather than a redirect.
  await page.goto(
    `${BASE_URL}/authorize?client_id=nobody&request_uri=urn:ietf:params:oauth:request_uri:absent`,
  );

  // Assert
  await expectWithinScriptAllowlist(page, 'error.html');
});

test('the login page is allowed one script and works without it', async ({ page, request }) => {
  // Arrange & Act
  const flow = await startAuthorization(request);
  await page.goto(flow.authorizationUrl);

  // Assert: the passkey bootstrap, and nothing beside it.
  await expectWithinScriptAllowlist(page, 'login.html');
  // The mechanism the page always had, still real and still enabled.
  await expectUsableWithoutScript(page, 'login.html');
  // And the enhancement stays hidden, so no browser is shown a button that
  // could not work: `navigator.credentials.get()` is a call, not markup.
  await expect(page.getByRole('button', { name: 'Sign in with a passkey' })).toBeHidden();
});

test('the consent page carries no script', async ({ page, request }) => {
  // Arrange
  const flow = await startAuthorization(request);
  await page.goto(flow.authorizationUrl);

  // Act
  await page.locator('input[name="username"]').fill(USERNAME);
  await page.locator('input[name="password"]').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Allow' })).toBeVisible();

  // Assert
  await expectWithinScriptAllowlist(page, 'consent.html');
});

test('the passkey enrolment page is allowed one script and offers a way out', async ({
  page,
  request,
}) => {
  // Arrange: enrolment hangs off a session, and a session comes from signing in.
  const flow = await startAuthorization(request);
  await page.goto(flow.authorizationUrl);
  await page.locator('input[name="username"]').fill(USERNAME);
  await page.locator('input[name="password"]').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Allow' })).toBeVisible();

  // Act
  const response = await page.goto(`${BASE_URL}/passkeys`);

  // Assert: this is the one page whose subject really cannot be done without
  // script, so what it owes a browser without it is a way somewhere else.
  expect(response?.status(), 'a signed-in user must be able to reach enrolment').toBe(200);
  await expectWithinScriptAllowlist(page, 'passkey.html');
  await expectUsableWithoutScript(page, 'passkey.html');
});

test('the recovery page carries no script', async ({ page }) => {
  // Arrange & Act: the page a person reaches with no credential at all.
  await page.goto(`${BASE_URL}/recovery`);

  // Assert
  await expectWithinScriptAllowlist(page, 'password_reset.html');
});

/**
 * The negative proof: the gate fires.
 *
 * Run against a page that really does carry a script — the login page — under
 * a template name nobody allowlisted. The budget for an unlisted page is zero,
 * so the assertion must refuse it. Without this, every test above would pass
 * just as happily against a helper that counted nothing.
 */
test('a page that is not on the allowlist may carry no script', async ({ page, request }) => {
  // Arrange
  const flow = await startAuthorization(request);
  await page.goto(flow.authorizationUrl);
  expect(await page.locator('script').count(), 'this proof needs a page with a script').toBe(1);

  // Act & Assert
  await expect(
    expectWithinScriptAllowlist(page, 'a-page-nobody-allowlisted.html'),
    'a scripted page outside the allowlist was accepted',
    // The sentence for an *unlisted* page, not merely any refusal: a gate that
    // said "more script than permitted" would be one whose budget for an
    // unknown page had stopped being zero, which is the mutation that matters.
  ).rejects.toThrow(/is not on the allowlist in e2e\/src\/no-script\.ts/);
});
