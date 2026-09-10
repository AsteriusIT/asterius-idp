/**
 * axe over every page this server renders and really serves (`ast-rna`,
 * absorbing `ast-xq0`).
 *
 * `ast-ndk.2` asked for an accessibility sweep and got one over three pages —
 * error, login and consent — asserted incidentally inside the CSP sweep. Since
 * then the passkey page and both logout pages became routes an ordinary user
 * reaches, and nothing checked them. This file is the sweep as a subject of its
 * own: one test per page, so a violation names the page it is on.
 *
 * # Which pages are here, and which are not
 *
 * Everything in `crates/web/templates` that a route actually renders today:
 * error, login, consent, the passkey enrolment page, the logout confirmation
 * and the signed-out page. The eight templates for the device flow, for
 * registration and for password recovery are *not* wired to any route (the
 * handlers do not exist yet), and a test that reached for them would be a test
 * of nothing. They arrive with the beads that route them.
 *
 * `form_post.html` is also absent, deliberately: it is a document whose only
 * content is a form that submits itself on load, so it is never a page a person
 * is looking at. `form-post.spec.ts` asserts what it is for.
 *
 * The console's screens are swept where they live — `console.spec.ts` and
 * `key-rotation.spec.ts` — because each is reached by driving the shell.
 *
 * # Why the JS project
 *
 * axe-core is script: it is injected into the page and run there. So this file
 * is ignored by the no-JS project, which is not a gap — WCAG conformance is a
 * property of the markup, and the markup is what the server sent either way.
 */
import AxeBuilder from '@axe-core/playwright';
import type { Page, TestInfo } from '@playwright/test';
import { signIn } from '../src/console.js';
import { BASE_URL, PASSWORD, USERNAME } from '../src/environment.js';
import { expect, test } from '../src/fixtures.js';
import { startAuthorization } from '../src/flow.js';

/**
 * Runs axe over whatever the page is showing, and fails on any violation.
 *
 * WCAG 2.1 level AA, which is the bar `ast-ndk.2` set and the one most public
 * procurement asks for. The report is attached whether or not it is empty: a
 * failure that only says "1 violation" costs whoever reads it a local run.
 */
async function expectNoViolation(page: Page, testInfo: TestInfo): Promise<void> {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  await testInfo.attach('axe', {
    body: JSON.stringify(results.violations, null, 2),
    contentType: 'application/json',
  });
  expect(results.violations).toEqual([]);
}

/** Signs in through the flow and stops on the consent screen. */
async function reachConsent(page: Page, authorizationUrl: string): Promise<void> {
  await page.goto(authorizationUrl);
  await page.locator('input[name="username"]').fill(USERNAME);
  await page.locator('input[name="password"]').fill(PASSWORD);
  await Promise.all([
    page.waitForResponse((candidate) => candidate.request().method() === 'POST'),
    page.getByRole('button', { name: 'Sign in', exact: true }).click(),
  ]);
  await expect(page.getByRole('button', { name: 'Allow' })).toBeVisible();
}

test('the error page has no accessibility violation', async ({ page }, testInfo) => {
  // Arrange: an authorization request naming nothing this server knows, which
  // RFC 6749 §4.1.2.1 makes a page rather than a redirect.
  const response = await page.goto(
    `${BASE_URL}/authorize?client_id=nobody&request_uri=urn:ietf:params:oauth:request_uri:absent`,
  );
  expect(response?.status()).toBeGreaterThanOrEqual(400);

  // Act & Assert
  await expectNoViolation(page, testInfo);
});

test('the login page has no accessibility violation', async ({ page, request }, testInfo) => {
  // Arrange
  const flow = await startAuthorization(request);
  await page.goto(flow.authorizationUrl);
  await expect(page.locator('input[name="password"]')).toBeVisible();

  // Act & Assert
  await expectNoViolation(page, testInfo);
});

test('the consent page has no accessibility violation', async ({ page, request }, testInfo) => {
  // Arrange
  const flow = await startAuthorization(request);
  await reachConsent(page, flow.authorizationUrl);

  // Act & Assert
  await expectNoViolation(page, testInfo);
});

test('the passkey enrolment page has no accessibility violation', async ({
  page,
  request,
}, testInfo) => {
  // Arrange: enrolment hangs off a session, and a session comes from signing in.
  const flow = await startAuthorization(request);
  await reachConsent(page, flow.authorizationUrl);
  const response = await page.goto(`${BASE_URL}/passkeys`);
  expect(response?.status(), 'a signed-in user must be able to reach enrolment').toBe(200);

  // Act & Assert
  await expectNoViolation(page, testInfo);
});

test('the logout confirmation page has no accessibility violation', async ({ page }, testInfo) => {
  // Arrange: a bare `GET /logout` carrying a session is the request OIDC
  // RP-Initiated Logout 1.0 §2 makes this server *ask* about, so this page is
  // reached by asking for a logout and nothing else.
  await signIn(page);
  await page.goto(`${BASE_URL}/logout`);
  await expect(page.getByRole('button', { name: 'Log out' })).toBeVisible();

  // Act & Assert
  await expectNoViolation(page, testInfo);
});

/**
 * **A documented failure, and a defect this sweep found (`ast-rna`).**
 *
 * The confirmation page above posts to
 * `asterius_oidc::metadata::Endpoint::EndSession.path()` — the bare `/logout`,
 * root-relative and with no mount prefix
 * (`crates/server/src/http/logout.rs::confirmation_page`). A tenant reached at
 * `/t/{id}` therefore loses its tenant on the answer, and the browser gets a
 * 404 instead of the signed-out page: pressing "Log out" on a path-routed
 * tenant ends nothing. `ast-295` made the rendered URLs carry their prefix and
 * this page was missed; `ast-f0y` then removed the `custom_host` fixture that
 * had been hiding it, which is why it is visible now.
 *
 * Marked `test.fail()` rather than deleted, on the precedent `ast-jsq` set in
 * `no-js-flow.spec.ts`: the assertion is what the page must do, and the day
 * the action carries its prefix this test passes unexpectedly and fails the
 * run until the annotation is removed. Fixing the handler belongs to whoever
 * owns that file, not to a bead about CI.
 */
test('the signed-out page has no accessibility violation', async ({ page }, testInfo) => {
  test.fail(true, 'the confirmation form posts to /logout without the tenant prefix');

  // Arrange: the answer to the question above.
  await signIn(page);
  await page.goto(`${BASE_URL}/logout`);
  await page.getByRole('button', { name: 'Log out' }).click();
  await expect(page.getByRole('heading', { name: 'You are signed out' })).toBeVisible();

  // Act & Assert
  await expectNoViolation(page, testInfo);
});
