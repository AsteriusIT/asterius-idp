/**
 * The account pages, with JavaScript disabled (`ast-ndk.4`).
 *
 * Password recovery (`ast-2vk.10`) and RP-initiated logout are the two places a
 * person acts on their *account* rather than on an authorization, and they are
 * the two most likely to be reached from somewhere odd: a link opened in a
 * mail client's embedded browser, a shared machine, a corporate profile with
 * scripting switched off. A recovery flow that needed script would strand
 * exactly the person who has already lost their way in.
 *
 * The Rust tests cover what these handlers decide. What only a browser can show
 * is that the pages are usable at all with no script: that the reset form
 * submits, that the mailed link opens a page a person can complete, and that
 * pressing "Log out" really ends the session rather than landing on a 404 —
 * which is what it did on a path-routed tenant until `ast-295`.
 *
 * `src/fixtures.ts` fails any test during which the browser refused something,
 * so the CSP claim is swept here without a line per page.
 */
import type { Page } from '@playwright/test';
import { expect, test } from '../src/fixtures.js';
import { BASE_URL, PASSWORD, TENANT, USERNAME } from '../src/environment.js';
import { startAuthorization } from '../src/flow.js';
import { latestRecoveryLink } from '../src/outbox.js';
import { expectWithinScriptAllowlist } from '../src/no-script.js';

/**
 * The password this test moves the fixture user to, and back off again.
 *
 * A reset that set the same password would prove nothing: the page would look
 * identical whether the credential was written or silently dropped. So the
 * value differs, and the test restores the fixture's own before it ends —
 * `seed.sql` rewrites the hash on every run, but the specs after this one in a
 * single run would meet whatever it left behind.
 */
const REPLACEMENT = 'a second browser sweep passphrase';

/** Signs in through a real authorization request and stops at consent. */
async function signIn(page: Page, authorizationUrl: string, password: string): Promise<void> {
  await page.goto(authorizationUrl);
  await page.locator('input[name="username"]').fill(USERNAME);
  await page.locator('input[name="password"]').fill(password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
}

/** Walks a whole reset, from the form to the link to the new credential. */
async function reset(page: Page, to: string): Promise<void> {
  // --- The ask ------------------------------------------------------------
  await page.goto(`${BASE_URL}/recovery`);
  await expect(page.getByRole('heading', { name: 'Reset your password' })).toBeVisible();
  await expectWithinScriptAllowlist(page, 'password_reset.html');
  await page.locator('input[name="email"]').fill(USERNAME);
  await page.getByRole('button', { name: 'Send the link' }).click();

  // The same page for an address this server knows and one it does not, which
  // is the whole design of it: an enumeration oracle on a reset form is the
  // classic one.
  await expect(page.getByRole('heading', { name: 'Check your email' })).toBeVisible();
  await expectWithinScriptAllowlist(page, 'password_reset_sent.html');

  // --- The link -----------------------------------------------------------
  // Read from the outbox, which is where the only sender this repository ships
  // puts it. It is a credential; see `src/outbox.ts`.
  const link = await latestRecoveryLink(TENANT, USERNAME);
  expect(link, 'the mailed link left the tenant it was issued for').toContain(`${BASE_URL}/recovery/new`);
  await page.goto(link);
  await expect(page.getByRole('heading', { name: 'Choose a new password' })).toBeVisible();
  await expectWithinScriptAllowlist(page, 'password_new.html');

  // --- The new credential -------------------------------------------------
  await page.locator('input[name="password"]').fill(to);
  await page.locator('input[name="password_confirmation"]').fill(to);
  await page.getByRole('button', { name: 'Save the new password' }).click();
  // A 303 to the tenant's own root: the flow is over and there is nothing to
  // say that a page would not also be a page a spent token leads to.
  await page.waitForURL(`${BASE_URL}**`);
}

test('a password is recovered without JavaScript, and the new one signs in', async ({
  page,
  request,
}) => {
  // --- Act ----------------------------------------------------------------
  await reset(page, REPLACEMENT);

  // --- Assert: the credential really changed ------------------------------
  await signIn(page, (await startAuthorization(request)).authorizationUrl, REPLACEMENT);
  await expect(
    page.getByRole('button', { name: 'Allow' }),
    'the password the reset wrote does not sign in',
  ).toBeVisible();

  // --- Restore: the fixture's own password, through the same flow ---------
  await reset(page, PASSWORD);
  await signIn(page, (await startAuthorization(request)).authorizationUrl, PASSWORD);
  await expect(
    page.getByRole('button', { name: 'Allow' }),
    'the fixture password was not restored; later specs in this run would fail',
  ).toBeVisible();
});

test('a session is ended by a browser that runs no script', async ({ page, request }) => {
  // --- Arrange: a session, made the way a person makes one ----------------
  await signIn(page, (await startAuthorization(request)).authorizationUrl, PASSWORD);
  await expect(page.getByRole('button', { name: 'Allow' })).toBeVisible();

  // --- Act: OIDC RP-Initiated Logout 1.0 §2, the bare GET a link is -------
  await page.goto(`${BASE_URL}/logout`);
  await expectWithinScriptAllowlist(page, 'logout_confirm.html');
  await page.getByRole('button', { name: 'Log out' }).click();

  // --- Assert: the page says so... ----------------------------------------
  await expect(page.getByRole('heading', { name: 'You are signed out' })).toBeVisible();
  await expectWithinScriptAllowlist(page, 'logged_out.html');

  // --- ...and the session is gone, which is the part a page can lie about --
  await page.goto((await startAuthorization(request)).authorizationUrl);
  await expect(
    page.locator('input[name="password"]'),
    'the next authorization did not ask for a password, so the session survived the logout',
  ).toBeVisible();
});
