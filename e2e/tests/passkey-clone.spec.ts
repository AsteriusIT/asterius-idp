/**
 * `ast-qwu`: a cloned authenticator, in a real browser.
 *
 * WebAuthn L3 §7.2 step 21 says an assertion whose signature counter did not
 * advance means "a cloned authenticator, or a malfunction", and this server
 * answers both the same way: the credential stops working and the trail says
 * why (`http::passkeys::clone_signal`). `crates/webauthn` proves the
 * classification against vectors and `crates/server/tests/passkey_login.rs`
 * proves the handler against a fabricated assertion. Neither can produce a
 * *clone* — an authenticator holding the same private key at an older counter,
 * signing a challenge this server issued, through the same page a user uses.
 * Chromium's virtual authenticator can, because `WebAuthn.addCredential` takes
 * a private key and a counter, and that is the only reason this file exists.
 *
 * # One test, because the device is the subject
 *
 * The authenticator belongs to the DevTools session, which belongs to the
 * page, which belongs to the test. Splitting the enrolment, the clone and the
 * attempt-after-blocking across tests would give each one an empty device.
 * The three acts are marked below.
 *
 * # What "blocked" has to mean
 *
 * Refusing the cloned assertion is not enough on its own: a server that merely
 * compared counters would refuse it too, and would then happily accept the
 * *real* authenticator's next assertion — leaving a credential whose copy is
 * out there in circulation. So the last act puts the counter back ahead of the
 * stored one and asserts that this is refused as well.
 */
import { expect, test } from '../src/fixtures.js';
import {
  PASSWORD,
  USERNAME,
  WEBAUTHN_BASE_URL,
  WEBAUTHN_TENANT,
} from '../src/environment.js';
import {
  attachVirtualAuthenticator,
  startWebauthnAuthorization,
  type VirtualAuthenticator,
  type VirtualCredential,
} from '../src/passkeys.js';
import { eventsSince } from '../src/audit.js';

/** The status line the page's script writes when the ceremony was refused. */
const REFUSED = 'That did not work.';

/**
 * Presses "Sign in with a passkey" and reports what the finish endpoint said.
 *
 * Presence is switched off across the navigation for the reason
 * `passkey-ceremony.spec.ts` gives — the conditional-mediation ceremony the
 * page starts on load would otherwise sign in on its own, before the button
 * exists to be pressed — and switched back on once the click has drawn its own
 * challenge, so the device answers the ceremony the test chose.
 */
async function pressTheButton(
  page: import('@playwright/test').Page,
  request: import('@playwright/test').APIRequestContext,
  authenticator: VirtualAuthenticator,
): Promise<number> {
  await authenticator.simulatePresence(false);
  const flow = await startWebauthnAuthorization(request);
  await page.goto(flow.authorizationUrl);
  const button = page.getByRole('button', { name: 'Sign in with a passkey' });
  await expect(button).toBeVisible();
  const finished = page.waitForResponse((response) =>
    response.url().includes('/passkey/finish'),
  );
  await button.click();
  await authenticator.simulatePresence(true);
  return (await finished).status();
}

test('a credential whose counter went backwards is refused, and stays refused', async ({
  page,
  context,
  request,
}) => {
  // --- Arrange: a device, a passkey, and one sign-in that really worked ----
  // The window the audit assertion looks in. Taken before anything happens and
  // widened by a minute, because the timestamps are the server's clock and
  // this is the test's.
  const since = new Date(Date.now() - 60_000).toISOString();

  const authenticator = await attachVirtualAuthenticator(page);
  const enrolling = await startWebauthnAuthorization(request);
  await page.goto(enrolling.authorizationUrl);
  await page.locator('input[name="username"]').fill(USERNAME);
  await page.locator('input[name="password"]').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Allow' })).toBeVisible();

  await page.goto(`${WEBAUTHN_BASE_URL}/passkeys`);
  await page.getByRole('button', { name: 'Create a passkey' }).click();
  await expect
    .poll(async () => (await authenticator.credentials()).length, {
      message: 'the enrolment ceremony created no credential',
    })
    .toBe(1);

  // The session the password wrote is thrown away, so what follows is the
  // credential's doing and nothing else.
  await context.clearCookies();
  expect(
    await pressTheButton(page, request, authenticator),
    'the honest sign-in was refused, so nothing below is about cloning',
  ).toBe(204);
  await expect(page.getByRole('button', { name: 'Allow' })).toBeVisible();

  // What the device holds now: the key, and a counter the server has recorded.
  const [genuine] = await authenticator.credentials();
  const asserted = genuine as VirtualCredential;
  expect(
    asserted.privateKey,
    'the authenticator did not expose a key, so no clone can be made',
  ).toBeTruthy();
  expect(
    asserted.signCount,
    'the counter did not move, so a regression cannot be told from it',
  ).toBeGreaterThan(0);

  // --- Act: the same credential, at a counter that is behind ---------------
  // This is the clone: same id, same private key, same account — an older
  // copy of a device whose original has since been used. Chromium increments
  // before signing, so a stored zero presents one, which is at or below what
  // the honest sign-in already recorded.
  await context.clearCookies();
  await authenticator.forget(asserted.credentialId);
  await authenticator.putCredential(asserted, 0);

  const cloned = await pressTheButton(page, request, authenticator);

  // --- Assert: refused, and told nothing ----------------------------------
  expect(cloned, 'the cloned assertion was accepted').toBe(400);
  await expect(page.locator('#passkey-signin-status')).toContainText(REFUSED);
  await expect(page.locator('input[name="password"]')).toBeVisible();
  expect(
    (await context.cookies()).find((cookie) => cookie.name === '__Host-asterius_session'),
    'a cloned credential wrote a session',
  ).toBeUndefined();

  // --- Assert: the operator was told everything ---------------------------
  const failures = await eventsSince(WEBAUTHN_TENANT, 'auth.failed', since);
  const signal = failures.find((event) => event.detail.reason === 'sign_count_regression');
  expect(signal, 'the clone signal is not in the audit trail').toBeDefined();
  expect(signal?.outcome).toBe('failure');
  expect(signal?.detail.kind).toBe('passkey');
  // The RFC 8176 `amr` value for a software key, which is what a passkey is to
  // this server (`http::passkeys::amr` says why it never claims `hwk`).
  expect(signal?.detail.method).toBe('swk');
  // Both counters, because "how far behind" is what tells a broken
  // authenticator from a credential that has been copied and used elsewhere.
  expect(
    Number(signal?.detail.presented_sign_count),
    'the trail does not say what was presented',
  ).toBeLessThanOrEqual(Number(signal?.detail.stored_sign_count));

  // --- Assert: the credential is blocked, not merely out of step ----------
  // The original device, ahead of the stored counter again. A server that only
  // compared counters would sign this in; a server that blocked the credential
  // refuses it, which is what §7.2 step 21 asks for.
  await context.clearCookies();
  await authenticator.forget(asserted.credentialId);
  await authenticator.putCredential(asserted, asserted.signCount + 1_000);

  const afterBlocking = await pressTheButton(page, request, authenticator);

  expect(afterBlocking, 'the blocked credential signed in again').toBe(400);
  await expect(page.locator('#passkey-signin-status')).toContainText(REFUSED);
  expect(
    (await context.cookies()).find((cookie) => cookie.name === '__Host-asterius_session'),
    'a blocked credential wrote a session',
  ).toBeUndefined();

  await authenticator.remove();
});
