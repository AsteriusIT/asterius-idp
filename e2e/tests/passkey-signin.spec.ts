/**
 * `ast-2vk.4`: the sign-in page's passkey path, in a real browser.
 *
 * What only a browser can show is that the enhancement is an enhancement. The
 * Rust tests prove the ceremony and the refusals; the source audit proves the
 * markup. Neither can prove that a browser with script *enabled* reveals the
 * button, that the button appears without the password form changing, or that
 * revealing it provokes no Content-Security-Policy violation — which it would
 * the moment the bootstrap lost its nonce or reached for an inline handler.
 * The `csp` fixture fails this file if the browser refuses anything.
 *
 * # What is deliberately not here yet
 *
 * The ceremony itself, driven by Chromium's virtual authenticator over CDP.
 * The RP ID this server derives is the issuer's host, and the sweep's fixture
 * issuer is `https://127.0.0.1:{port}/t/e2e` — an IP literal, which WebAuthn
 * does not accept as an RP ID and which Chromium refuses before any
 * authenticator, virtual or otherwise, is consulted. Making that test possible
 * means moving the fixture tenant onto a name, and `e2e/fixtures/asterius.toml.in`
 * chose the address on purpose (a name that may resolve to `::1` first is a way
 * for a run to fail for a reason that has nothing to do with the code). So it
 * is a fixture decision to take deliberately rather than a line to add here.
 */
import { expect, test } from '../src/fixtures.js';
import { PASSWORD, USERNAME } from '../src/environment.js';
import { startAuthorization } from '../src/flow.js';

test('the script reveals the passkey button and leaves the password form alone', async ({
  page,
  request,
}) => {
  // --- Arrange ------------------------------------------------------------
  const flow = await startAuthorization(request);

  // --- Act ----------------------------------------------------------------
  await page.goto(flow.authorizationUrl);

  // --- Assert: the enhancement appeared ----------------------------------
  await expect(page.getByRole('button', { name: 'Sign in with a passkey' })).toBeVisible();
  // ...and the mechanism is untouched.
  await expect(page.locator('input[name="username"]')).toBeVisible();
  await expect(page.locator('input[name="password"]')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeEnabled();
  // Conditional mediation is asked for where a browser reads it. Whether this
  // browser offers it is the browser's business; that the page asks is ours.
  await expect(page.locator('input[name="username"]')).toHaveAttribute(
    'autocomplete',
    'username webauthn',
  );
});

test('the password path still works on the page that now carries a script', async ({
  page,
  request,
}) => {
  // --- Arrange ------------------------------------------------------------
  const flow = await startAuthorization(request);
  await page.goto(flow.authorizationUrl);

  // --- Act ----------------------------------------------------------------
  await page.locator('input[name="username"]').fill(USERNAME);
  await page.locator('input[name="password"]').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();

  // --- Assert -------------------------------------------------------------
  await expect(page.getByRole('button', { name: 'Allow' })).toBeVisible();
});

/**
 * The anti-enumeration answer, from outside the process.
 *
 * A request with no synchroniser token and a request with a forged one are the
 * same refusal, and neither says whether the interaction exists. Posted
 * directly rather than through the page, because the page would never send
 * either.
 */
test('a passkey options request without the page behind it is refused', async ({
  page,
  request,
}) => {
  // --- Arrange ------------------------------------------------------------
  const flow = await startAuthorization(request);
  await page.goto(flow.authorizationUrl);
  const url = await page.locator('#passkey-signin').getAttribute('data-options-url');
  expect(url, 'the page names no options endpoint').toBeTruthy();

  // --- Act ----------------------------------------------------------------
  const refused = await page.evaluate(async (endpoint: string) => {
    const answer = await fetch(endpoint, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ csrf: 'not-the-token' }),
    });
    return { status: answer.status, body: await answer.json() };
  }, url as string);

  // --- Assert -------------------------------------------------------------
  expect(refused.status).toBe(400);
  expect(refused.body.error).toBe('authentication_failed');
  expect(
    Object.keys(refused.body).sort(),
    'a refusal says which request it was, and nothing about why',
  ).toEqual(['correlation_id', 'error']);
});
