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
 * # What is not here, and where it is instead
 *
 * The ceremony itself. It cannot run on this tenant at all: the RP ID is the
 * issuer's host, this issuer's is `127.0.0.1`, and an IP literal is not a
 * domain — Chromium refuses before any authenticator is consulted. `ast-kb0`
 * added a second tenant on a name rather than moving this one, and the
 * enrolment-then-sign-in walk lives in `passkey-ceremony.spec.ts`. So what is
 * asserted below is the page, on the tenant the rest of the sweep uses.
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
