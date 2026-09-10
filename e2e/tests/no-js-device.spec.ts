/**
 * The device flow's browser half, with JavaScript disabled (`ast-ndk.4`).
 *
 * RFC 8628 exists for a device that cannot show a browser, so the *person's*
 * half runs on whatever browser they happen to have — a television's, a
 * set-top box's companion phone, a shared terminal. It is the last place in
 * this server where "we assume script" would be an acceptable answer, and
 * `crates/server/tests/end_to_end.rs` cannot say anything about it: it drives
 * the pages with an HTTP client that never had script to disable.
 *
 * So the whole of §3.3 is walked here by a browser that will not run a line of
 * it: the code-entry page, the confirmation of §3.3.1, and the outcome page. The
 * device's own half (§3.1 and §3.4) is an API client in `src/device.ts`,
 * because a device with no browser is the premise of the grant — and the poll
 * that finally answers with a token is what proves the person's clicks reached
 * the device at all.
 *
 * The CSP assertion is not written out per test: `src/fixtures.ts` fails any
 * test during which the browser refused anything.
 */
import { expect, test } from '../src/fixtures.js';
import { BASE_URL, PASSWORD, USERNAME } from '../src/environment.js';
import { discover, registerClient } from '../src/authorization.js';
import {
  DEVICE_GRANT,
  newProofKey,
  pollOnce,
  pollUntilAnswered,
  requestDeviceAuthorization,
} from '../src/device.js';
import { expectWithinScriptAllowlist } from '../src/no-script.js';

// A person typing a code, a sign-in, two page transitions and a poll interval
// the RFC sets at five seconds. The default budget is for a page, not a flow.
test.setTimeout(120_000);

test('a device is connected by a browser that runs no script', async ({ page, request }) => {
  // --- Arrange: the device asks (§3.1) ------------------------------------
  const discovery = await discover(request, BASE_URL);
  const device = await registerClient(request, discovery, '', [DEVICE_GRANT]);
  // The key the token will be bound to (RFC 9449): a device that cannot show a
  // browser can still hold a key, and this server binds every token it mints.
  const key = await newProofKey();
  const authorization = await requestDeviceAuthorization(request, discovery, device);

  // §3.2: the URI is absolute, because it is read off a screen and typed into
  // a browser that has no base to resolve it against — and it carries the
  // tenant's mount prefix, because a path-routed tenant is where it is served.
  expect(authorization.verification_uri).toBe(`${BASE_URL}/device`);
  expect(authorization.user_code, 'a device authorization with no code to show').toBeTruthy();

  // --- Assert: nothing is granted yet (§3.5) ------------------------------
  const pending = await pollOnce(request, discovery, device, authorization.device_code, key);
  expect(pending.status).toBe(400);
  expect(
    pending.body['error'],
    'the device was told something other than to keep waiting',
  ).toBe('authorization_pending');

  // --- Act: the person opens the URI on the browser they have -------------
  // With no session, §3.3's page cannot be shown at all: an approval creates a
  // grant on somebody's account, so "somebody" has to be authenticated first.
  await page.goto(authorization.verification_uri);
  await expect(page.locator('input[name="username"]')).toBeVisible();
  await page.locator('input[name="username"]').fill(USERNAME);
  await page.locator('input[name="password"]').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();

  // --- Assert: the code-entry page, and nothing on it needs script --------
  await expect(page.getByRole('heading', { name: 'Connect a device' })).toBeVisible();
  await expectWithinScriptAllowlist(page, 'device.html');
  await expect(page.locator('input[name="user_code"]')).toBeVisible();

  // --- Act: the code the device is showing --------------------------------
  await page.locator('input[name="user_code"]').fill(authorization.user_code);
  await page.getByRole('button', { name: 'Continue' }).click();

  // --- Assert: §3.3.1's confirmation --------------------------------------
  // The server displays the code *it* matched and asks the person to compare
  // it against the device in front of them, which is what turns a mailed
  // `verification_uri_complete` from a click into a comparison (§5.4).
  await expect(page.getByRole('heading', { name: 'Is this the code on your device?' })).toBeVisible();
  await expect(page.locator('.code-display')).toHaveText(authorization.user_code);
  await expectWithinScriptAllowlist(page, 'device_confirm.html');

  // --- Act: the approval --------------------------------------------------
  await page.getByRole('button', { name: 'Yes, continue' }).click();

  // --- Assert: the person is finished, and told so ------------------------
  await expect(page.getByRole('heading', { name: 'Device connected' })).toBeVisible();
  await expectWithinScriptAllowlist(page, 'device_done.html');

  // --- Assert: and the device, which saw none of that, has its token ------
  const answered = await pollUntilAnswered(
    request,
    discovery,
    device,
    authorization.device_code,
    key,
    authorization.interval,
  );
  expect(
    answered.status,
    `the device was refused after an approval: ${JSON.stringify(answered.body)}`,
  ).toBe(200);
  expect(answered.body['access_token'], 'the approval minted no access token').toBeTruthy();
  // RFC 9449 §5: a token bound to the key the poll proved possession of is a
  // `DPoP` token and says so, so a resource server cannot accept it as a bearer.
  expect(answered.body['token_type']).toBe('DPoP');
});
