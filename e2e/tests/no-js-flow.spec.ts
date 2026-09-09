/**
 * `ast-2vk.14`: a headless browser with JavaScript disabled walks the flow.
 *
 * Everything asserted here was previously only inferred. `source_audit.rs`
 * proves that no template contains a `<script>`; it cannot prove that the pages
 * are *usable* without one, that Chromium keeps the `__Host-` cookie we write,
 * or that the authorization response survives the policy we serve. Those are
 * browser facts, and this is the only test in the repository with a browser.
 *
 * The CSP assertion is deliberately not written out in each test: `src/fixtures.ts`
 * fails any test during which the browser refused anything, so every document
 * and every submission below is swept without a line somebody has to remember.
 */
import { expect, test } from '../src/fixtures.js';
import { INTERACTION_COOKIE, PASSWORD, USERNAME } from '../src/environment.js';
import { startAuthorization } from '../src/flow.js';

test('login and consent are usable with JavaScript disabled', async ({
  page,
  context,
  request,
}) => {
  // --- Arrange ------------------------------------------------------------
  const flow = await startAuthorization(request);

  // --- Act: /authorize, which 303s into the interaction -------------------
  await page.goto(flow.authorizationUrl);

  // --- Assert: the login page needs nothing to run ------------------------
  await expect(page.locator('input[name="username"]')).toBeVisible();
  await expect(page.locator('input[name="password"]')).toBeVisible();
  // One script, and it is the passkey bootstrap `ast-2vk.4` added — named in
  // `source_audit::SCRIPTED_TEMPLATES` with the reason. What matters here is
  // that it changes nothing when it does not run: the block it would reveal
  // stays hidden, so a browser with scripting off is never shown a button that
  // could not work, and the form below it is the whole page.
  expect(
    await page.locator('script').count(),
    'the login page carries a script other than the passkey bootstrap',
  ).toBe(1);
  await expect(page.locator('#passkey-signin')).toBeHidden();
  await expect(page.getByRole('button', { name: 'Sign in with a passkey' })).toBeHidden();

  // The reason this test needs a browser at all. `__Host-` is enforced by the
  // browser and by nothing else: Chromium drops the cookie outright unless it
  // was set over a secure origin, has `Path=/` and names no `Domain`. That the
  // cookie is here at all is the proof that the attributes
  // `asterius_web::interaction::set_cookie` writes earn the prefix; the
  // assertions below say which attributes those are.
  const interaction = (await context.cookies()).find(
    (cookie) => cookie.name === INTERACTION_COOKIE,
  );
  expect(interaction, `the browser kept no ${INTERACTION_COOKIE} cookie`).toBeDefined();
  expect(interaction?.secure).toBe(true);
  expect(interaction?.httpOnly).toBe(true);
  expect(interaction?.path).toBe('/');
  expect(interaction?.sameSite).toBe('Lax');

  // --- Act: sign in, with a plain form submission -------------------------
  await page.locator('input[name="username"]').fill(USERNAME);
  await page.locator('input[name="password"]').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();

  // --- Assert: consent, reached without script ----------------------------
  await expect(page.getByRole('button', { name: 'Allow' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Deny' })).toBeVisible();
  expect(await page.locator('script').count(), 'the consent page carries a script').toBe(0);

  // The session cookie is written at the same moment and carries the same
  // prefix, for the same browser-enforced reasons.
  const session = (await context.cookies()).find(
    (cookie) => cookie.name === '__Host-asterius_session',
  );
  expect(session, 'signing in wrote no session cookie').toBeDefined();
  expect(session?.secure).toBe(true);
  expect(session?.httpOnly).toBe(true);
  expect(session?.path).toBe('/');
});

/**
 * The last hop, and the one this sweep found broken on its first run.
 *
 * Approving consent posts to `/interaction/{id}` and the server answers 303 to
 * the client's `redirect_uri`. Chromium enforces `form-action` across the
 * *redirects* of a form submission, not only its action, so while the consent
 * page was served `form-action 'self'` the response was minted, the grant and
 * the code were written, and then the browser refused to follow the redirect
 * that carried them: the user sat on the consent screen with no error and the
 * client waited forever (`ast-jsq`).
 *
 * The fix is `asterius_web::Document::with_form_post_to`, the seam `ast-gxh.5`
 * built for "this one page also submits to this one registered callback",
 * applied to the consent screen with the origin of the `redirect_uri` this
 * authorization was validated against — one origin, that page only. Nothing
 * but a browser can check that, which is why this assertion lives here and not
 * in a Rust test.
 */
test.describe('the last hop', () => {
  test('the authorization response reaches the client', async ({ page, request }) => {
    // --- Arrange ------------------------------------------------------------
    const flow = await startAuthorization(request);
    await page.goto(flow.authorizationUrl);
    await page.locator('input[name="username"]').fill(USERNAME);
    await page.locator('input[name="password"]').fill(PASSWORD);
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Allow' })).toBeVisible();

    // --- Act ----------------------------------------------------------------
    await page.getByRole('button', { name: 'Allow' }).click();
    // Caught rather than awaited bare: a test that dies of its own timeout says
    // "timed out" where this one has something specific to report.
    await page.waitForURL(`${flow.redirectUri}*`, { timeout: 10_000 }).catch(() => {});

    // --- Assert -------------------------------------------------------------
    const landed = new URL(page.url());
    expect(
      `${landed.origin}${landed.pathname}`,
      'the browser never reached the client callback',
    ).toBe(flow.redirectUri);
    expect(landed.searchParams.get('state')).toBe(flow.state);
    expect(landed.searchParams.get('code'), 'the redirect carried no code').toBeTruthy();
    // RFC 9207: the response names the issuer that produced it, so a client
    // cannot be steered into redeeming a code at the wrong authorization server.
    expect(landed.searchParams.get('iss')).toBeTruthy();
  });
});
