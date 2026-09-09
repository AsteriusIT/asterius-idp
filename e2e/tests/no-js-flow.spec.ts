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
import { interceptCallback, startAuthorization } from '../src/flow.js';

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
  expect(
    await page.locator('script').count(),
    'the login page carries a script; source_audit.rs should have refused it',
  ).toBe(0);

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
  await page.getByRole('button', { name: 'Sign in' }).click();

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
 * redirects of a form submission, and the consent page is served
 * `form-action 'self'` — so the response is minted, the grant and the code are
 * written, and then the browser refuses to follow the redirect that carries
 * them. The user is left on the consent screen with no error, and the client
 * waits forever.
 *
 * Confirmed rather than guessed: with a `redirect_uri` on the server's own
 * origin the identical flow completes and the code arrives, and the database
 * holds a grant and a code for the blocked attempt too. So it is the redirect
 * that is refused, not the submission.
 *
 * `asterius_web::csp` already has the seam this needs —
 * `Policy::with_form_post_to`, built for `ast-gxh.5` to name "this one page
 * also submits to this one registered callback" — but the consent page does
 * not use it. Widening a security header is a decision with an owner, so this
 * test states what the product should do and is marked as a known failure
 * rather than being weakened into a test of the broken behaviour.
 *
 * `test.fail()` and not `skip`: the day the consent page names the client's
 * origin, this test passes and the run goes red until somebody deletes this
 * annotation. A skipped test would have gone on being skipped.
 */
test.describe('the last hop', () => {
  // Scoped to this block, so a regression anywhere else still fails the run.
  test.fail();

  test('the authorization response reaches the client', async ({ page, context, request }) => {
    // --- Arrange ------------------------------------------------------------
    await interceptCallback(context);
    const flow = await startAuthorization(request);
    await page.goto(flow.authorizationUrl);
    await page.locator('input[name="username"]').fill(USERNAME);
    await page.locator('input[name="password"]').fill(PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();
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
    await expect(page.locator('#callback')).toBeVisible();
  });
});
