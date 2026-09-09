/**
 * `response_mode=form_post`, which `ast-2vk.14` asked a browser to confirm
 * auto-submits without script — and which `ast-gxh.5` has now built.
 *
 * The counter-intuitive part, written down when this file was still a `fixme`
 * and still the reason the test is shaped like this: a form cannot auto-submit
 * without script. `<noscript>` cannot submit anything and there is no HTML
 * attribute that does. So a no-JS `form_post` response is a page with a real
 * submit button the user presses, plus — for the overwhelmingly common scripted
 * case — a nonced inline script that presses it for them. Both halves are
 * asserted here, in the suite that can see each: the `no-js` project presses
 * the button, the `js` project presses nothing and expects to arrive anyway.
 *
 * Nothing here asserts the absence of a CSP violation by hand. `src/fixtures.ts`
 * fails any test during which the browser refused anything, which is what makes
 * the `form-action` claim real: the page is served `form-action 'self'` plus
 * the client's origin, and a browser that disagreed would refuse the submission
 * and fail these tests twice over.
 */
import { expect, test } from '../src/fixtures.js';
import { PASSWORD, USERNAME } from '../src/environment.js';
import { startAuthorization } from '../src/flow.js';

/** Signs in and approves consent, and returns the response that answered. */
async function approve(page: import('@playwright/test').Page, authorizationUrl: string) {
  await page.goto(authorizationUrl);
  await page.locator('input[name="username"]').fill(USERNAME);
  await page.locator('input[name="password"]').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('button', { name: 'Allow' })).toBeVisible();

  // The document that answers the consent POST is the form-post page itself,
  // and its headers are the only place `Cache-Control` and the policy can be
  // read from.
  const answered = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' && response.url().includes('/interaction/'),
  );
  await page.getByRole('button', { name: 'Allow' }).click();
  return await answered;
}

test('a form_post response submits to the client, with and without script', async ({
  page,
  request,
  javaScriptEnabled,
}) => {
  // --- Arrange ------------------------------------------------------------
  const flow = await startAuthorization(request, 'form_post');

  // --- Act ----------------------------------------------------------------
  const response = await approve(page, flow.authorizationUrl);

  // --- Assert: the response is a page, and one nothing may keep ------------
  expect(response.status(), 'a form_post response is a rendered page, not a redirect').toBe(200);
  const headers = response.headers();
  expect(headers['content-type']).toContain('text/html');
  // OAuth 2.0 Form Post Response Mode §2: the page carries a live
  // authorization code and MUST NOT be cached.
  expect(headers['cache-control']).toBe('no-store');
  expect(headers['location'], 'a form_post response also redirected').toBeUndefined();

  // The policy names exactly the client's origin beside `'self'`, so this one
  // page may post where no other page of this server may.
  const clientOrigin = new URL(flow.redirectUri).origin;
  expect(headers['content-security-policy']).toContain(`form-action 'self' ${clientOrigin};`);

  if (javaScriptEnabled) {
    // --- Assert: the script pressed the button, and the browser allowed it -
    await page.waitForURL(`${flow.redirectUri}*`, { timeout: 10_000 }).catch(() => {});
    expect(
      page.url(),
      'the auto-submit script did not deliver the response to the client',
    ).toContain(flow.redirectUri);
    return;
  }

  // --- Assert: with script off the page is still a working page -----------
  const form = page.locator('form#form-post');
  await expect(form).toHaveAttribute('method', 'post');
  // The exact registered callback: §2 posts to the `redirect_uri` itself, and
  // the response parameters travel in the body rather than in that URL.
  await expect(form).toHaveAttribute('action', flow.redirectUri);
  await expect(page.locator('input[name="code"]')).toHaveCount(1);
  await expect(page.locator('input[name="state"]')).toHaveValue(flow.state);
  // RFC 9207 §2: the response names the issuer that produced it, in this mode
  // as in the other.
  await expect(page.locator('input[name="iss"]')).not.toHaveValue('');
  // Nothing was submitted by itself: script is off, and this is the case the
  // button exists for.
  expect(page.url(), 'the page navigated with no script to navigate it').not.toContain(
    flow.redirectUri,
  );

  // --- Act: the user presses the button the page always shows -------------
  const submitted = page.getByRole('button', { name: 'Continue' });
  await expect(submitted).toBeVisible();
  await submitted.click();
  await page.waitForURL(`${flow.redirectUri}*`, { timeout: 10_000 }).catch(() => {});

  // --- Assert -------------------------------------------------------------
  expect(page.url(), 'pressing Continue did not reach the client callback').toContain(
    flow.redirectUri,
  );
});
