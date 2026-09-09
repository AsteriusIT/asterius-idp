/**
 * The negative proof: a deliberately broken page must fail the run.
 *
 * `ast-ndk.6` asks for this by name, and it is the only part of a CSP sweep
 * that is worth anything on its own. Every other test in this directory passes
 * just as happily against a browser that reports nothing at all — a listener
 * attached to the wrong event, a console channel Playwright stopped
 * surfacing, a policy header that quietly went missing. This test breaks a page
 * on purpose and asserts that the same gate every other test relies on refuses
 * it.
 *
 * Two things make it a proof rather than a demonstration:
 *
 *  - The policy served with the broken page is **the real one**, read off a
 *    live response from the server under test rather than written here. A
 *    fixture with an invented policy would prove that an invented policy
 *    blocks things.
 *  - The assertion under test is **the same function** `src/fixtures.ts` calls
 *    at the end of every other test. There is no second implementation that
 *    could be stricter than the one that actually gates the run.
 *
 * It runs in both projects, because a gate that only fires when script is
 * enabled would leave the no-JS suite — the suite this repository cares most
 * about — unguarded.
 */
import { expect, test } from '../src/fixtures.js';
import { BASE_URL } from '../src/environment.js';

// The one test allowed to end dirty. Everything else fails on a violation.
test.use({ allowCspViolations: true });

/** A path nothing serves, so the interception cannot mask a real page. */
const BROKEN_PATH = '/e2e-deliberately-broken-page';

test('a page that violates the real policy fails the gate', async ({ page, context, csp }) => {
  // --- Arrange: take the policy the server actually sends -----------------
  const live = await page.goto(
    `${BASE_URL}/authorize?client_id=nobody&request_uri=urn:ietf:params:oauth:request_uri:absent`,
  );
  const policy = live?.headers()['content-security-policy'];
  expect(policy, 'no live policy to break').toBeTruthy();
  // The error page itself must be clean, or the rest of this proves nothing:
  // a violation from *that* navigation would be indistinguishable from one the
  // broken fixture caused.
  csp.assertClean('the live page the policy was read from');

  // Same origin, real policy, three refusals it has no nonce for: an image
  // from an origin `img-src 'self' data:` does not name, an inline style
  // `style-src 'nonce-…'` does not carry, and an inline script under
  // `script-src 'nonce-…' 'strict-dynamic'`. The first two are refused whether
  // or not the browser runs script, which is what makes this proof work in the
  // no-JS project as well.
  await context.route(`${BASE_URL}${BROKEN_PATH}`, async (route) => {
    await route.fulfill({
      status: 200,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'content-security-policy': policy ?? '',
      },
      body: [
        '<!doctype html><html lang="en"><head>',
        '<title>deliberately broken</title>',
        '<style>body { color: red }</style>',
        '</head><body>',
        '<img src="https://violation.example.test/pixel.png" alt="">',
        '<script>window.shouldNeverRun = true;</script>',
        '</body></html>',
      ].join(''),
    });
  });

  // --- Act ----------------------------------------------------------------
  await page.goto(`${BASE_URL}${BROKEN_PATH}`);
  // The refusals are reported as the resources are fetched and the document is
  // parsed; wait for the browser to have finished doing both.
  await page.waitForLoadState('load');
  await expect
    .poll(() => csp.reported().length, {
      message: 'the browser reported no violation for a page that plainly violates the policy',
    })
    .toBeGreaterThan(0);

  // --- Assert: the gate the whole suite depends on refuses this page ------
  let refused: Error | undefined;
  try {
    csp.assertClean('the deliberately broken page');
  } catch (error) {
    refused = error as Error;
  }
  expect(refused, 'CspWatcher.assertClean accepted a page the browser refused').toBeDefined();
  expect(refused?.message).toContain('Content-Security-Policy violation');
  // Named, not just counted: a failure message that does not say which page and
  // which directive sends whoever reads it back to the browser by hand.
  expect(refused?.message).toContain(BROKEN_PATH);
});
