/**
 * `ast-kb0`: the ceremony itself, in a browser, with an authenticator.
 *
 * The acceptance criterion `ast-2vk.4` left open. `crates/webauthn` proves the
 * verification against test vectors and `crates/server/tests/passkey_login.rs`
 * proves the endpoints against a fabricated assertion; neither can prove that
 * the two pages, the two scripts and the four endpoints compose into a passkey
 * a user can *create* and then *sign in with*. That is what a virtual
 * authenticator driven over CDP is for, and this file is the only place in the
 * repository where a real `navigator.credentials` call happens.
 *
 * # Two navigations, one page
 *
 * The enrolment and the sign-in are separate top-level navigations with the
 * cookie jar emptied in between, so the sign-in has no session to lean on and
 * nothing survives it but the credential the server stored. They share a page
 * on purpose: Chromium's virtual authenticator belongs to the DevTools session,
 * which belongs to the page, so a second page would hold no credential and the
 * test would be proving something about the harness.
 *
 * # Why the tenant is not the sweep's
 *
 * An IP literal is not a valid RP ID. See `src/passkeys.ts`, and the note in
 * `e2e/fixtures/asterius.toml.in` that this deliberately did not overwrite.
 */
import { expect, test } from '../src/fixtures.js';
import { PASSWORD, USERNAME, WEBAUTHN_BASE_URL, WEBAUTHN_RP_ID } from '../src/environment.js';
import { attachVirtualAuthenticator, startWebauthnAuthorization } from '../src/passkeys.js';

/** The refusal every rejected sign-in is supposed to be, and only that. */
interface Refusal {
  readonly status: number;
  readonly body: Record<string, string>;
}

/**
 * The body the page posted for a sign-in that really worked.
 *
 * Captured once and reused by the refusal test, which needs an assertion that
 * is genuine in every respect so that what it is refused *for* is unambiguous.
 * Signing a second one would need a second authenticator and would advance the
 * credential's signature counter, which is a different test's subject.
 */
let signedAssertion: Record<string, unknown> | undefined;

test.describe.serial('a passkey, end to end', () => {
  test('a passkey created in one navigation signs in in the next', async ({
    page,
    context,
    request,
  }) => {
    // --- Arrange: a device, and a user who has signed in with a password ---
    const authenticator = await attachVirtualAuthenticator(page);
    const enrolling = await startWebauthnAuthorization(request);
    await page.goto(enrolling.authorizationUrl);
    await page.locator('input[name="username"]').fill(USERNAME);
    await page.locator('input[name="password"]').fill(PASSWORD);
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Allow' })).toBeVisible();

    // --- Act: navigation one, the enrolment ------------------------------
    await page.goto(`${WEBAUTHN_BASE_URL}/passkeys`);
    await page.getByRole('button', { name: 'Create a passkey' }).click();

    // --- Assert: the authenticator holds a discoverable credential -------
    await expect
      .poll(async () => (await authenticator.credentials()).length, {
        message: 'the enrolment ceremony created no credential',
      })
      .toBe(1);
    const [created] = await authenticator.credentials();
    expect(created.rpId, 'the credential is scoped to another relying party').toBe(WEBAUTHN_RP_ID);
    // Username-less sign-in asks for a discoverable credential and nothing
    // else, so a non-resident one would be invisible to the next navigation.
    expect(created.isResidentCredential, 'the credential is not discoverable').toBe(true);
    await expect(page.locator('#passkey-status')).not.toContainText('did not work');

    // --- Act: navigation two, and nothing carried over --------------------
    // The session the password wrote is thrown away: what signs in below is
    // the credential, or nothing.
    await context.clearCookies();
    await page.route('**/interaction/*/passkey/finish', async (route) => {
      const posted = route.request().postData();
      if (posted !== null) {
        signedAssertion = JSON.parse(posted) as Record<string, unknown>;
      }
      await route.continue();
    });

    // The login page asks for conditional mediation the moment it loads. A
    // device that answers on its own would satisfy *that* ceremony and sign in
    // before the button was pressed, so the device waits until it is asked.
    await authenticator.simulatePresence(false);

    const signingIn = await startWebauthnAuthorization(request);
    await page.goto(signingIn.authorizationUrl);
    const button = page.getByRole('button', { name: 'Sign in with a passkey' });
    await expect(button).toBeVisible();
    await button.click();
    await authenticator.simulatePresence(true);

    // --- Assert: signed in, with no username and no password typed --------
    await expect(page.getByRole('button', { name: 'Allow' })).toBeVisible();
    const session = (await context.cookies()).find(
      (cookie) => cookie.name === '__Host-asterius_session',
    );
    expect(session, 'the passkey sign-in wrote no session cookie').toBeDefined();
    expect(signedAssertion, 'no finish request was observed').toBeDefined();

    await authenticator.remove();
  });

  /**
   * What the ceremony refuses, and — the point — that it refuses them alike.
   *
   * A replayed assertion and an assertion for a credential this server never
   * saw are answered by two different lines of `login_finish`, and an attacker
   * must not be able to tell which. The server keeps that promise by giving
   * every refusal the same body; this locks it from the browser, where a
   * divergence would actually be observable.
   */
  test('a replayed assertion and an unknown credential are the same refusal', async ({
    page,
    request,
  }) => {
    // --- Arrange: a fresh interaction, and the assertion that once worked --
    expect(signedAssertion, 'the sign-in test did not capture an assertion').toBeDefined();
    const flow = await startWebauthnAuthorization(request);
    await page.goto(flow.authorizationUrl);
    const root = page.locator('#passkey-signin');
    const optionsUrl = await root.getAttribute('data-options-url');
    const finishUrl = await root.getAttribute('data-finish-url');
    const csrf = await root.getAttribute('data-csrf');
    expect(optionsUrl && finishUrl && csrf, 'the page names no ceremony').toBeTruthy();

    // --- Act ---------------------------------------------------------------
    // Both attempts draw their own challenge first, so each is refused for the
    // one reason it is meant to be refused for and not for having none.
    const [replayed, unknown] = await page.evaluate(
      async (input: {
        optionsUrl: string;
        finishUrl: string;
        csrf: string;
        assertion: Record<string, unknown>;
      }) => {
        const draw = () =>
          fetch(input.optionsUrl, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ csrf: input.csrf }),
          });
        const finish = async (body: Record<string, unknown>) => {
          const answer = await fetch(input.finishUrl, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(body),
          });
          return { status: answer.status, body: (await answer.json()) as Record<string, string> };
        };

        // A genuine assertion, signed over a challenge that has already been
        // spent, offered against a challenge it never saw.
        await draw();
        const first = await finish({ ...input.assertion, csrf: input.csrf });

        // The same assertion, for a credential id nothing answers to.
        await draw();
        const strange = new Uint8Array(32);
        crypto.getRandomValues(strange);
        const rawId = btoa(String.fromCharCode(...strange))
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');
        const second = await finish({ ...input.assertion, csrf: input.csrf, rawId });

        return [first, second];
      },
      {
        optionsUrl: optionsUrl as string,
        finishUrl: finishUrl as string,
        csrf: csrf as string,
        assertion: signedAssertion as Record<string, unknown>,
      },
    );

    // --- Assert -----------------------------------------------------------
    for (const refusal of [replayed, unknown] as Refusal[]) {
      expect(refusal.status).toBe(400);
      expect(refusal.body.error).toBe('authentication_failed');
      expect(
        Object.keys(refusal.body).sort(),
        'a refusal says which request it was, and nothing about why',
      ).toEqual(['correlation_id', 'error']);
    }
    // The correlation id is the one thing that differs, because it is the one
    // thing that says nothing about the request.
    expect(replayed.body.correlation_id).not.toBe(unknown.body.correlation_id);
    expect(
      { ...replayed.body, correlation_id: '' },
      'the two refusals are distinguishable',
    ).toEqual({ ...unknown.body, correlation_id: '' });

    // Neither attempt signed anybody in: the page is still the login page.
    await expect(page.locator('input[name="password"]')).toBeVisible();
  });
});

/**
 * `ast-1gj`: pressing the button must beat the autofill ceremony it replaces.
 *
 * The login page starts a conditional-mediation ceremony as it loads, and
 * `authenticate` aborts whatever is outstanding before it starts another. That
 * abort only reaches a ceremony which has got as far as `credentials.get`: one
 * still *fetching its options* was never told, went on to sign the challenge
 * the click had already replaced, and posted it — spending the challenge the
 * deliberate ceremony was about to use. Both are then refused, and a user who
 * did nothing but press the button early is told "that did not work".
 *
 * It surfaced as a red `passkey-clone` on `main` (run 34483437177), where the
 * autofill options request took 166 ms on a cold CI runner and the click
 * landed inside it; locally the same request answers in 7 ms. So this holds
 * the first one open rather than hoping for a slow machine: the click lands
 * mid-flight every time.
 */
test('pressing the button while the autofill ceremony is fetching its options signs in', async ({
  page,
  context,
  request,
}) => {
  // --- Arrange: a device with a passkey, and an empty cookie jar ----------
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
  await context.clearCookies();

  // --- Act: the click arrives while the autofill options are in flight ----
  // The *answers* are held, not the requests: the server must draw the
  // autofill challenge first and the button's second — that is the order the
  // page produces and the order that decides which challenge is the live one.
  // Only the delivery is reordered, and only enough to put the click inside
  // the autofill ceremony's flight and the autofill assertion ahead of the
  // button's, which is the interleaving CI hit.
  let drawn = 0;
  await page.route('**/interaction/*/passkey/options', async (route) => {
    drawn += 1;
    const held = drawn === 1 ? 400 : 1_500;
    const answer = await route.fetch();
    await new Promise((resolve) => setTimeout(resolve, held));
    await route.fulfill({ response: answer });
  });

  await authenticator.simulatePresence(false);
  const signingIn = await startWebauthnAuthorization(request);
  await page.goto(signingIn.authorizationUrl);
  const button = page.getByRole('button', { name: 'Sign in with a passkey' });
  await expect(button).toBeVisible();
  await button.click();
  await authenticator.simulatePresence(true);

  // --- Assert: the ceremony the user asked for is the one that counted ----
  await expect(page.getByRole('button', { name: 'Allow' })).toBeVisible();
  expect(
    (await context.cookies()).find((cookie) => cookie.name === '__Host-asterius_session'),
    'the sign-in the user asked for wrote no session',
  ).toBeDefined();
  expect(
    drawn,
    'the button drew no challenge of its own, so nothing was superseded and this proves nothing',
  ).toBe(2);

  await authenticator.remove();
});
