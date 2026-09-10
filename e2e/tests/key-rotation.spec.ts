/**
 * Rotating a signing key from the console, in a real browser (`ast-rna`).
 *
 * `ast-f7m.7` proved the rotation *at the API*: a request to `POST
 * /keys/rotate` stages a key, promotes it and leaves the previous one
 * published. What no API test can say is whether the button an operator
 * actually presses does that — the screen is script, its request carries a
 * synchroniser token and an idempotency key the shell mints
 * (`console/src/api.ts`), and the whole path runs under `connect-src 'self'`.
 *
 * The property asserted is OIDC Core §10.1.1's: after a rotation the JWK Set a
 * relying party fetches carries the *new* key and still carries the previous
 * one. Dropping the old key at the moment of rotation would invalidate every
 * token signed a second earlier, and a screen that reported a rotation without
 * publishing the new key would break verification for everyone.
 *
 * The evidence is read from the published JWK Set over HTTP — the document a
 * relying party would fetch, found through discovery — and not from the
 * console's own rendering of it: the screen showing a key is the screen's
 * claim, and this file exists to check the server's.
 *
 * Only the JS project runs this file, for `console.spec.ts`'s reason: a
 * console is script by definition.
 */
import AxeBuilder from '@axe-core/playwright';
import type { APIRequestContext, Locator, Page } from '@playwright/test';
import { discover } from '../src/authorization.js';
import { CONSOLE_URL, open, signIn } from '../src/console.js';
import { BASE_URL } from '../src/environment.js';
import { expect, test } from '../src/fixtures.js';

/** One row of the console's key table, as an operator reads it. */
interface Row {
  readonly kid: string;
  readonly state: string;
  readonly published: string;
}

/** The first algorithm group on the screen, and the algorithm it is for. */
async function firstGroup(page: Page): Promise<{ section: Locator; alg: string }> {
  const section = page.locator('section[aria-labelledby^="alg-"]').first();
  await expect(section, 'the tenant has no signing key at all').toBeVisible();
  const alg = (await section.getByRole('heading').first().innerText()).trim();
  return { section, alg };
}

/** Every key row in one algorithm group. */
async function rows(section: Locator): Promise<Row[]> {
  const cells = await section.locator('tbody tr').evaluateAll((elements) =>
    elements.map((row) => {
      const columns = Array.from(row.querySelectorAll('td'), (cell) => cell.textContent ?? '');
      return { kid: columns[0] ?? '', state: columns[1] ?? '', published: columns[2] ?? '' };
    }),
  );
  return cells.map((row) => ({
    kid: row.kid.trim(),
    state: row.state.trim(),
    published: row.published.trim(),
  }));
}

/** The key that is signing right now, as the screen reports it. */
async function activeKid(section: Locator): Promise<string> {
  const active = (await rows(section)).filter((row) => row.state === 'active');
  expect(active, 'the group does not have exactly one active key').toHaveLength(1);
  return active[0]?.kid ?? '';
}

/**
 * The `kid` values a relying party would find, fetched the way one would.
 *
 * Through the discovery document, because that is the only address a relying
 * party is given; `/jwks` is where it happens to live today.
 */
async function publishedKids(api: APIRequestContext): Promise<string[]> {
  const discovery = await discover(api, BASE_URL);
  const response = await api.get(discovery.jwks_uri);
  expect(response.status(), 'the JWK Set is not being served').toBe(200);
  const document = (await response.json()) as { keys?: { kid?: string }[] };
  return (document.keys ?? []).map((key) => key.kid ?? '');
}

test('the signing-key screen is reachable and reads the admin API', async ({ page }) => {
  // Arrange
  await signIn(page);

  // Act
  await open(page, 'Signing keys', 'Signing keys');

  // Assert: the inventory arrived, rather than a skeleton or an error.
  const { section, alg } = await firstGroup(page);
  expect(alg, 'the group is headed by no algorithm name').not.toBe('');
  expect(await rows(section), 'the group lists no key').not.toHaveLength(0);
  await expect(page.getByRole('heading', { name: 'Published JWK Set' })).toBeVisible();
});

test('rotating from the console signs with a new kid and keeps publishing the previous one', async ({
  page,
  request,
}) => {
  // Arrange: the key that is signing now, and the set as it stands.
  await signIn(page);
  await open(page, 'Signing keys', 'Signing keys');
  const { section, alg } = await firstGroup(page);
  const before = await activeKid(section);
  expect(await publishedKids(request), 'the active key is not published').toContain(before);

  // Act: the button an operator presses. "Immediately" because the ordinary
  // rotation only *stages* a key — it starts signing after the propagation
  // period, which is hours away and is not what this asserts.
  await section.getByRole('button', { name: 'Rotate and sign immediately' }).click();
  await expect(page.getByRole('status')).toContainText('is now signing');

  // Assert: the screen agrees a different key is signing…
  const after = await activeKid(section);
  expect(after, `rotating ${alg} left the same key signing`).not.toBe(before);

  // …and the published set — the document a relying party fetches — carries
  // both. The new one, or nothing it signs can be verified; the previous one,
  // or every token signed a second ago becomes unverifiable (OIDC Core
  // §10.1.1).
  const kids = await publishedKids(request);
  expect(kids, 'the new signing key is not in the published JWK Set').toContain(after);
  expect(kids, 'the superseded key was dropped from the JWK Set at once').toContain(before);

  // And the screen says so too, which is what an operator has to believe.
  const superseded = (await rows(section)).find((row) => row.kid === before);
  expect(superseded?.published, 'the screen claims the previous key is gone').toBe('yes');
});

test('the signing-key screen has no accessibility violation', async ({ page }, testInfo) => {
  // Arrange
  await signIn(page);
  await open(page, 'Signing keys', 'Signing keys');

  // Act
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();

  // Assert
  await testInfo.attach('axe', {
    body: JSON.stringify(results.violations, null, 2),
    contentType: 'application/json',
  });
  expect(results.violations).toEqual([]);
  expect(page.url()).toContain(CONSOLE_URL);
});
