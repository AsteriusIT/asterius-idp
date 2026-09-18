/**
 * The console's screens, photographed (`ast-fe39`).
 *
 * Not an assertion: a picture of every screen an administrator can reach,
 * written to `docs/console/`, so that a redesign can be reviewed as what it is
 * — a change to what people see — rather than as a diff of class names. The
 * pair it produces is what the ticket asks for: the same eight screens before
 * the migration and after it, taken by the same browser at the same size. Set
 * `E2E_SHOTS_THEME=dark` for the matching dark-theme series.
 *
 * # Why it does not run with the sweep
 *
 * It proves nothing. Every criterion the console has — no CSP violation, no
 * third-party call, no axe violation, the screens reachable through the
 * navigation — is asserted by `console.spec.ts`, and a spec that only writes
 * files would add a minute to every run and a directory of churn to every diff.
 * So it is opt-in:
 *
 *     E2E_SHOTS=docs/console/after ./scripts/browser-tests.sh \
 *       --project=js tests/console-shots.spec.ts
 *
 * `E2E_SHOTS` is the directory, relative to the repository root, and its
 * absence is what skips the file.
 *
 * # Why the selectors are the coarsest available
 *
 * Because it has to run against *both* designs: the "before" pictures are
 * taken with the previous bundle checked out, and a spec that named the new
 * shell's markup could not take them. A navigation link with a visible name
 * and a heading are what the two have in common.
 */
import { expect, test } from '@playwright/test';
import { signIn, signInAsDeploymentAdmin } from '../src/console.js';

const DIRECTORY = process.env.E2E_SHOTS;
const THEME = process.env.E2E_SHOTS_THEME ?? 'light';

test.skip(DIRECTORY === undefined, 'set E2E_SHOTS to a directory to take the pictures');

if (THEME !== 'light' && THEME !== 'dark') {
  throw new Error('E2E_SHOTS_THEME must be either light or dark');
}

async function prepareTheme(page: Parameters<typeof signIn>[0]): Promise<void> {
  await page.addInitScript((theme) => {
    window.localStorage.setItem('asterius.console.theme', theme);
  }, THEME);
}

/** The screens, as the navigation names them, and the file each one gets. */
const SCREENS: readonly (readonly [string, string])[] = [
  ['Overview', 'overview'],
  ['Users', 'users'],
  ['Applications', 'clients'],
  ['Signing keys', 'keys'],
  ['Shared signals', 'ssf'],
  ['Audit trail', 'audit'],
  ['Access policy', 'policy'],
  ['Tenant settings', 'settings'],
];

test('every console screen is photographed', async ({ page }) => {
  // Arrange: one signed-in shell, at the desktop sweep width.
  await page.setViewportSize({ width: 1440, height: 900 });
  await prepareTheme(page);
  await signIn(page);
  await expect(page.getByRole('heading', { name: 'Asterius console' })).toBeVisible();
  await expect(page.locator('html')).toHaveClass(THEME === 'dark' ? /dark/ : /^(?!.*dark)/);

  for (const [label, file] of SCREENS) {
    // Act: through the navigation, which is how an administrator gets there.
    await page.getByRole('link', { name: label, exact: true }).click();
    // The screen's own heading, so the picture is not of a half-drawn screen.
    await expect(page.getByRole('heading', { name: label, exact: true }).first()).toBeVisible();
    // The reads each screen opens with are given a moment to land: a skeleton
    // is a fair picture of a console, but not the one being reviewed.
    await page.waitForLoadState('networkidle');
    await page.screenshot({ path: `../${DIRECTORY}/${file}.png`, scale: 'css' });
  }
});

/**
 * The tenants screen, photographed as the only caller who can open it
 * (`ast-l5bl`).
 *
 * A second test and a second sign-in, because `reach: 'deployment'` means the
 * shell the loop above photographs — a tenant admin's — simply has no Tenants
 * link. Adding the screen to `SCREENS` would have photographed whatever the
 * click landed on instead.
 */
test('the tenants screen is photographed as the deployment administrator', async ({ page }) => {
  // Arrange
  await page.setViewportSize({ width: 1440, height: 900 });
  await prepareTheme(page);
  await signInAsDeploymentAdmin(page);

  // Act
  await page.getByRole('link', { name: 'Tenants', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Tenants', exact: true }).first()).toBeVisible();
  // The list, and then one settings read per row: the features column is the
  // last thing to arrive, and the picture is not of the screen without it.
  await page.waitForLoadState('networkidle');
  await page.screenshot({ path: `../${DIRECTORY}/tenants.png`, scale: 'css' });
});
