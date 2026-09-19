import { expect, test } from '../src/fixtures.js';
import { PASSWORD, USERNAME } from '../src/environment.js';

const APP_A = process.env.E2E_DEMO_A_URL ?? 'https://localhost:9551';
const APP_B = process.env.E2E_DEMO_B_URL ?? 'https://localhost:9552';

test('two confidential BFFs share IdP authentication and keep separate consent', async ({ page }) => {
  await page.goto(APP_A);
  await page.getByRole('link', { name: 'Sign in with Asterius' }).click();
  await page.locator('input[name="username"]').fill(USERNAME);
  await page.locator('input[name="password"]').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Allow' })).toBeVisible();
  await page.getByRole('button', { name: 'Allow' }).click();
  await expect(page.getByText('Signed in as')).toBeVisible();
  await expect(page.locator('[data-testid="userinfo"]')).toContainText('sub');

  await page.goto(APP_B);
  await page.getByRole('link', { name: 'Sign in with Asterius' }).click();
  await expect(page.locator('input[name="password"]')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Allow' })).toBeVisible();
  await page.getByRole('button', { name: 'Allow' }).click();
  await expect(page.getByText('Signed in as')).toBeVisible();

  await page.getByRole('link', { name: 'Refresh tokens' }).click();
  await expect(page.getByText('Signed in as')).toBeVisible();

  await page.getByRole('link', { name: 'Force reauthentication' }).click();
  await expect(page.locator('input[name="password"]')).toBeVisible();
  await page.goto(APP_B);
  await page.getByRole('link', { name: 'Require passkey step-up' }).click();
  await expect(page.getByRole('button', { name: 'Sign in with a passkey' })).toBeVisible();

  await page.goto(`${APP_A}/logout`);
  await expect(page.getByText('This application session is signed out.')).toBeVisible();
  await page.goto(`${APP_B}/check-session`);
  await expect(page.getByText('Signed out.')).toBeVisible();
});
