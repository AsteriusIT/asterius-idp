import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import { BASE_URL } from '../src/environment.js';
import { CONSOLE_URL } from '../src/console.js';
import { CspWatcher } from '../src/csp.js';

test('external sign-in errors explain recovery without reflecting provider input', async ({ context, page }, testInfo) => {
  const scripted = testInfo.project.name === 'js';
  const watcher = await CspWatcher.attach(context, scripted);
  const response = await page.goto(`${BASE_URL}/oidc/upstream/callback/missing?error=access_denied&error_description=untrusted-provider-detail&state=private-state`);
  expect(response?.status()).toBe(400);
  await expect(page.getByRole('heading', { name: 'We could not sign you in' })).toBeVisible();
  await expect(page.getByText('Return to the application you were trying to access and start a new sign-in request.')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Return to sign-in' })).toHaveCount(0);
  const body = await page.locator('body').innerText();
  expect(body).not.toContain('untrusted-provider-detail');
  expect(body).not.toContain('private-state');
  if (scripted) {
    const accessibility = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
    expect(accessibility.violations).toEqual([]);
  }
  await page.screenshot({ path: testInfo.outputPath('external-sign-in-error.png'), fullPage: true });
  watcher.assertClean('external sign-in error page');
});

test('external sign-in errors return a live browser interaction to tenant sign-in', async ({ page }) => {
  await page.goto(CONSOLE_URL);
  await expect(page.locator('input[name="username"]')).toBeVisible();
  const login = page.url();
  const response = await page.goto(`${BASE_URL}/oidc/upstream/callback/missing?error=access_denied`);
  expect(response?.status()).toBe(400);
  const retry = page.getByRole('link', { name: 'Return to sign-in' });
  await expect(retry).toHaveAttribute('href', new URL(login).pathname);
  await retry.click();
  await expect(page.locator('input[name="username"]')).toBeVisible();
  expect(page.url()).toBe(login);
});
