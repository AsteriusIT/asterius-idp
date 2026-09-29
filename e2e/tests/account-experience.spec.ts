/** Layout/native-form checks against Rust-produced fixtures. Backend journeys
 * remain in no-js-account.spec.ts; these fixtures never authenticate a user. */
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '../..');
const origin = 'https://account-experience.test';
const fixtures = ['account_totp.setup', 'account_totp.active', 'account_totp.pending', 'account_providers', 'account_external_approvals'];

for (const locale of ['en', 'fr']) {
  test(`account security pages reflow with native forms (${locale})`, async ({ page }, info) => {
    const violations: string[] = [];
    await page.route(`${origin}/**`, async route => {
      const url = new URL(route.request().url());
      if (url.pathname.endsWith('.woff2')) {
        await route.fulfill({ contentType: 'font/woff2', body: readFileSync(`${root}/crates/web/assets/fonts/Geist-Variable.woff2`) });
      } else if (route.request().method() === 'POST') {
        await route.fulfill({ contentType: 'text/plain', body: 'Native POST received' });
      } else {
        const name = url.pathname.slice(1);
        if (!fixtures.includes(name)) { await route.fulfill({ status: 404 }); return; }
        await route.fulfill({ contentType: 'text/html', headers: {
          'Content-Security-Policy': "default-src 'none'; script-src 'nonce-snapshot-nonce' 'strict-dynamic'; style-src 'nonce-snapshot-nonce'; img-src 'self'; font-src 'self'; form-action 'self'; base-uri 'none'",
        }, body: readFileSync(`${root}/crates/web/tests/golden/${name}.${locale}.html`, 'utf8') });
      }
    });
    page.on('console', message => { if (message.text().includes('violates the following Content Security Policy')) violations.push(message.text()); });
    for (const fixture of fixtures) {
      await page.goto(`${origin}/${fixture}`);
      await expect(page.locator('html')).toHaveAttribute('lang', locale);
      await expect(page.getByRole('main')).toBeVisible();
      await expect(page.locator('script')).toHaveCount(0);
      if (fixture === 'account_totp.setup') {
        expect((await page.locator('input[name=code]').boundingBox())!.height).toBeGreaterThanOrEqual(44);
      }
      for (const width of [320, 390, 768, 1440]) {
        await page.setViewportSize({ width, height: 900 });
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      }
      if (info.project.name === 'js') {
        expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
      }
      if (process.env.E2E_SHOTS && fixture === 'account_totp.setup' && info.project.name === 'no-js') {
        await page.setViewportSize({ width: 390, height: 900 });
        await page.screenshot({ path: `${process.env.E2E_SHOTS}/authenticator-${locale}-390.png`, fullPage: true });
      }
    }
    await page.goto(`${origin}/account_totp.active`);
    await page.locator('summary').click();
    const checkbox = page.getByRole('checkbox');
    await expect(checkbox).toBeVisible();
    expect(await page.locator('form').evaluate(form => (form as HTMLFormElement).checkValidity())).toBe(false);
    await checkbox.check();
    const request = page.waitForRequest(request => request.method() === 'POST');
    await page.getByRole('button').click();
    const fields = new URLSearchParams((await request).postData()!);
    expect(fields.get('csrf')).toBe('snapshot-csrf');
    expect(fields.get('action')).toBe('remove');
    expect(violations).toEqual([]);
  });
}
