// Real browser authentication; callback code stays in its private fixture file.
import { chromium } from '../../e2e/node_modules/playwright-core/index.mjs';
import { readFile, writeFile } from 'node:fs/promises';
const file = process.argv[2];
const input = JSON.parse(await readFile(file, 'utf8'));
const browser = await chromium.launch({ headless: true });
let stage = 'open authorization';
try {
  const context = await browser.newContext({ ignoreHTTPSErrors: true,
    ...(input.mode === 'logout' ? { storageState: file + '.storage.json' } : {}) });
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  if (input.mode === 'logout') {
    stage = 'source logout';
    await page.goto(input.issuer + '/logout');
    await page.getByRole('button', { name: 'Log out', exact: true }).click();
    if ((await context.cookies()).some(cookie => cookie.name === '__Host-asterius_session')) {
      throw new Error('source session cookie survived logout');
    }
  } else {
  await page.goto(input.authorizationUrl);
  stage = 'username/password form';
  await page.locator('input[name="username"]').fill('sweep@example.test');
  await page.locator('input[name="password"]').fill('correct horse battery staple');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  stage = 'consent';
  if (!new URL(page.url()).pathname.endsWith('/oidc/callback')) {
    await page.getByRole('button', { name: 'Allow', exact: true }).click();
  }
  stage = 'callback';
  await page.waitForURL(url => url.pathname.endsWith('/oidc/callback'));
  const url = new URL(page.url());
  if (!url.searchParams.has('code') || !url.searchParams.has('state')) {
    throw new Error('provider did not return an authorization code');
  }
  await writeFile(file, JSON.stringify(Object.fromEntries(url.searchParams)), { mode: 0o600 });
  await context.storageState({ path: file + '.storage.json' });
  }
} catch {
  console.error('NATIVE_BROWSER_STAGE=' + stage);
  process.exitCode = 1;
} finally {
  await browser.close();
}
