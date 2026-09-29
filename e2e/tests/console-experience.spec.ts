/** Focused UI regressions using the real bundle and deterministic API responses.
 * These tests verify browser behavior, not backend authorization/integration.
 */
import { test, expect, type Page, type Route } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const dist = resolve(import.meta.dirname, '../../console/dist');
const manifest = JSON.parse(readFileSync(`${dist}/.vite/manifest.json`, 'utf8'));
const origin = 'https://console-experience.test';
const entry = `${origin}/t/review/admin/`;
const nonce = 'experience-review-test-nonce';
const session = { tenant: 'review', workspace: 'review', user: 'admin', username: 'admin@example.test', roles: ['tenant_admin'],
  scopes: ['admin.session:read', 'admin.users:read', 'admin.users:write', 'admin.tenants:write', 'admin.resource_servers:read', 'admin.resource_servers:write', 'admin.authorization_details_types:read', 'admin.authorization_details_types:write', 'admin.flows:read', 'admin.clients:read', 'admin.clients:write'], deployment_scopes: [], csrf_token: 'fixture-csrf' };
const user = { user_id: 'alex', username: 'alex@example.test', email: 'alex@example.test', email_verified: true, status: 'active', can_authenticate: true, claims: {}, created_at: 1700000000, updated_at: 1700000000 };
const settings = { tenant_id: 'review', disabled_features: [], acr_policy: { levels: [] }, authorization_code_lifetime_seconds: 60, access_token_lifetime_seconds: 300 };

type Reply = { body: unknown; status?: number };
async function prepare(page: Page, override?: (path: string, route: Route) => Reply | undefined) {
  const errors: string[] = [];
  await page.emulateMedia({ reducedMotion: 'reduce' });
  page.on('pageerror', error => errors.push(error.message));
  await page.route(`${origin}/**`, async route => {
    const url = new URL(route.request().url());
    const path = url.pathname.split('/api/v1/')[1];
    if (path !== undefined) {
      const custom = override?.(path, route);
      const body = path.endsWith('/oidc-bindings') ? { bindings: [] } : path === 'session' ? session : path === 'users/alex' ? user : path.endsWith('/credentials') ? { password: true, passkeys: [] }
        : path === 'users' ? { items: [{ ...user, claims: 0 }], next_cursor: null }
        : path === 'tenants/review/settings' ? settings
        : path === 'resource-servers' ? { items: [{ identifier: 'https://api.example.test', scopes: ['read'], default_token_lifetime_seconds: null, introspection_clients: [] }] }
        : { items: [], next_cursor: null };
      await route.fulfill({ status: custom?.status ?? 200, contentType: 'application/json', body: JSON.stringify(custom?.body ?? body) });
    } else if (url.pathname.endsWith('/admin/')) {
      await route.fulfill({ contentType: 'text/html', headers: { 'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${nonce}' 'strict-dynamic'; style-src 'nonce-${nonce}'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'` },
        body: `<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>Console</title><link rel="stylesheet" nonce="${nonce}" href="${manifest['style.css'].file}"></head><body><div id="console"></div><script id="console-entry" nonce="${nonce}" type="module" src="${manifest['src/main.tsx'].file}"></script></body></html>` });
    } else if (url.pathname.includes('/assets/')) {
      const filename = url.pathname.split('/assets/')[1]!;
      await route.fulfill({ body: readFileSync(`${dist}/assets/${filename}`), contentType: filename.endsWith('.js') ? 'application/javascript' : filename.endsWith('.css') ? 'text/css' : 'font/woff2' });
    } else await route.fulfill({ status: 404, body: 'Not found' });
  });
  return errors;
}

test('resource request expiry removes the privileged shell', async ({ page }) => {
  await prepare(page, path => path === 'users' ? { status: 401, body: { error: { message: 'Expired' } } } : undefined);
  await page.goto(`${entry}#/users`);
  await expect(page.getByRole('heading', { name: 'Signed out', exact: true })).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Console sections' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
});

test('withdrawal requires confirmation and a failed write keeps the dialog open', async ({ page }) => {
  let writes = 0;
  const errors = await prepare(page, (path, route) => {
    if (path.startsWith('resource-servers/') && route.request().method() === 'DELETE') {
      writes++; return { status: 409, body: { error: { message: 'This audience is still in use.' } } };
    }
    return undefined;
  });
  await page.goto(`${entry}#/resources`);
  await page.getByRole('button', { name: 'Withdraw', exact: true }).click();
  const dialog = page.getByRole('alertdialog');
  await expect(dialog).toBeVisible();
  expect(writes).toBe(0);
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  expect(writes).toBe(0);
  await page.getByRole('button', { name: 'Withdraw', exact: true }).click();
  await dialog.getByRole('button', { name: 'Withdraw registration' }).click();
  await expect(dialog.getByRole('alert')).toContainText('This audience is still in use.');
  expect(writes).toBe(1);
  expect(errors).toEqual([]);
});

test('dirty schema navigation preserves or discards the draft by explicit choice', async ({ page }) => {
  await prepare(page);
  await page.goto(`${entry}#/authorization-details`);
  await page.getByRole('button', { name: 'Register type' }).click();
  await page.getByLabel('Type name', { exact: true }).fill('payment');
  await page.getByRole('link', { name: 'Users', exact: true }).click();
  await page.getByRole('button', { name: 'Keep editing' }).click();
  await expect(page.getByLabel('Type name', { exact: true })).toHaveValue('payment');
  await page.getByRole('link', { name: 'Users', exact: true }).click();
  await page.getByRole('button', { name: 'Discard changes', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Users', exact: true })).toBeVisible();
});

test('user tabs survive reload and keep unsaved identity edits between tabs', async ({ page }) => {
  const errors = await prepare(page);
  await page.goto(`${entry}#/users?id=alex&tab=sessions`);
  await expect(page.getByRole('tab', { name: 'Sessions', exact: true })).toHaveAttribute('aria-selected', 'true');
  await page.reload();
  await expect(page.getByRole('tab', { name: 'Sessions', exact: true })).toHaveAttribute('aria-selected', 'true');
  await page.getByRole('tab', { name: 'Identity data' }).click();
  await page.getByLabel('Email', { exact: true }).fill('new@example.test');
  await page.getByRole('tab', { name: 'Sessions', exact: true }).click();
  await expect(page.getByRole('alertdialog')).toHaveCount(0);
  await page.getByRole('tab', { name: 'Identity data' }).click();
  await expect(page.getByLabel('Email', { exact: true })).toHaveValue('new@example.test');
  await page.getByRole('button', { name: 'Back to users' }).click();
  await page.getByRole('button', { name: 'Keep editing' }).click();
  await expect(page.getByLabel('Email', { exact: true })).toHaveValue('new@example.test');
  expect(errors).toEqual([]);
});

test('schema editor reflows and remains accessible in both themes', async ({ page }) => {
  const errors = await prepare(page);
  await page.goto(`${entry}#/authorization-details`);
  await page.getByRole('button', { name: 'Register type' }).click();
  await page.getByLabel('Type name', { exact: true }).fill('payment');
  await page.getByLabel('Consent template', { exact: true }).fill('Initiate the payment you described');
  for (const dark of [false, true]) {
    await page.evaluate(value => document.documentElement.classList.toggle('dark', value), dark);
    await expect(page.locator('.content')).toHaveCSS('color', dark ? 'rgb(244, 244, 245)' : 'rgb(24, 24, 27)');
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      const save = page.getByRole('button', { name: 'Validate and register' });
      await expect(save).toBeEnabled();
      await save.scrollIntoViewIfNeeded();
      await expect(save).toBeInViewport();
      await page.getByRole('heading', { name: 'Authorization details', exact: true }).scrollIntoViewIfNeeded();
      if (width === 390 || width === 1440) {
        expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
        if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/schema-${width}-${dark ? 'dark' : 'light'}.png` });
      }
    }
  }
  expect(errors).toEqual([]);
});

test('browser Back cancellation retains its history destination and draft', async ({ page }) => {
  const errors = await prepare(page);
  await page.goto(`${entry}#/users`);
  await page.evaluate(() => { window.location.hash = '#/users?id=alex&tab=claims'; });
  await page.getByLabel('Email', { exact: true }).fill('draft@example.test');
  await page.evaluate(() => history.back());
  await page.getByRole('button', { name: 'Keep editing' }).click();
  await expect(page.getByLabel('Email', { exact: true })).toHaveValue('draft@example.test');
  await page.evaluate(() => history.back());
  await page.getByRole('button', { name: 'Discard changes', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Users', exact: true })).toBeVisible();
  await page.evaluate(() => history.forward());
  await expect(page.getByRole('button', { name: 'Back to users' })).toBeVisible();
  expect(errors).toEqual([]);
});

test('dirty resource dialog uses an inline discard choice and restores its opener', async ({ page }) => {
  await prepare(page);
  await page.goto(`${entry}#/resources`);
  await page.getByRole('button', { name: 'Register resource server' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Audience URL', { exact: true }).fill('https://draft.example.test');
  await page.keyboard.press('Escape');
  await expect(dialog.getByText('Your changes have not been saved.')).toBeVisible();
  await expect(page.getByRole('alertdialog')).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Keep editing' }).click();
  await expect(dialog.getByLabel('Audience URL', { exact: true })).toHaveValue('https://draft.example.test');
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
  await dialog.getByRole('button', { name: 'Discard changes' }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Register resource server' })).toBeFocused();
});


test('application secret survives tab changes and warns before leaving until acknowledged', async ({ page }) => {
  const client = { client_id: 'reports', client_name: 'Reports', compliance_profile: 'oidc', status: 'active', application_type: 'web',
    token_endpoint_auth_method: 'client_secret_basic', redirect_uris: ['https://reports.example.test/callback'], post_logout_redirect_uris: [],
    grant_types: ['authorization_code'], scope: 'openid', id_token_signed_response_alg: 'EdDSA', subject_type: 'public', resources: [],
    authorization_details_types: [], roles_in_id_token: false, managed_groups_claim: false };
  let writes = 0;
  const errors = await prepare(page, (path, route) => {
    if (path === 'clients/reports') {
      if (route.request().method() === 'PUT') { writes++; return { body: { ...client, client_secret: 'fixture-one-time-secret' } }; }
      return { body: client };
    }
    return undefined;
  });
  await page.goto(`${entry}#/clients?id=reports&tab=credentials`);
  await page.getByRole('button', { name: 'Rotate secret', exact: true }).click();
  await expect(page.getByText('fixture-one-time-secret', { exact: true })).toBeVisible();
  expect(writes).toBe(1);
  await page.getByRole('tab', { name: 'General', exact: true }).click();
  await page.getByRole('tab', { name: 'Credentials', exact: true }).click();
  await expect(page.getByText('fixture-one-time-secret', { exact: true })).toBeVisible();
  await page.getByRole('link', { name: 'Users', exact: true }).click();
  await page.getByRole('button', { name: 'Keep editing' }).click();
  await page.getByRole('button', { name: 'I have saved the secret' }).click();
  await page.getByRole('link', { name: 'Users', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Users', exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});

test('expiry during a write removes both the editor and its draft prompt', async ({ page }) => {
  let writes = 0;
  await prepare(page, (path, route) => {
    if (path.startsWith('resource-servers/') && route.request().method() === 'PUT') {
      writes++; return { status: 401, body: { error: { message: 'Expired' } } };
    }
    return undefined;
  });
  await page.goto(`${entry}#/resources`);
  await page.getByRole('button', { name: 'Register resource server' }).click();
  await page.getByLabel('Audience URL', { exact: true }).fill('https://new.example.test');
  await page.getByRole('dialog').getByRole('button', { name: 'Register resource server' }).click();
  await expect(page.getByRole('heading', { name: 'Signed out', exact: true })).toBeVisible();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(page.getByRole('alertdialog')).toHaveCount(0);
  expect(writes).toBe(1);
});
