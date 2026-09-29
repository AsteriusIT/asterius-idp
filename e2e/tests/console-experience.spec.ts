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

test('architecture editor opens an object, saves its changes and previews the saved revision', async ({ page }) => {
  const id = 'a0000000-0000-4000-8000-000000000001';
  let flow = { id, name: 'Review architecture', revision: 1, updated_at: '2026-09-29T00:00:00Z', graph: { schema_version: 1,
    nodes: [{ id: 'api', kind: 'api', mode: 'managed', label: 'Review API', identifier: 'https://api.example/', x: 0, y: 0, settings: { scopes: ['read'] } }], edges: [] } };
  const errors = await prepare(page, (path, route) => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.flows:write'] } };
    if (path === `flows/${id}`) {
      if (route.request().method() === 'PUT') flow = { ...flow, ...route.request().postDataJSON(), revision: flow.revision + 1 };
      return { body: flow };
    }
    if (path === `flows/${id}/plan`) return { body: { flow_id: id, revision: flow.revision, digest: 'fixture', applicable: true, steps: [] } };
    return undefined;
  });
  await page.goto(`${entry}#/architecture?flow=${id}&mode=edit`);
  await page.getByRole('button', { name: 'Show object list', exact: true }).click();
  await page.getByRole('button', { name: 'Review API · API', exact: true }).click();
  await page.getByLabel('Display name', { exact: true }).fill('Updated API');
  await page.getByRole('button', { name: 'Save draft', exact: true }).click();
  await expect.poll(() => flow.graph.nodes[0]?.label).toBe('Updated API');
  await page.getByRole('button', { name: 'Review changes', exact: true }).click();
  await expect(page.getByText('Ready to apply.', { exact: false })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Apply this plan', exact: true })).toBeEnabled();
  expect(errors).toEqual([]);
});

test('architecture URL rejects malformed identifiers before any flow request', async ({ page }) => {
  const requested: string[] = [];
  const errors = await prepare(page, path => { requested.push(path); return undefined; });
  await page.goto(`${entry}#/architecture?flow=${encodeURIComponent('../../users')}`);
  await expect(page.getByText('Invalid architecture identifier', { exact: true })).toBeVisible();
  expect(requested.filter(path => path.startsWith('flows/') || path === 'users')).toEqual([]);
  expect(errors).toEqual([]);
});


test('tenant TOTP activation saves and reloads without replacing existing assurance levels', async ({ page }) => {
  let saved = { ...settings, limits: { max_authorization_code_lifetime_seconds: 60, max_access_token_lifetime_seconds: 3600 }, acr_policy: { amr_in_id_token: true, levels: [
    { value: 'password', amr: ['pwd'] }, { value: 'phr', amr: ['swk'] },
  ] } };
  let writes = 0;
  await prepare(page, (path, route) => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.tenants:read'] } };
    if (path !== 'tenants/review/settings') return undefined;
    if (route.request().method() === 'PUT') { saved = { ...saved, ...route.request().postDataJSON() }; writes++; }
    return { body: saved };
  });
  await page.goto(`${entry}#/settings`);
  await page.getByRole('tab', { name: 'Authentication', exact: true }).click();
  await expect(page.getByRole('status')).toContainText('Disabled in this configuration');
  await page.getByRole('button', { name: 'Enable authenticator codes' }).click();
  expect(writes).toBe(0);
  await expect(page.getByLabel('Assurance level 2: Authenticator code')).toBeChecked();
  await page.getByRole('button', { name: 'Save settings', exact: true }).click();
  await expect.poll(() => writes).toBe(1);
  expect(saved.acr_policy.levels.map(level => level.amr)).toEqual([['pwd'], ['pwd', 'otp'], ['swk']]);
  await page.reload();
  await page.getByRole('tab', { name: 'Authentication', exact: true }).click();
  await expect(page.getByLabel('Assurance level 2: Authenticator code')).toBeChecked();
  await page.getByLabel('Assurance level 2: Authenticator code').uncheck();
  await page.getByRole('button', { name: 'Save settings', exact: true }).click();
  await expect.poll(() => writes).toBe(2);
  expect(saved.acr_policy.levels.some(level => level.amr.includes('otp'))).toBe(false);
});

test('an audit event link loads its record independently of the current list', async ({ page }) => {
  const event = { id: 42, hash: 'abc', type: 'auth.login', outcome: 'success', occurred_at: '2026-09-29T12:00:00Z', detail: { source: 'fixture' } };
  const errors = await prepare(page, path => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.audit:read'] } };
    if (path === 'audit/events/42') return { body: event };
    return undefined;
  });
  await page.goto(`${entry}#/audit?id=42`);
  await expect(page.getByRole('heading', { name: 'Event #42', exact: true })).toBeVisible();
  await expect(page.getByText('auth.login', { exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByRole('button', { name: 'Copy event link' })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page).toHaveURL(`${entry}#/audit`);
  expect(errors).toEqual([]);
});

test('policy restoration confirms publication and keeps failures in the dialog', async ({ page }) => {
  let writes = 0;
  const policy = { document: { version: 1, rules: [] }, rule_count: 0, updated_at: '2026-09-29T12:00:00Z' };
  const errors = await prepare(page, (path, route) => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.policies:read', 'admin.policies:write'] } };
    if (path === 'policies/history') return { body: { items: [{ id: 7, policy }] } };
    if (path === 'policies') {
      if (route.request().method() === 'PUT') { writes++; return { status: 409, body: { error: { message: 'Publication refused for this test.' } } }; }
      return { body: policy };
    }
    return undefined;
  });
  await page.goto(`${entry}#/policy`);
  await page.locator('summary').filter({ hasText: 'Version 7' }).click();
  await page.getByRole('button', { name: 'Restore version 7', exact: true }).click();
  expect(writes).toBe(0);
  await page.getByRole('button', { name: 'Restore and publish' }).click();
  await expect(page.getByRole('alertdialog')).toContainText('Publication refused for this test.');
  expect(writes).toBe(1);
  expect(errors).toEqual([]);
});

test('schema sample checks use the draft and invalidate stale results when edited', async ({ page }) => {
  let body: unknown;
  await prepare(page, (path, route) => {
    if (path === 'authorization-details-types/validate-sample') {
      body = route.request().postDataJSON();
      return { body: { valid: false, message: 'Schema violation at /amount' } };
    }
    return undefined;
  });
  await page.goto(`${entry}#/authorization-details`);
  await page.getByRole('button', { name: 'Register type', exact: true }).click();
  await page.getByLabel('Sample JSON', { exact: true }).fill('{"amount":42}');
  await page.getByRole('button', { name: 'Validate sample', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('/amount');
  expect(body).toEqual({ schema: { type: 'object' }, sample: { amount: 42 } });
  await page.getByLabel('Sample JSON', { exact: true }).fill('{}');
  await expect(page.getByText('Schema violation at /amount')).toHaveCount(0);
});

test('guided application setup preserves fields and requires review before registration', async ({ page }) => {
  let writes = 0;
  const errors = await prepare(page, (_path, route) => {
    if (route.request().method() === 'POST') writes++;
    return undefined;
  });
  await page.goto(`${entry}#/clients`);
  await page.getByRole('button', { name: 'Guided setup', exact: true }).click();
  await page.getByLabel('Client name', { exact: true }).fill('Review app');
  await expect(page.getByRole('button', { name: 'Register client', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  await page.getByRole('button', { name: 'Previous step', exact: true }).click();
  await expect(page.getByLabel('Client name', { exact: true })).toHaveValue('Review app');
  await page.getByRole('tab', { name: 'Review', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Review application', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Register client', exact: true })).toBeVisible();
  expect(writes).toBe(0);
  expect(errors).toEqual([]);
});

test('user server sorting and search survive an account inspection', async ({ page }) => {
  const queries: string[] = [];
  await prepare(page, (path, route) => {
    if (path === 'users') queries.push(new URL(route.request().url()).search);
    return undefined;
  });
  await page.goto(`${entry}#/users`);
  await page.getByLabel('Search', { exact: true }).fill('alex');
  await page.getByRole('button', { name: 'Search', exact: true }).click();
  await page.getByLabel('Server order', { exact: true }).selectOption('-username');
  await expect.poll(() => queries.some(query => query.includes('sort=-username') && query.includes('q=alex'))).toBe(true);
  await page.getByRole('button', { name: /alex@example.test/ }).click();
  await page.getByRole('button', { name: /Back to users/ }).click();
  await expect(page.getByLabel('Search', { exact: true })).toHaveValue('alex');
  await expect(page.getByLabel('Server order', { exact: true })).toHaveValue('-username');
});

test('OIDC metadata checks run automatically and allow an explicit retry', async ({ page }) => {
  let checks = 0;
  const errors = await prepare(page, (path, route) => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.oidc_providers:read'] } };
    if (path === 'oidc/providers') return { body: { providers: [{ id: 'external', name: 'External provider', issuer: 'https://issuer.example.test', client_id: 'console', enabled: true, secret_configured: true, callback_url: 'https://idp.example.test/callback' }] } };
    if (path === 'oidc/providers/check') {
      checks++;
      expect(route.request().postDataJSON()).toEqual({ id: 'external' });
      return { body: { checked_at: 1700000000, checks: [{ name: 'discovery', status: 'pass', message: 'Discovery metadata is valid.' }] } };
    }
    return undefined;
  });
  await page.goto(`${entry}#/oidc-providers`);
  await expect(page.getByText('Metadata checks pass', { exact: true })).toBeVisible();
  expect(checks).toBe(1);
  await page.getByRole('button', { name: 'Check now', exact: true }).click();
  await expect.poll(() => checks).toBe(2);
  expect(errors).toEqual([]);
});

test('guided setup and assurance settings support keyboard, reflow and zoom', async ({ page }) => {
  const errors = await prepare(page, path => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.tenants:read'] } };
    if (path === 'tenants/review/settings') return { body: { ...settings, limits: { max_authorization_code_lifetime_seconds: 60, max_access_token_lifetime_seconds: 3600 }, acr_policy: { levels: [{ value: 'password', amr: ['pwd'] }] } } };
    return undefined;
  });
  await page.goto(`${entry}#/clients?mode=new&guided=1`);
  await page.getByRole('tab', { name: 'General', exact: true }).focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.getByRole('tab', { name: 'Callbacks', exact: true })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('tab', { name: 'Callbacks', exact: true })).toHaveAttribute('aria-selected', 'true');
  for (const destination of ['clients?mode=new&guided=1', 'settings']) {
    await page.goto(`${entry}#/${destination}`);
    if (destination === 'settings') await page.getByRole('tab', { name: 'Authentication', exact: true }).click();
    for (const dark of [false, true]) {
      await page.evaluate(value => document.documentElement.classList.toggle('dark', value), dark);
      await expect(page.locator('.content')).toHaveCSS('color', dark ? 'rgb(244, 244, 245)' : 'rgb(24, 24, 27)');
      for (const width of [320, 1440]) {
        await page.setViewportSize({ width, height: 1000 });
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
        expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
      }
    }
    // 200% document zoom complements the 320px reflow check (1280px at 400%).
    await page.evaluate(value => { const style = document.createElement('style'); style.id = 'zoom-check'; style.nonce = value; style.textContent = 'html { zoom: 2; }'; document.head.append(style); }, nonce);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    const action = page.getByRole('button', { name: destination === 'settings' ? 'Enable authenticator codes' : 'Continue', exact: true });
    await action.focus();
    await expect(action).toBeFocused();
    await action.scrollIntoViewIfNeeded();
    await expect(action).toBeInViewport();
    await page.evaluate(() => document.getElementById('zoom-check')?.remove());
  }
  expect(errors).toEqual([]);
});

test('access overview skips failed sign-ins when finding the last success', async ({ page }) => {
  await prepare(page, (path, route) => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.audit:read'] } };
    if (path === 'audit/events') return { body: new URL(route.request().url()).searchParams.has('cursor')
      ? { items: [{ outcome: 'success', occurred_at: '2026-09-28T12:00:00Z' }], next_cursor: null }
      : { items: [{ outcome: 'failure', occurred_at: '2026-09-29T12:00:00Z' }], next_cursor: 'older' } };
    return undefined;
  });
  await page.goto(`${entry}#/users?id=alex`);
  const summary = page.locator('section').filter({ has: page.getByRole('heading', { name: 'Access overview', exact: true }) }).last();
  await expect(summary).toContainText('2026-09-28');
  await expect(summary).not.toContainText('2026-09-29');
});

test('manual configuration checks report missing setup without sending a mutation', async ({ page }) => {
  let writes = 0;
  await prepare(page, (path, route) => {
    if (route.request().method() !== 'GET') writes++;
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.keys:read'] } };
    if (path === 'federation/keys') return { body: { keys: [], rotation_period_seconds: 0 } };
    return undefined;
  });
  await page.goto(`${entry}#/federation`);
  await expect(page.getByText('No active federation signing key is configured.', { exact: false })).toHaveCount(0);
  await page.getByRole('button', { name: 'Check configuration', exact: true }).click();
  await expect(page.getByText('No active federation signing key is configured.', { exact: false })).toBeVisible();
  await expect(page.getByText('Automatic rotation has no positive period configured.', { exact: false })).toBeVisible();
  expect(writes).toBe(0);
});
