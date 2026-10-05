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
      await route.fulfill({ body: readFileSync(`${dist}/assets/${filename}`), contentType: filename.endsWith('.js') ? 'application/javascript' : filename.endsWith('.css') ? 'text/css' : filename.endsWith('.svg') ? 'image/svg+xml' : 'font/woff2' });
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

test('Kubernetes page uses searchable pickers, YAML examples and a separate terminal section', async ({ page }) => {
  const profile = { cluster_id: 'production', client_id: 'broker', namespace: 'apps', group_ids: ['operators'], revision: 2,
    issuer: 'https://issuer.example.test', audience: 'https://cluster.example.test', registration_compatible: true,
    authentication_configuration: { apiVersion: 'apiserver.config.k8s.io/v1beta1', kind: 'AuthenticationConfiguration' },
    rbac_bindings: [{ apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'RoleBinding', metadata: { name: 'view' } }], legacy_flags: ['--oidc-issuer-url=https://issuer.example.test'] };
  const errors = await prepare(page, path => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.groups:read'] } };
    if (path === 'clients') return { body: { items: [{ client_id: 'broker', client_name: 'Cluster broker', status: 'active' }, { client_id: 'another', client_name: 'Unused broker', status: 'active' }], next_cursor: null } };
    if (path === 'clients/broker/kubernetes') return { body: profile };
    if (path === 'clients/another/kubernetes') return { status: 404, body: {} };
    if (path === 'clients/broker/kubernetes/online') return { status: 404, body: {} };
    if (path === 'groups') return { body: { items: [{ id: 'operators', display_name: 'Operators', name: 'operators' }, { id: 'auditors', display_name: 'Auditors', name: 'auditors' }], next_cursor: null } };
    if (path === 'groups/operators') return { body: { id: 'operators', display_name: 'Operators', name: 'operators' } };
    return undefined;
  });
  await page.goto(`${entry}#/kubernetes`);
  await expect(page.getByRole('navigation', { name: 'Console sections' }).getByRole('link', { name: 'Help & guides' })).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'Help and guides' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Architecture builder' })).toBeVisible();
  expect(await page.locator('a[href="#/kubernetes"] img').evaluate(image => (image as HTMLImageElement).naturalWidth)).toBeGreaterThan(0);
  await expect(page.getByRole('table', { name: 'Cluster profiles' })).toBeVisible();
  await expect(page.getByRole('region', { name: 'Connected clusters' })).toBeVisible();
  await page.getByRole('button', { name: 'Add cluster' }).click();
  await page.getByRole('combobox', { name: 'Broker application' }).click();
  await page.getByRole('combobox', { name: 'Search broker applications' }).fill('unused');
  await expect(page.getByRole('option', { name: /Unused broker/ })).toBeVisible();
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: /View production/ }).click();
  await expect(page.getByRole('region', { name: 'Cluster authentication configuration' })).toContainText('apiVersion:');
  await expect(page.getByRole('region', { name: 'Cluster authentication configuration' })).not.toContainText('"apiVersion"');
  await expect(page.getByRole('region', { name: 'Terminal login', exact: true })).toBeVisible();
  await page.getByRole('combobox', { name: /Released managed groups/ }).click();
  await page.getByRole('combobox', { name: 'Search managed groups' }).fill('Audit');
  await expect(page.getByRole('option', { name: /Auditors/ })).toBeVisible();
  await page.getByRole('option', { name: /Auditors/ }).click();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('button', { name: 'Remove Auditors (auditors)' })).toBeVisible();
  await page.setViewportSize({ width: 390, height: 800 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await expect(page.getByRole('link', { name: 'Help and guides' })).toBeInViewport();
  expect(errors).toEqual([]);
});

test('Provisioning client searches inside its select and retains an off-page choice', async ({ page }) => {
  const errors = await prepare(page, (path, route) => {
    if (path === 'clients') {
      const query = new URL(route.request().url()).searchParams.get('q') ?? '';
      return { body: query.toLowerCase().includes('outside')
        ? { items: [{ client_id: 'outside', client_name: 'Outside page broker' }], next_cursor: null }
        : query === ''
          ? { items: [{ client_id: 'first', client_name: 'First page broker' }], next_cursor: 'more' }
          : { items: [], next_cursor: null } };
    }
    if (path === 'clients/outside') return { body: { client_id: 'outside', client_name: 'Outside page broker', status: 'active',
      token_endpoint_auth_method: 'private_key_jwt', grant_types: ['client_credentials'], dpop_bound_access_tokens: true,
      resources: [], scope: 'admin.scim:read admin.scim:write' } };
    return undefined;
  });
  await page.goto(`${entry}#/scim`);
  const picker = page.getByRole('combobox', { name: 'Application', exact: true });
  await expect(picker).toBeVisible();
  await expect(page.getByRole('button', { name: 'Search applications' })).toHaveCount(0);
  await picker.click();
  await expect(page.getByText('More results exist. Refine your search.')).toBeVisible();
  await page.getByRole('combobox', { name: 'Search provisioning applications' }).fill('outside');
  await expect(page.getByRole('option', { name: /Outside page broker/ })).toBeVisible();
  if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/scim-provisioning-picker.png` });
  await page.getByRole('option', { name: /Outside page broker/ }).click();
  await expect(picker).toContainText('Outside page broker (outside)');
  await expect(page.getByRole('status').filter({ hasText: 'Outside page broker' })).toBeVisible();
  await picker.click();
  await page.getByRole('combobox', { name: 'Search provisioning applications' }).fill('nothing');
  await expect(page.getByText('No applications match. Try a name or client ID.')).toBeVisible();
  await expect(picker).toContainText('Outside page broker (outside)');
  await page.getByRole('button', { name: 'Clear selection' }).click();
  await expect(picker).toContainText('Choose an application');
  await page.setViewportSize({ width: 390, height: 800 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  expect(errors).toEqual([]);
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
  await page.getByRole('button', { name: 'Edit identity data' }).click();
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
    await expect(page.locator('.content')).toHaveCSS('color', dark ? 'rgb(245, 246, 248)' : 'rgb(24, 24, 27)');
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
  await page.getByRole('button', { name: 'Edit identity data' }).click();
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
  await expect(page.getByText('fixture-one-time-secret', { exact: true })).toHaveCount(0);
  if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/client-secret-hidden.png` });
  await page.getByRole('button', { name: 'Show secret', exact: true }).click();
  await expect(page.getByText('fixture-one-time-secret', { exact: true })).toBeVisible();
  expect(writes).toBe(1);
  if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/client-secret-revealed.png` });
  await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async () => { throw new Error('Clipboard unavailable in this test'); } } }));
  await page.getByRole('button', { name: 'Copy secret', exact: true }).click();
  await expect(page.getByText('Copy was unavailable. Select and copy the value manually.', { exact: true })).toBeVisible();
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

test('tenant-wide test console selects an application and user, then decodes an issued ID token', async ({ page }) => {
  const client = { client_id: 'reports', client_name: 'Reports', compliance_profile: 'oidc', status: 'active', application_type: 'web',
    token_endpoint_auth_method: 'client_secret_basic', redirect_uris: ['https://reports.example.test/callback'], post_logout_redirect_uris: [],
    grant_types: ['authorization_code'], scope: 'openid', id_token_signed_response_alg: 'EdDSA', subject_type: 'public', resources: [],
    authorization_details_types: [], roles_in_id_token: false, managed_groups_claim: false };
  const claims = { iss: `${origin}/t/review`, sub: 'subject', aud: 'reports', asterius_test: true };
  const jwt = `${Buffer.from('{"typ":"JWT","alg":"EdDSA"}').toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.signature`;
  let issued = 0;
  const errors = await prepare(page, (path, route) => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.test_tokens:write'] } };
    if (path === 'clients') return { body: { items: [client], next_cursor: null } };
    if (path === 'clients/reports') return { body: client };
    if (path === 'clients/reports/test-token') {
      issued++;
      expect(route.request().postDataJSON()).toEqual({ user_id: 'alex' });
      return { body: { id_token: jwt, expires_in: 60 } };
    }
    return undefined;
  });
  await page.setViewportSize({ width: 1920, height: 900 });
  await page.goto(`${entry}#/token-console`);
  await expect(page.getByRole('heading', { name: 'Token test console' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Token test console' })).toHaveAttribute('aria-current', 'page');
  expect((await page.locator('.token-console-page').boundingBox())!.width).toBeGreaterThan(1480);
  if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/tenant-token-console.png` });
  await expect(page.getByRole('button', { name: 'Save client' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Issue test ID token' })).toBeDisabled();
  await page.getByRole('combobox', { name: 'Application' }).click();
  await page.getByRole('combobox', { name: 'Search applications for test token' }).fill('reports');
  await page.getByRole('option', { name: /Reports/ }).click();
  await expect(page.getByRole('button', { name: 'Issue test ID token' })).toBeDisabled();
  await page.getByRole('combobox', { name: 'User' }).click();
  await page.getByRole('combobox', { name: 'Search users for test token' }).fill('alex');
  await page.getByRole('option', { name: /alex@example.test/ }).click();
  await page.getByRole('button', { name: 'Issue test ID token' }).click();
  await expect(page.getByRole('region', { name: 'JWT claims' })).toContainText('asterius_test');
  await page.getByText('Claims as YAML').click();
  await expect(page.getByRole('region', { name: 'JWT claims YAML' })).toContainText('asterius_test: true');
  await page.setViewportSize({ width: 390, height: 844 });
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.goto(`${entry}#/clients?id=reports&tab=test`);
  await expect(page.getByRole('tab', { name: 'General' })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Test console' })).toHaveCount(0);
  expect(issued).toBe(1);
  expect(errors).toEqual([]);
});

test('application connection card keeps its blue gradient and adds borderless copy actions', async ({ page }) => {
  const client = { client_id: 'reports', client_name: 'Reports', compliance_profile: 'oidc', status: 'active', application_type: 'web',
    token_endpoint_auth_method: 'client_secret_basic', redirect_uris: ['https://reports.example.test/callback'], post_logout_redirect_uris: [],
    grant_types: ['authorization_code'], scope: 'openid', id_token_signed_response_alg: 'EdDSA', subject_type: 'public', resources: [],
    authorization_details_types: [], roles_in_id_token: false, managed_groups_claim: false };
  await prepare(page, path => path === 'clients/reports' ? { body: client } : undefined);
  await page.route('**/.well-known/openid-configuration', route => route.fulfill({ contentType: 'application/json', body: JSON.stringify({
    issuer: `${origin}/t/review`, token_endpoint_auth_methods_supported: ['client_secret_basic'],
  }) }));
  await page.goto(`${entry}#/clients?id=reports`);
  const card = page.locator('.application-connection-card');
  await expect(card.getByText('Connect to this application')).toBeVisible();
  expect(await card.evaluate(element => getComputedStyle(element).backgroundImage)).toContain('linear-gradient');
  for (const label of ['Copy client ID', 'Copy authentication method', 'Copy issuer', 'Copy discovery URL']) {
    const button = card.getByRole('button', { name: label });
    await expect(button).toBeVisible();
    expect(await button.evaluate(element => getComputedStyle(element).borderTopWidth)).toBe('0px');
  }
  if (process.env.E2E_SHOTS) await card.screenshot({ path: `${process.env.E2E_SHOTS}/application-connection-card.png` });
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
  const policy = { document: { version: 1, rules: [] }, revision: null, rule_count: 0, updated_at: '2026-09-29T12:00:00Z' };
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

test('directory search and status filter share one line and survive account inspection', async ({ page }) => {
  const queries: string[] = [];
  const clientQueries: string[] = [];
  await prepare(page, (path, route) => {
    if (path === 'users') queries.push(new URL(route.request().url()).search);
    if (path === 'clients') clientQueries.push(new URL(route.request().url()).search);
    return undefined;
  });
  await page.goto(`${entry}#/users`);
  await page.getByRole('searchbox', { name: 'Search' }).fill('alex');
  await page.getByRole('button', { name: 'Search', exact: true }).click();
  await page.getByRole('button', { name: /Filter by status: All statuses/ }).click();
  await page.getByRole('menuitemradio', { name: 'Active' }).click();
  await expect.poll(() => queries.some(query => query.includes('status=active') && query.includes('q=alex'))).toBe(true);
  await expect(page.getByRole('button', { name: /Order:/ })).toHaveCount(0);
  const userToolbar = page.locator('.directory-toolbar');
  const searchBox = await userToolbar.getByRole('searchbox').boundingBox();
  const filterButton = await userToolbar.getByRole('button', { name: /Filter by status/ }).boundingBox();
  expect(searchBox && filterButton && Math.abs(searchBox.y - filterButton.y) < 8).toBe(true);
  if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/users-toolbar.png`, fullPage: true });
  await page.getByRole('button', { name: /alex@example.test/ }).click();
  await page.getByRole('button', { name: /Back to users/ }).click();
  await expect(page.getByRole('searchbox', { name: 'Search' })).toHaveValue('alex');
  await expect(page.getByRole('button', { name: /Filter by status: Active/ })).toBeVisible();
  await page.goto(`${entry}#/clients`);
  const clientToolbar = page.locator('.directory-toolbar');
  await expect(clientToolbar.getByRole('searchbox', { name: 'Search clients' })).toBeVisible();
  await expect(clientToolbar.getByRole('button', { name: /Filter by status/ })).toBeVisible();
  await clientToolbar.getByRole('searchbox', { name: 'Search clients' }).fill('demo');
  await clientToolbar.getByRole('button', { name: 'Search' }).click();
  await clientToolbar.getByRole('button', { name: /Filter by status/ }).click();
  await page.getByRole('menuitemradio', { name: 'Disabled' }).click();
  await expect.poll(() => clientQueries.some(query => query.includes('status=disabled') && query.includes('q=demo'))).toBe(true);
  if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/clients-toolbar.png`, fullPage: true });
  await page.setViewportSize({ width: 320, height: 800 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await expect.poll(async () => {
    const clientSearch = await clientToolbar.getByRole('searchbox').boundingBox();
    const clientFilter = await clientToolbar.getByRole('button', { name: /Filter by status/ }).boundingBox();
    return clientSearch && clientFilter ? Math.abs(clientSearch.y - clientFilter.y) : Infinity;
  }).toBeLessThan(8);
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
    if (destination === 'settings') {
      await page.getByRole('tab', { name: 'Authentication', exact: true }).click();
    }
    for (const dark of [false, true]) {
      await page.evaluate(value => document.documentElement.classList.toggle('dark', value), dark);
      await expect(page.locator('.content')).toHaveCSS('color', dark ? 'rgb(245, 246, 248)' : 'rgb(24, 24, 27)');
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
  const check = page.getByRole('button', { name: 'Check configuration', exact: true });
  expect((await check.boundingBox())?.width).toBeLessThan(240);
  await check.click();
  await expect(page.getByText('No active federation signing key is configured.', { exact: false })).toBeVisible();
  await expect(page.getByText('Automatic rotation has no positive period configured.', { exact: false })).toBeVisible();
  expect(writes).toBe(0);
});

test('tenant settings open on tabs with direct controls', async ({ page }) => {
  await prepare(page, path => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.tenants:read', 'admin.policies:read', 'admin.policies:write', 'admin.theme:read', 'admin.theme:write'] } };
    if (path === 'tenants/review/settings') return { body: { ...settings, limits: { max_authorization_code_lifetime_seconds: 60, max_access_token_lifetime_seconds: 3600 }, acr_policy: { levels: [{ value: 'password', amr: ['pwd'] }] } } };
    return undefined;
  });
  await page.goto(`${entry}#/settings`);
  await expect(page.getByRole('tab', { name: 'Capabilities' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save settings' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Edit settings' })).toHaveCount(0);
  await expect(page.locator('.app-topbar').getByRole('link', { name: 'Architecture builder' })).toBeVisible();
});

test('workspace health is reachable from the top bar and reports scoped milestones', async ({ page }) => {
  await prepare(page, path => {
    if (path === 'overview/users') return { body: { value: 1 } };
    if (path === 'overview/applications') return { body: { value: 0 } };
    if (path === 'overview/keys') return { body: { value: 1 } };
    return undefined;
  });
  await page.goto(`${entry}#/overview`);
  await expect(page.getByText('Workspace setup checklist')).toHaveCount(0);
  await page.getByRole('link', { name: 'Workspace health', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Workspace setup checklist' })).toBeVisible();
  await expect(page.getByText('Needs setup')).toBeVisible();
  expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
});

test('linked upstream identities are read first and the linking dialog preserves a rejected draft', async ({ page }) => {
  await prepare(page, (path, route) => {
    if (path === 'users/alex/oidc-bindings') {
      if (route.request().method() === 'PUT') return { status: 409, body: { error: { message: 'Binding refused for this test.' } } };
      return { body: { bindings: [] } };
    }
    return undefined;
  });
  await page.goto(`${entry}#/users?id=alex&tab=credentials`);
  await expect(page.getByLabel('Exact upstream subject')).toHaveCount(0);
  await page.getByRole('button', { name: 'Link identity', exact: true }).click();
  await page.getByLabel('Provider ID').fill('external');
  await page.getByLabel('Exact issuer URL').fill('https://issuer.example.test');
  await page.getByLabel('Exact upstream subject').fill('subject-123');
  await page.getByRole('button', { name: 'Review link' }).click();
  await page.getByRole('button', { name: 'Confirm link' }).click();
  await expect(page.getByRole('dialog')).toContainText('Binding refused for this test.');
  await expect(page.getByLabel('Exact upstream subject')).toHaveValue('subject-123');
});

test('group membership is read first and its add form opens from an action', async ({ page }) => {
  const group = { id: 'group-1', name: 'operators', display_name: 'Operators', revision: 1, created_at: '2026-09-29T12:00:00Z', updated_at: '2026-09-29T12:00:00Z' };
  await prepare(page, path => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.groups:read', 'admin.groups:write', 'admin.memberships:read', 'admin.memberships:write'] } };
    if (path === 'groups') return { body: { items: [group], next_cursor: null } };
    if (path === 'groups/group-1') return { body: group };
    if (path === 'groups/group-1/members') return { body: { items: [], next_cursor: null } };
    return undefined;
  });
  await page.goto(`${entry}#/groups`);
  await page.getByRole('button', { name: 'View Operators' }).click();
  await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
  await expect(page.getByLabel('Find a user')).toHaveCount(0);
  await page.getByRole('button', { name: 'Add member' }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await expect(page.getByLabel('Find a user')).toBeVisible();
});

test('SAML signing and service-provider forms open from explicit actions', async ({ page }) => {
  await prepare(page, path => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.saml:read', 'admin.saml:write'] } };
    if (path === 'saml/idp-key') return { body: { keys: [] } };
    if (path === 'saml/sp-trusts') return { body: { service_providers: [] } };
    return undefined;
  });
  await page.goto(`${entry}#/saml`);
  await expect(page.getByLabel('X.509 certificate (DER)')).toHaveCount(0);
  await expect(page.getByLabel('Entity ID')).toHaveCount(0);
  await page.getByRole('button', { name: 'Import IdP key' }).click();
  await expect(page.getByRole('dialog').getByLabel('X.509 certificate (DER)')).toBeVisible();
  await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
  await page.getByRole('button', { name: 'Add service provider' }).click();
  await expect(page.getByRole('dialog').getByLabel('Entity ID')).toBeVisible();
});

test('inbound signal subject mapping reads first and opens bind/remove actions', async ({ page }) => {
  await prepare(page, path => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.ssf:read', 'admin.ssf:write'] } };
    if (path === 'ssf/streams') return { body: { items: [] } };
    return undefined;
  });
  await page.goto(`${entry}#/ssf`);
  await expect(page.getByRole('heading', { name: 'Inbound subject mapping' })).toBeVisible();
  await expect(page.getByLabel('Peer client ID')).toHaveCount(0);
  await page.getByRole('button', { name: 'Bind subject' }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByLabel('Peer client ID')).toBeVisible();
  await dialog.getByLabel('Peer client ID').fill('peer-1');
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog.getByText('Your changes have not been saved.')).toBeVisible();
  await dialog.getByRole('button', { name: 'Discard changes' }).click();
  await expect(dialog).toHaveCount(0);
  await page.getByRole('button', { name: 'Remove mapping' }).click();
  await expect(page.getByRole('dialog').getByRole('heading', { name: 'Remove inbound subject mapping' })).toBeVisible();
  await page.getByRole('dialog').getByLabel('Peer client ID').fill('peer-1');
  await page.getByRole('dialog').getByLabel('Local username').fill('alex@example.test');
  await page.getByRole('dialog').getByRole('button', { name: 'Review removal' }).click();
  await expect(page.getByRole('alertdialog')).toContainText('Security events for the entered peer');
});

test('dark surfaces keep readable headings and controls across main destinations', async ({ page }) => {
  test.setTimeout(90_000);
  await prepare(page, path => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.tenants:read', 'admin.policies:read', 'admin.theme:read', 'admin.keys:read'] } };
    if (path.startsWith('overview/')) return { body: { value: 0 } };
    if (path === 'policies') return { body: { document: { version: 1, rules: [] }, rule_count: 0, updated_at: '2026-09-29T12:00:00Z' } };
    if (path === 'tenants/review/settings') return { body: { ...settings, limits: { max_authorization_code_lifetime_seconds: 60, max_access_token_lifetime_seconds: 3600 }, acr_policy: { levels: [{ value: 'password', amr: ['pwd'] }] } } };
    return undefined;
  });
  for (const route of ['overview', 'users', 'clients', 'settings', 'policy', 'health']) {
    await page.goto(`${entry}#/${route}`);
    await page.evaluate(() => document.documentElement.classList.add('dark'));
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(page.locator('.content')).toHaveCSS('color', 'rgb(245, 246, 248)');
    await expect(page.locator('.screen-head h2')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    const violations = (await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations;
    expect(violations).toEqual([]);
  }
});

test('developer guides reveal focused recipes and searchable account-aware tasks', async ({ page }) => {
  const errors = await prepare(page);
  await page.goto(`${entry}#/help`);
  await expect(page.getByRole('tab', { name: 'Developer integration' })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('heading', { name: 'From registration to your first sign-in' })).toBeVisible();
  await expect(page.getByText('Keep tokens in your server or backend-for-frontend')).not.toBeVisible();
  await page.getByText('Web application or SPA with a backend', { exact: true }).click();
  await expect(page.getByText('Keep tokens in your server or backend-for-frontend')).toBeVisible();
  await page.getByRole('tab', { name: 'Console tasks' }).click();
  await page.getByRole('searchbox', { name: 'Search console guides' }).fill('application');
  await expect(page.locator('.task-guide')).toHaveCount(2);
  await page.getByText('Connect an application', { exact: true }).click();
  await expect(page.getByRole('link', { name: 'Open applications', exact: true })).toBeVisible();
  await page.getByRole('searchbox').fill('no-such-task');
  await expect(page.getByText('No matching guides.', { exact: false })).toBeVisible();
  await page.getByRole('tab', { name: 'Developer integration' }).click();
  await expect(page.getByRole('tabpanel', { name: 'Developer integration' }).getByRole('link', { name: 'Resource servers', exact: true })).toBeVisible();
  await expect(page.getByRole('tabpanel', { name: 'Developer integration' }).getByRole('link', { name: 'Open architecture builder', exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});

test('console actions stay compact and redesigned guides reflow in both themes', async ({ page }) => {
  test.setTimeout(90_000);
  const errors = await prepare(page, path => path.startsWith('overview/') ? { body: { value: 0, definition: 'Current tenant activity', collected_at: '2026-10-02T12:00:00Z' } } : undefined);
  for (const route of ['overview', 'help', 'clients']) {
    await page.goto(`${entry}#/${route}`);
    for (const dark of [false, true]) {
      await page.evaluate(value => document.documentElement.classList.toggle('dark', value), dark);
      await expect(page.locator('.content')).toHaveCSS('color', dark ? 'rgb(245, 246, 248)' : 'rgb(24, 24, 27)');
      await expect(page.locator('.topbar-tenant span.text-sm')).toHaveCSS('color', dark ? 'rgb(245, 246, 248)' : 'rgb(24, 24, 27)');
      for (const width of [320, 390, 768, 1440]) {
        await page.setViewportSize({ width, height: 900 });
        await expect(page.locator('.screen-head h2')).toBeVisible();
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
        for (const button of await page.locator('.screen-actions .console-action').all()) {
          const bounds = await button.boundingBox();
          expect(bounds?.width).toBeLessThan(220);
        }
        if (width === 390 || width === 1440) {
          expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
          if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/${route}-${width}-${dark ? 'dark' : 'light'}.png` });
        }
      }
    }
  }
  expect(errors).toEqual([]);
});


test('application lists show pagination only when another page exists', async ({ page }) => {
  let next: string | null = null;
  await prepare(page, path => path === 'clients' ? { body: { items: [], next_cursor: next } } : undefined);
  await page.goto(`${entry}#/clients`);
  await expect(page.getByText('No client matches.', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Next page', exact: true })).toHaveCount(0);
  await page.getByText('Dynamic client registration', { exact: false }).click();
  await expect(page.getByText('Initial access tokens are managed', { exact: false })).toBeVisible();
  next = 'next-page';
  await page.reload();
  await expect(page.getByRole('button', { name: 'Next page', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'Next page', exact: true }).click();
  await expect(page.getByRole('button', { name: 'First page', exact: true })).toBeEnabled();
});

test('developer guidance stays available without offering inaccessible destinations', async ({ page }) => {
  await prepare(page, path => path === 'session' ? { body: { ...session, scopes: [], deployment_scopes: [] } } : undefined);
  await page.goto(`${entry}#/help`);
  const guide = page.getByRole('tabpanel', { name: 'Developer integration' });
  await expect(guide.getByRole('heading', { name: 'From registration to your first sign-in' })).toBeVisible();
  await expect(guide.getByRole('link')).toHaveCount(0);
  await page.getByRole('tab', { name: 'Console tasks' }).click();
  await expect(page.getByText('No matching guides.', { exact: false })).toBeVisible();
});

test('groups share the directory toolbar and role assignments fit their dialog', async ({ page }) => {
  const group = { id: 'group-1', name: 'operators', display_name: 'Operators', revision: 1, created_at: '2026-09-29T12:00:00Z', updated_at: '2026-09-29T12:00:00Z' };
  const errors = await prepare(page, path => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.groups:read', 'admin.groups:write', 'admin.app_roles:read', 'admin.app_roles:write'] } };
    if (path === 'groups') return { body: { items: [group], next_cursor: null } };
    if (path === 'groups/group-1') return { body: group };
    if (path === 'groups/group-1/app-roles') return { body: { roles: [], resource_access: {} } };
    if (path === 'app-roles') return { body: { roles: [{ name: 'reader', description: 'Read reports' }] } };
    return undefined;
  });
  await page.goto(`${entry}#/groups`);
  const search = page.getByRole('searchbox', { name: 'Search groups', exact: true });
  const searchButton = page.getByRole('button', { name: 'Search groups', exact: true });
  for (const width of [390, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    // Sample both controls in one layout frame after the responsive shell settles.
    await expect.poll(() => page.locator('.directory-search').evaluate(form => {
      const input = form.querySelector('input')!.getBoundingClientRect();
      const button = form.querySelector('button')!.getBoundingClientRect();
      return Math.abs(input.y - button.y);
    })).toBeLessThan(3);
    await expect.poll(() => page.locator('.directory-search').evaluate(form => {
      const input = form.querySelector('input')!.getBoundingClientRect();
      const button = form.querySelector('button')!.getBoundingClientRect();
      return button.x - input.right;
    })).toBeGreaterThan(0);
  }
  await page.getByRole('button', { name: 'View Operators' }).click();
  await page.getByRole('button', { name: 'Assign role', exact: true }).click();
  const dialog = page.getByRole('dialog');
  for (const width of [320, 390, 640, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    expect(await dialog.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
    await expect(dialog.getByRole('button', { name: 'Assign role', exact: true })).toBeInViewport();
    await expect(dialog.getByRole('combobox', { name: 'Application', exact: true })).not.toHaveCSS('border-top-color', 'rgb(24, 24, 27)');
    if (width === 390 || width === 1440) {
      expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze()).violations).toEqual([]);
      if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/group-role-${width}.png` });
    }
  }
  expect(errors).toEqual([]);
});

test('SCIM and protocol endpoints use copyable document rows', async ({ page }) => {
  const issuer = `${origin}/t/review`;
  const errors = await prepare(page, path => {
    if (path === 'tenants/review') return { body: { issuer } };
    if (path === 'tenants/review/settings') return { body: { ...settings, limits: { max_authorization_code_lifetime_seconds: 60, max_access_token_lifetime_seconds: 3600 } } };
    if (path === 'clients') return { body: { items: [{ client_id: 'reports', client_name: 'Reports' }], next_cursor: null } };
    return undefined;
  });
  await page.route('**/.well-known/openid-configuration', route => route.fulfill({ contentType: 'application/json', body: JSON.stringify({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks` }) }));
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  for (const route of ['scim', 'settings']) {
    await page.goto(`${entry}#/${route}`);
    if (route === 'settings') await page.getByRole('tab', { name: 'Protocol endpoints', exact: true }).click();
    const copy = page.getByRole('button', { name: route === 'scim' ? 'Copy SCIM base URL' : 'Copy Discovery document', exact: true });
    await expect(copy).toBeVisible();
    await copy.click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(route === 'scim' ? `${entry}api/v1/scim/v2` : `${issuer}/.well-known/openid-configuration`);
    if (route === 'settings') await expect(page.getByRole('button', { name: 'Save settings', exact: true })).toHaveCount(0);
    for (const dark of [false, true]) {
      await page.evaluate(value => document.documentElement.classList.toggle('dark', value), dark);
      await expect(page.locator('.content')).toHaveCSS('color', dark ? 'rgb(245, 246, 248)' : 'rgb(24, 24, 27)');
      for (const width of [320, 390, 1440]) {
        await page.setViewportSize({ width, height: 900 });
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
        expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze()).violations).toEqual([]);
        if (process.env.E2E_SHOTS && width !== 320) await page.screenshot({ path: `${process.env.E2E_SHOTS}/${route}-document-${width}-${dark ? 'dark' : 'light'}.png` });
      }
    }
  }
  expect(errors).toEqual([]);
});

test('architecture toolbar does not overlap the palette and details stay within their pane', async ({ page }) => {
  const id = 'a0000000-0000-4000-8000-000000000001';
  const errors = await prepare(page, path => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.flows:write'] } };
    if (path === `flows/${id}`) return { body: { id, name: 'Architecture review', revision: 1, graph: { schema_version: 1, nodes: [], edges: [] } } };
    if (path === `flows/${id}/plan`) return { body: { flow_id: id, revision: 1, digest: 'fixture', applicable: true, steps: [] } };
    return undefined;
  });
  await page.goto(`${entry}#/architecture?flow=${id}&mode=edit`);
  const toggle = page.getByRole('button', { name: 'Show object list', exact: true });
  await expect(toggle).toBeVisible();
  for (const width of [390, 768, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    await expect.poll(() => page.evaluate(() => {
      const palette = document.querySelector('.architecture-palette')!.getBoundingClientRect();
      const view = document.querySelector('.architecture-view-switch button')!.getBoundingClientRect();
      const pane = document.querySelector('.architecture-sidepane')!;
      return (palette.right <= view.x || palette.bottom <= view.y)
        && pane.scrollWidth <= pane.clientWidth
        && document.documentElement.scrollWidth <= innerWidth;
    })).toBe(true);
    if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/architecture-toolbar-${width}.png` });
  }
  await toggle.click();
  await expect(page.getByRole('button', { name: 'Show canvas', exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});


test('account menu has clear account navigation and quiet pointer states with keyboard focus', async ({ page, context }) => {
  const errors = await prepare(page);
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin });
  await page.goto(`${entry}#/users`);
  const trigger = page.getByRole('button', { name: 'Account menu', exact: true });
  for (const dark of [false, true]) {
    await page.evaluate(value => document.documentElement.classList.toggle('dark', value), dark);
    for (const width of [320, 390, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      await trigger.click();
      const menu = page.getByRole('menu', { name: 'Account menu' });
      await expect(menu).toBeVisible();
      const account = menu.getByRole('menuitem', { name: /My account/ });
      await expect(account).toHaveAttribute('href', '/t/admin/account');
      await expect(menu).toContainText(session.username);
      await expect(menu).toContainText(session.user);
      const preferences = menu.getByRole('menuitem', { name: 'Preferences', exact: true });
      await preferences.hover();
      expect(await preferences.evaluate(element => getComputedStyle(element).outlineStyle)).toBe('none');
      expect(await preferences.evaluate(element => getComputedStyle(element).color)).toBe(await account.evaluate(element => getComputedStyle(element).color));
      expect(await menu.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
      const bounds = (await menu.boundingBox())!;
      expect(bounds.x).toBeGreaterThanOrEqual(0);
      expect(bounds.x + bounds.width).toBeLessThanOrEqual(width);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      if (width !== 320) {
        expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze()).violations).toEqual([]);
        if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/account-menu-${width}-${dark ? 'dark' : 'light'}.png` });
      }
      await page.keyboard.press('Escape');
      await expect(menu).toHaveCount(0);
      await expect(trigger).toBeFocused();
    }
  }
  await trigger.press('ArrowDown');
  const menu = page.getByRole('menu', { name: 'Account menu' });
  const account = menu.getByRole('menuitem', { name: /My account/ });
  await expect(account).toBeFocused();
  expect(await account.evaluate(element => getComputedStyle(element).outlineStyle)).toBe('solid');
  await page.keyboard.press('ArrowDown');
  const preferences = menu.getByRole('menuitem', { name: 'Preferences', exact: true });
  await expect(preferences).toBeFocused();
  await expect(preferences).toHaveCSS('outline-width', '2px');
  await menu.getByRole('menuitem', { name: /Copy account identifier/ }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(session.user);
  await trigger.click();
  await menu.getByRole('menuitem', { name: 'Preferences', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Preferences', exact: true })).toBeVisible();
  const health = page.getByRole('link', { name: 'Workspace health', exact: true });
  await health.hover();
  expect(await health.evaluate(element => getComputedStyle(element).outlineStyle)).toBe('none');
  expect(errors).toEqual([]);
});

test('conditional rollout stages locally and stale publication preserves the reviewed draft', async ({ page }) => {
  const revision = `sha256:${'a'.repeat(64)}`;
  const document = { version: 1, rules: [{ id: 'base', effect: 'permit' }], conditional_scopes: [{ id: 'guard', mode: 'report_only', clients: ['app'], actions: ['refresh_token'], rules: [{ id: 'device', effect: 'permit', when: { device_compliance: 'compliant' } }] }] };
  const writes: { revision: string | undefined; body: unknown }[] = [];
  const errors = await prepare(page, (path, route) => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.policies:read', 'admin.policies:write'] } };
    if (path === 'policies' && route.request().method() === 'PUT') {
      writes.push({ revision: route.request().headers()['if-match'], body: route.request().postDataJSON() });
      return { status: 409, body: { error: { message: 'Policy revision changed.' } } };
    }
    if (path === 'policies') return { body: { document, revision, updated_at: null } };
    return undefined;
  });
  await page.goto(`${entry}#/policy`);
  await page.getByRole('button', { name: 'Stage active enforcement', exact: true }).click();
  expect(writes).toHaveLength(0);
  await expect(page.getByLabel('The rule document, as the evaluator reads it')).toContainText('"active"');
  await page.getByRole('button', { name: 'Save policy', exact: true }).click();
  expect(writes).toHaveLength(0);
  await page.getByRole('alertdialog').getByRole('button', { name: 'Publish reviewed policy' }).click();
  await expect(page.getByRole('button', { name: 'Save policy', exact: true })).toBeDisabled();
  expect(writes).toHaveLength(1);
  expect(writes[0]!.revision).toBe(`"${revision}"`);
  expect((writes[0]!.body as typeof document).conditional_scopes[0]!.mode).toBe('active');
  await expect(page.getByLabel('The rule document, as the evaluator reads it')).toContainText('"active"');
  expect(errors).toEqual([]);
});

test('long policy editing uses a focused page and guarded return to saved rules', async ({ page }) => {
  let document: { version: number; rules: { id: string; effect: string }[] } = { version: 1, rules: [] };
  let writes = 0;
  const errors = await prepare(page, (path, route) => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.policies:read', 'admin.policies:write'] } };
    if (path === 'policies' && route.request().method() === 'PUT') {
      writes++;
      document = route.request().postDataJSON() as typeof document;
      return { body: { revision: null } };
    }
    if (path === 'policies') return { body: { document, revision: null, rule_count: document.rules.length, updated_at: null } };
    return undefined;
  });
  await page.goto(`${entry}#/policy`);
  await page.getByRole('button', { name: 'Edit policy' }).click();
  await expect(page.getByRole('heading', { name: 'Edit access policy' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Try a request' })).toHaveCount(0);
  await page.setViewportSize({ width: 390, height: 800 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
  if (process.env.E2E_SHOTS) {
    await page.getByRole('heading', { name: 'Edit access policy' }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: `${process.env.E2E_SHOTS}/policy-editor-mobile.png` });
  }
  const editor = page.getByLabel('The rule document, as the evaluator reads it');
  await editor.fill('{"version":1,"rules":[{"id":"draft","effect":"deny"}]}');
  await page.getByRole('button', { name: 'Back to access policy' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Keep editing' }).click();
  await expect(editor).toContainText('draft');
  await page.getByRole('button', { name: 'Cancel editing' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Discard changes' }).click();
  await expect(page.getByRole('heading', { name: 'Access policy', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Try a request' })).toBeVisible();
  expect(writes).toBe(0);
  await page.getByRole('button', { name: 'Edit policy' }).click();
  await page.getByLabel('The rule document, as the evaluator reads it').fill('{"version":1,"rules":[{"id":"saved","effect":"deny"}]}');
  await page.getByRole('button', { name: 'Save policy' }).click();
  await expect(page.getByRole('heading', { name: 'Access policy', exact: true })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'saved' })).toBeVisible();
  expect(writes).toBe(1);
  expect(errors).toEqual([]);
});

test('conditional simulation labels hypothetical evidence and missing report-only facts accessibly', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  let requested: Record<string, unknown> | null = null;
  const errors = await prepare(page, (path, route) => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.policies:read'] } };
    if (path === 'policies') return { body: { document: { version: 1, rules: [] }, revision: null, updated_at: null } };
    if (path === 'clients') return { body: { items: [{ client_id: 'app', client_name: 'App' }], next_cursor: null } };
    if (path === 'policies/simulate') {
      requested = route.request().postDataJSON() as Record<string, unknown>;
      return { body: { decision: false, simulation: { enforced: false, current_policy_revision: null, provenance: { policy: 'stored', context_properties: 'hypothetical' }, conditional: { enforcement_action: 'refresh_token', legacy_would_permit: false, active_would_permit: false, facts: [{ name: 'device_compliance', availability: 'stale', source: 'hypothetical_operator_example', hypothetical: true }], scopes: [{ id: 'guard', mode: 'report_only', would_decision: false, required_facts: ['device_compliance'], missing_required_evidence: true, assurance_remedy: null }] } } } };
    }
    return undefined;
  });
  await page.goto(`${entry}#/policy`);
  await page.getByLabel('Tenant user', { exact: true }).selectOption('alex');
  await page.getByLabel('Application', { exact: true }).selectOption('app');
  await page.getByLabel('Registered resource', { exact: true }).selectOption('https://api.example.test');
  await page.getByLabel('Enforcement boundary', { exact: true }).selectOption('refresh_token');
  await page.getByLabel('Supply hypothetical evidence examples').check();
  await page.getByLabel('Device compliance availability').selectOption('stale');
  await page.getByRole('button', { name: 'Simulate', exact: true }).click();
  await expect(page.getByText('Hypothetical example', { exact: true })).toBeVisible();
  await expect(page.getByText('Required evidence is missing, stale, invalid or unavailable.')).toBeVisible();
  expect(requested).toMatchObject({ action: 'read', enforcement_action: 'refresh_token', hypothetical_trusted_context: { device_compliance: { availability: 'stale' } } });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  const sourceTable = page.locator('[data-slot="table-container"]').filter({ hasText: 'Evidence source' });
  await sourceTable.focus();
  await page.keyboard.press('ArrowRight');
  await expect.poll(() => sourceTable.evaluate(element => element.scrollLeft)).toBeGreaterThan(0);
  const audit = await new AxeBuilder({ page }).analyze();
  expect(audit.violations.filter(v => v.impact === 'critical' || v.impact === 'serious')).toEqual([]);
  expect(errors).toEqual([]);
});

test('conditional access read-only preview exposes no activation controls', async ({ page }) => {
  let writes = 0;
  const errors = await prepare(page, (path, route) => {
    if (route.request().method() !== 'GET') writes++;
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes.filter(scope => !scope.endsWith(':write')), 'admin.policies:read'] } };
    if (path === 'policies') return { body: { document: { version: 1, rules: [], conditional_scopes: [{ id: 'guard', mode: 'report_only', clients: ['app'], actions: ['refresh_token'], rules: [] }] }, revision: `sha256:${'a'.repeat(64)}`, updated_at: null } };
    return undefined;
  });
  await page.goto(`${entry}#/policy`);
  await expect(page.getByRole('heading', { name: 'Conditional access rollout' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Stage active enforcement', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Edit policy', exact: true })).toHaveCount(0);
  await expect(page.getByText('Read only', { exact: true })).toBeVisible();
  expect(writes).toBe(0);
  expect(errors).toEqual([]);
});
