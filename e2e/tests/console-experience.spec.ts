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
  page.on('console', message => {
    if (message.text().startsWith('Console CSP violation:')) errors.push(message.text());
  });
  await page.addInitScript(() => document.addEventListener('securitypolicyviolation', event => {
    console.error(`Console CSP violation: ${event.violatedDirective} ${event.blockedURI}`);
  }));
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
      await route.fulfill({ contentType: 'text/html; charset=utf-8', headers: { 'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${nonce}' 'strict-dynamic'; style-src 'nonce-${nonce}'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'` },
        body: `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Console</title><link rel="stylesheet" nonce="${nonce}" href="${manifest['style.css'].file}"></head><body><div id="console"></div><script id="console-entry" nonce="${nonce}" type="module" src="${manifest['src/main.tsx'].file}"></script></body></html>` });
    } else if (url.pathname.includes('/assets/')) {
      const filename = url.pathname.split('/assets/')[1]!;
      await route.fulfill({ body: readFileSync(`${dist}/assets/${filename}`), contentType: filename.endsWith('.js') ? 'application/javascript; charset=utf-8' : filename.endsWith('.css') ? 'text/css; charset=utf-8' : filename.endsWith('.svg') ? 'image/svg+xml' : 'font/woff2' });
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
  await page.getByRole('dialog', { name: 'Add a cluster profile' }).getByRole('button', { name: 'Cancel' }).click();
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
    await expect(page.locator('.content')).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      const save = page.getByRole('button', { name: 'Validate and register' });
      await expect(save).toBeEnabled();
      await save.scrollIntoViewIfNeeded();
      await expect(save).toBeInViewport();
      await page.getByRole('heading', { name: 'Register authorization details type', exact: true }).scrollIntoViewIfNeeded();
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
  expect((await page.locator('.token-console-page').boundingBox())!.width).toBeLessThanOrEqual(1480);
  await expect(page.locator('.app-topbar').getByRole('link', { name: 'Token test console', exact: true })).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Console sections' }).getByRole('link', { name: 'Token test console', exact: true })).toHaveCount(0);
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
  for (const width of [390, 1440]) for (const dark of [false, true]) {
    await page.setViewportSize({ width, height: 1000 });
    await page.evaluate(value => document.documentElement.classList.toggle('dark', value), dark);
    await page.mouse.move(0, 0);
    await expect(page.getByRole('button', { name: 'Clear', exact: true })).toHaveCSS('color', dark ? 'rgb(163, 163, 163)' : 'rgb(102, 112, 133)');
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
    if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/token-workspace-${width}-${dark}.png`, fullPage: true });
  }
  await page.getByRole('button', { name: 'Clear', exact: true }).click();
  await expect(page.getByText('No token to inspect', { exact: true })).toBeVisible();
  await page.getByRole('textbox', { name: 'Encoded token' }).fill('invalid.jwt');
  await expect(page.getByRole('textbox', { name: 'Encoded token' })).toHaveAttribute('aria-invalid', 'true');
  await expect(page.getByText(/This JWT could not be decoded/)).toBeVisible();
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

test('provider editing has its own page and failed deletion retains its confirmation', async ({ page }) => {
  let deletes = 0;
  const errors = await prepare(page, (path, route) => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.oidc_providers:read', 'admin.oidc_providers:write'] } };
    if (path === 'oidc/providers' && route.request().method() === 'DELETE') {
      deletes++;
      return { status: 409, body: { error: { message: 'This provider still has linked identities.' } } };
    }
    if (path === 'oidc/providers') return { body: { callback_url_template: 'https://idp.example.test/callback/{id}', providers: [{ id: 'external', name: 'External provider', issuer: 'https://issuer.example.test', client_id: 'console', enabled: true, secret_configured: true, callback_url: 'https://idp.example.test/callback/external' }] } };
    if (path === 'oidc/providers/check') return { body: { checked_at: 1700000000, checks: [] } };
    return undefined;
  });
  await page.goto(`${entry}#/oidc-providers`);
  await page.getByRole('button', { name: 'Edit', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Edit sign-in provider' })).toBeVisible();
  await expect(page.getByRole('table', { name: 'External sign-in providers' })).toHaveCount(0);
  if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/provider-editor.png` });
  await page.setViewportSize({ width: 390, height: 800 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
  if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/provider-editor-mobile.png` });
  await page.getByLabel('Display name').fill('');
  await page.getByLabel('Display name').pressSequentially('Changed provider');
  await expect(page.getByLabel('Display name')).toBeFocused();
  await page.getByRole('button', { name: 'Back to sign-in providers' }).click();
  await page.getByRole('button', { name: 'Keep editing' }).click();
  await expect(page.getByLabel('Display name')).toHaveValue('Changed provider');
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await page.getByRole('button', { name: 'Discard changes', exact: true }).click();
  await page.getByRole('button', { name: 'Delete', exact: true }).click();
  const dialog = page.getByRole('alertdialog');
  await dialog.getByRole('button', { name: 'Delete provider' }).click();
  await expect(dialog.getByRole('alert')).toContainText('This provider still has linked identities.');
  expect(deletes).toBe(1);
  expect(errors).toEqual([]);
});

test('branding editor can return to its saved read view with clean or discarded changes', async ({ page }) => {
  const theme = { palette: { background: '#ffffff', text: '#18181b', muted_text: '#626975', accent: '#4054e8', accent_text: '#ffffff', danger: '#b42318' }, font: 'geist', radius_px: 8, spacing_px: 8, product_name: 'Review identity' };
  const errors = await prepare(page, path => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.theme:read', 'admin.theme:write'] } };
    if (path === 'theme') return { body: { theme, schema: {} } };
    return undefined;
  });
  await page.goto(`${entry}#/branding`);
  await expect(page.getByRole('heading', { name: 'Branding', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Edit branding' }).click();
  await page.getByRole('button', { name: 'Back to branding' }).click();
  await expect(page.getByRole('heading', { name: 'Branding', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Edit branding' }).click();
  await page.getByLabel('Product name').fill('Unsaved identity');
  await page.getByRole('button', { name: 'Cancel editing' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Keep editing' }).click();
  await expect(page.getByLabel('Product name')).toHaveValue('Unsaved identity');
  await page.getByRole('button', { name: 'Cancel editing' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Discard changes' }).click();
  await expect(page.getByRole('heading', { name: 'Branding', exact: true })).toBeVisible();
  await expect(page.getByText('Review identity', { exact: true })).toBeVisible();
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
      await expect(page.locator('.content')).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
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
  await expect(summary.locator('dl')).not.toContainText('2026-09-29');
  await expect(summary.getByRole('list', { name: 'Recent sign-in activity' })).toContainText('2026-09-29');
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
  await expect(page.getByRole('heading', { name: 'Members', exact: true })).toBeVisible();
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
    await expect(page.locator('.content')).toHaveCSS('color', 'rgb(250, 250, 250)');
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
      await expect(page.locator('.content')).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
      await expect(page.locator('.topbar-tenant span.text-sm')).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
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
    await expect(dialog.getByRole('combobox', { name: 'Application', exact: true })).not.toHaveCSS('border-top-color', 'rgb(16, 24, 40)');
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
      await expect(page.locator('.content')).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
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
        // Base UI guards redirect focus immediately; they never retain it.
        // https://github.com/mui/base-ui/issues/4668#issuecomment-4306200868
        expect((await new AxeBuilder({ page }).exclude('[data-base-ui-focus-guard]').withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze()).violations).toEqual([]);
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
  await page.keyboard.press('Shift+Tab');
  await expect(menu).toHaveCount(0);
  await expect(trigger).toBeFocused();
  await trigger.press('ArrowDown');
  await expect(account).toBeFocused();
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
  await page.getByRole('button', { name: 'Simulate', exact: true }).click();
  expect(requested).toBeNull();
  await expect(page.getByRole('combobox', { name: 'Tenant user', exact: true })).toBeFocused();
  await page.getByRole('combobox', { name: 'Tenant user', exact: true }).click();
  await page.getByRole('option', { name: 'alex@example.test', exact: true }).click();
  await page.getByRole('combobox', { name: 'Application', exact: true }).click();
  await page.getByRole('option', { name: 'App', exact: true }).click();
  await page.getByRole('combobox', { name: 'Registered resource', exact: true }).click();
  await page.getByRole('option', { name: 'https://api.example.test', exact: true }).click();
  await page.getByRole('combobox', { name: 'Enforcement boundary', exact: true }).click();
  await page.getByRole('option', { name: 'refresh_token', exact: true }).click();
  await page.getByLabel('Supply hypothetical evidence examples').check();
  await page.getByRole('combobox', { name: 'Device compliance availability', exact: true }).click();
  await page.getByRole('option', { name: 'Known example', exact: true }).click();
  await page.getByRole('button', { name: 'Simulate', exact: true }).click();
  expect(requested).toBeNull();
  await expect(page.getByRole('combobox', { name: 'Device compliance example value', exact: true })).toBeFocused();
  await page.getByRole('combobox', { name: 'Device compliance example value', exact: true }).click();
  await page.getByRole('option', { name: 'compliant', exact: true }).click();
  await page.getByRole('combobox', { name: 'Device compliance availability', exact: true }).click();
  await page.getByRole('option', { name: 'Stale', exact: true }).click();
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


test('redesign uses self-hosted Inter and Base tabs preserve unsaved fields', async ({ page }) => {
  const violations: string[] = [];
  const fontRequests: string[] = [];
  const errors = await prepare(page);
  page.on('request', request => {
    if (request.resourceType() === 'font') fontRequests.push(request.url());
  });
  await page.addInitScript(() => {
    (window as unknown as { cspViolations: string[] }).cspViolations = [];
    document.addEventListener('securitypolicyviolation', event => {
      (window as unknown as { cspViolations: string[] }).cspViolations.push(event.violatedDirective);
    });
  });
  await page.goto(`${entry}#/clients?mode=new&guided=1`);
  await page.getByLabel('Client name', { exact: true }).fill('Unsaved identity application');
  await page.evaluate(() => document.fonts.ready);
  expect(await page.evaluate(() => getComputedStyle(document.body).fontFamily)).toContain('Inter Variable');
  expect(await page.evaluate(() => Array.from(document.fonts).some(font => font.family === 'Inter Variable' && font.status === 'loaded'))).toBe(true);
  expect(fontRequests.length).toBeGreaterThan(0);
  expect(fontRequests.every(url => url.startsWith(`${origin}/t/review/admin/assets/inter-`))).toBe(true);
  const general = page.getByRole('tab', { name: 'General', exact: true });
  const callbacks = page.getByRole('tab', { name: 'Callbacks', exact: true });
  await general.focus();
  await page.keyboard.press('ArrowRight');
  await expect(callbacks).toBeFocused();
  await expect(general).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('Enter');
  await expect(callbacks).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByLabel('Client name', { exact: true })).toBeHidden();
  await general.click();
  await expect(general).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByLabel('Client name', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Client name', { exact: true })).toHaveValue('Unsaved identity application');
  await page.screenshot({ path: test.info().outputPath('redesign-light.png'), fullPage: true });
  await page.evaluate(() => document.documentElement.classList.add('dark'));
  await page.screenshot({ path: test.info().outputPath('redesign-dark.png'), fullPage: true });
  violations.push(...await page.evaluate(() => (window as unknown as { cspViolations: string[] }).cspViolations));
  expect(violations).toEqual([]);
  expect(errors).toEqual([]);
});

test('Base navigation tooltips preserve links and mobile sheet restores keyboard focus under CSP', async ({ page }) => {
  const errors = await prepare(page);
  await page.goto(`${entry}#/users`);
  await page.getByRole('navigation', { name: 'Sidebar display' }).getByRole('button', { name: 'Toggle Sidebar' }).click();
  const overview = page.getByRole('navigation', { name: 'Console sections' }).getByRole('link', { name: 'Overview', exact: true });
  await overview.hover();
  await expect(page.locator('[data-slot=tooltip-content]')).toHaveText('Overview');
  await expect(overview).toHaveAttribute('href', '#/overview');
  if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/collapsed-navigation-tooltip.png` });
  await page.keyboard.press('Escape');
  await expect(page.locator('[data-slot=tooltip-content]')).toHaveCount(0);
  await page.setViewportSize({ width: 390, height: 800 });
  const toggle = page.getByRole('button', { name: 'Toggle Sidebar', exact: true });
  await toggle.click();
  const sheet = page.getByRole('dialog', { name: 'Sidebar', exact: true });
  await expect(sheet).toBeVisible();
  await expect(sheet.getByRole('link', { name: 'Users', exact: true })).toBeVisible();
  if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/mobile-navigation-sheet.png` });
  await page.keyboard.press('Escape');
  await expect(sheet).toHaveCount(0);
  await expect(toggle).toBeFocused();
  await toggle.press('Enter');
  await sheet.getByRole('link', { name: 'Applications', exact: true }).click();
  await expect(sheet).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Applications', exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(errors).toEqual([]);
});

test('compact settings retain draft switches and unit inputs through a rejected save', async ({ page }) => {
  const fixture = { ...settings, allow_non_fapi_clients: false, always_ask_consent: false,
    limits: { max_authorization_code_lifetime_seconds: 60, max_access_token_lifetime_seconds: 3600 } };
  const errors = await prepare(page, path => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.tenants:read'] } };
    if (path === 'tenants/review/settings') return { body: fixture };
    return undefined;
  });
  let finish: (() => void) | undefined;
  let payload: Record<string, unknown> | undefined;
  await page.route(`${entry}api/v1/tenants/review/settings`, async route => {
    if (route.request().method() !== 'PUT') { await route.fallback(); return; }
    payload = route.request().postDataJSON();
    await new Promise<void>(resolve => { finish = resolve; });
    await route.fulfill({ status: 400, contentType: 'application/json', body: JSON.stringify({ error: { message: 'Authorization code lifetime exceeds the maximum of 60 seconds.' } }) });
  });
  await page.goto(`${entry}#/settings`);
  const exception = page.getByRole('switch', { name: 'Allow non-FAPI application exceptions', exact: true });
  await exception.focus();
  await exception.press('Space');
  await expect(exception).toBeChecked();
  for (const dark of [false, true]) {
    await page.evaluate(value => document.documentElement.classList.toggle('dark', value), dark);
    for (const width of [390, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      await expect(page.locator('.content')).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
      await expect(page.locator('.screen h2')).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
      await expect(page.locator('[data-slot=field-label]').first()).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
      expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
      if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/compact-capabilities-${width}-${dark ? 'dark' : 'light'}.png` });
    }
  }
  await page.getByRole('tab', { name: 'Token lifetimes', exact: true }).click();
  const code = page.getByRole('spinbutton', { name: 'Authorization code lifetime (seconds)', exact: true });
  await code.fill('999');
  for (const width of [390, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    const height = await code.evaluate(element => element.closest('[data-slot=input-group]')!.getBoundingClientRect().height);
    expect(height).toBe(width === 390 ? 44 : 36);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/compact-lifetimes-${width}.png` });
  }
  await page.getByRole('button', { name: 'Save settings', exact: true }).click();
  await expect.poll(() => payload?.authorization_code_lifetime_seconds).toBe(999);
  expect(payload?.allow_non_fapi_clients).toBe(true);
  await expect(code).toBeDisabled();
  await page.getByRole('tab', { name: 'Capabilities', exact: true }).click();
  await expect(exception).toBeDisabled();
  finish!();
  await expect(exception).toBeEnabled();
  await expect(exception).toBeChecked();
  await page.getByRole('tab', { name: 'Token lifetimes', exact: true }).click();
  await expect(code).toHaveValue('999');
  await expect(code).toHaveAttribute('aria-invalid', 'true');
  expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze()).violations).toEqual([]);
  await expect(page.getByRole('alert').filter({ hasText: 'Authorization code lifetime exceeds' })).toBeVisible();
  expect(errors).toEqual([]);
});

test('tenant settings share the page width and assurance remains editable at every width', async ({ page }) => {
  const errors = await prepare(page, path => path === 'session' ? { body: { ...session, scopes: [...session.scopes, 'admin.tenants:read'] } } : path === 'tenants/review/settings' ? { body: {
    ...settings, limits: { max_authorization_code_lifetime_seconds: 60, max_access_token_lifetime_seconds: 3600 }, acr_policy: { amr_in_id_token: false, levels: [
      { value: 'password', amr: ['pwd'] }, { value: 'verified', amr: ['swk', 'user'] },
    ] },
  } } : undefined);
  await page.goto(`${entry}#/settings`);
  for (const width of [390, 768, 1440, 1920]) {
    await page.setViewportSize({ width, height: 1100 });
    const screen = await page.locator('.content > .screen').boundingBox();
    const content = await page.locator('.content').evaluate(element => ({ width: element.clientWidth, padding: parseFloat(getComputedStyle(element).paddingLeft) + parseFloat(getComputedStyle(element).paddingRight) }));
    expect(screen!.width).toBeCloseTo(Math.min(1480, content.width - content.padding), 0);
    for (const tab of ['Capabilities', 'Token lifetimes', 'Authentication']) {
      await page.getByRole('tab', { name: tab, exact: true }).click();
      const configuration = await page.locator('.tenant-configuration').boundingBox();
      const section = await page.getByRole('tabpanel', { name: tab, exact: true }).locator('.settings-section').boundingBox();
      expect(section!.width).toBeGreaterThan(configuration!.width - 2);
      if (tab === 'Authentication') {
        const editor = page.locator('.assurance-editor');
        await expect(editor.getByLabel('Assurance level 1 ACR value', { exact: true })).toHaveValue('password');
        await expect(editor.locator('.assurance-method-grid').first().getByRole('checkbox')).toHaveCount(4);
        for (const dark of [false, true]) {
          await page.evaluate(value => document.documentElement.classList.toggle('dark', value), dark);
          await expect(page.locator('.content')).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
          expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
          await page.screenshot({ path: `/tmp/ast-vum8-authentication-${width}-${dark ? 'dark' : 'light'}.png`, fullPage: true });
        }
      }
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    }
  }
  await page.getByRole('button', { name: 'Enable authenticator codes', exact: true }).click();
  await expect(page.locator('.authenticator-policy')).toContainText('Enabled in this configuration. Save changes to apply.');
  await expect(page.getByLabel('Assurance level 2 ACR value', { exact: true })).toHaveValue('urn:asterius:acr:pwd-otp');
  const release = page.getByRole('switch', { name: 'Include authentication methods in ID tokens', exact: true });
  await release.focus(); await page.keyboard.press('Space'); await expect(release).toBeChecked();
  await page.getByRole('button', { name: 'Reorder assurance level 1: Password', exact: true }).focus();
  await page.keyboard.press('ArrowDown');
  await expect(page.getByLabel('Assurance level 2 ACR value', { exact: true })).toHaveValue('password');
  await page.getByRole('tab', { name: 'Capabilities', exact: true }).click();
  await page.getByRole('tab', { name: 'Authentication', exact: true }).click();
  await expect(release).toBeChecked();
  expect(errors).toEqual([]);
});

test('member identity picker selects stable IDs and retains a rejected choice', async ({ page }) => {
  const group = { id: 'group-1', name: 'operators', display_name: 'Operators', revision: 1, created_at: '2026-09-29T12:00:00Z', updated_at: '2026-09-29T12:00:00Z' };
  const people = [{ ...user, user_id: 'alex-1', username: 'Alex', email: 'first@example.test' }, { ...user, user_id: 'alex-2', username: 'Alex', email: 'second@example.test' }];
  let mutations = 0;
  const errors = await prepare(page, (path, route) => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.groups:read', 'admin.memberships:read', 'admin.memberships:write'] } };
    if (path === 'groups') return { body: { items: [group], next_cursor: null } };
    if (path === 'groups/group-1') return { body: group };
    if (path === 'groups/group-1/members') return { body: { items: [], next_cursor: null } };
    if (path === 'users') return { body: { items: people, next_cursor: null } };
    if (path === 'groups/group-1/members/alex-2') {
      expect(route.request().method()).toBe('PUT'); mutations++;
      return { status: 403, body: { error: { message: 'Membership refused for this test.' } } };
    }
    return undefined;
  });
  await page.goto(`${entry}#/groups`);
  await page.getByRole('button', { name: 'View Operators' }).click();
  await page.getByRole('button', { name: 'Add member', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Add member', exact: true });
  const input = dialog.getByRole('combobox', { name: 'Find a user', exact: true });
  // Base's open combobox limits the accessibility tree to the input and results.
  const add = dialog.getByRole('button', { name: 'Add member', exact: true, includeHidden: true });
  await expect(add).toBeDisabled();
  await input.fill('Alex');
  await expect(page.getByRole('option', { name: /second@example.test/ })).toBeVisible();
  await expect(add).toBeDisabled();
  await input.press('ArrowDown'); await input.press('ArrowDown'); await input.press('Enter');
  await expect(dialog).toContainText('Selected: Alex (alex-2)');
  expect(mutations).toBe(0);
  await add.click();
  await expect(dialog).toContainText('Membership refused for this test.');
  await expect(dialog).toContainText('Selected: Alex (alex-2)');
  await input.fill('Someone else'); await expect(add).toBeDisabled();
  await expect(dialog.getByText('Selected: Alex (alex-2)')).toHaveCount(0);
  expect(mutations).toBe(1);
  await expect(page.getByRole('option', { name: /second@example.test/ })).toBeVisible();
  await input.press('Escape');
  await expect(input).toBeFocused();
  await expect(input).toHaveAttribute('aria-expanded', 'false');
  for (const width of [390, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    for (const dark of [false, true]) {
      await page.evaluate(value => document.documentElement.classList.toggle('dark', value), dark);
      await expect(page.locator('[data-slot=sidebar-inset]')).toHaveCSS('background-color', dark ? 'rgb(20, 20, 20)' : 'rgb(255, 255, 255)');
      await expect(page.locator('.screen h2')).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
      await expect(dialog.locator('[data-slot=dialog-title]')).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
      expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
      if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/member-picker-${width}-${dark ? 'dark' : 'light'}.png` });
    }
  }
  expect(errors).toEqual([]);
});

test('identity search discards late results and loads cursor pages explicitly', async ({ page }) => {
  const group = { id: 'group-1', name: 'operators', display_name: 'Operators', revision: 1 };
  const errors = await prepare(page, path => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.groups:read', 'admin.memberships:read', 'admin.memberships:write'] } };
    if (path === 'groups') return { body: { items: [group], next_cursor: null } };
    if (path === 'groups/group-1') return { body: group };
    return undefined;
  });
  let refusals = 0;
  let finishOld: (() => Promise<void>) | undefined;
  await page.route(`${entry}api/v1/users?**`, async route => {
    const url = new URL(route.request().url());
    if (url.searchParams.get('q') === 'refused' && refusals++ === 0) {
      await route.fulfill({ status: 503, json: { error: { message: 'Directory unavailable for this test.' } } });
    } else if (url.searchParams.get('q') === 'old') {
      await new Promise<void>(resolve => { finishOld = async () => { await route.fulfill({ json: { items: [{ ...user, user_id: 'old', username: 'Old result' }], next_cursor: null } }); resolve(); }; });
    } else await route.fulfill({ json: { items: [{ ...user, user_id: url.searchParams.has('cursor') ? 'next' : 'new', username: url.searchParams.has('cursor') ? 'Next result' : 'New result' }], next_cursor: url.searchParams.has('cursor') ? null : 'page-2' } });
  });
  await page.goto(`${entry}#/groups`); await page.getByRole('button', { name: 'View Operators' }).click();
  await page.getByRole('button', { name: 'Add member', exact: true }).click();
  const input = page.getByRole('combobox', { name: 'Find a user', exact: true });
  await input.fill('old'); await expect.poll(() => Boolean(finishOld)).toBe(true);
  await input.fill('new'); await expect(page.getByRole('option', { name: /New result/ })).toBeVisible();
  await finishOld!(); await expect(page.getByRole('option', { name: /Old result/ })).toHaveCount(0);
  await page.getByRole('button', { name: 'Load more matches' }).click();
  await expect(page.getByRole('option', { name: /Next result/ })).toBeVisible();
  await expect(page.getByRole('option', { name: /New result/ })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Load more matches' })).toHaveCount(0);
  await input.fill('refused');
  await expect(page.getByText('Directory unavailable for this test.', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Retry search' }).click();
  await expect(page.getByRole('option', { name: /New result/ })).toBeVisible();
  for (const width of [390, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  }
  expect(errors).toEqual([]);
});

test('audit chips reflect applied filters and removal preserves other drafts', async ({ page }) => {
  const queries: string[] = [];
  const errors = await prepare(page, (path, route) => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.audit:read'] } };
    if (path === 'audit/events') { queries.push(new URL(route.request().url()).search); return { body: { items: [], next_cursor: null } }; }
    return undefined;
  });
  await page.goto(`${entry}#/audit`);
  await page.getByLabel('Event type', { exact: true }).fill('session.revoked');
  await expect(page.getByText('Filters have unapplied changes.', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Remove Event type filter' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Add filter', exact: true }).click();
  await page.getByRole('button', { name: 'Grant ID', exact: true }).click();
  await page.getByLabel('Grant ID', { exact: true }).fill('grant-1');
  await page.getByRole('button', { name: 'Apply filters' }).click();
  await expect.poll(() => queries.at(-1)).toContain('grant=grant-1');
  await expect(page.getByRole('button', { name: 'Edit Event type filter' })).toContainText('session.revoked');
  await page.getByLabel('User', { exact: true }).fill('unapplied-person');
  await page.getByRole('button', { name: 'Remove Grant ID filter' }).click();
  await expect.poll(() => queries.at(-1)).toBe('?type=session.revoked');
  await expect(page.getByLabel('User', { exact: true })).toHaveValue('unapplied-person');
  await expect(page.getByRole('link', { name: 'Export as NDJSON' })).toHaveAttribute('href', 'api/v1/audit/events/export?type=session.revoked');
  for (const width of [390, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
    if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/audit-filters-${width}.png` });
  }
  await page.getByRole('button', { name: 'Clear', exact: true }).click();
  await expect.poll(() => queries.at(-1)).toBe('');
  await expect(page.getByRole('button', { name: /Remove .* filter/ })).toHaveCount(0);
  expect(errors).toEqual([]);
});

test('guided progress uses one tablist and preserves the application draft', async ({ page }) => {
  const errors = await prepare(page);
  await page.goto(`${entry}#/clients?mode=new&guided=1`);
  const tabs = page.getByRole('tablist', { name: 'Application sections' });
  await expect(tabs).toHaveCount(1);
  await expect(tabs.locator('.workflow-step-number')).toHaveCount(6);
  await expect(page.getByText('Step 1 of 6.', { exact: false })).toBeVisible();
  const name = page.getByLabel('Client name', { exact: true });
  await name.fill('Operations dashboard');
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  await expect(page.getByText('Step 2 of 6.', { exact: false })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Callbacks', exact: true })).toHaveAttribute('aria-selected', 'true');
  await page.getByRole('tab', { name: 'General', exact: true }).click();
  await expect(name).toHaveValue('Operations dashboard');
  await page.setViewportSize({ width: 390, height: 900 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await expect(page.getByRole('tab', { name: 'Review', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Switch to full editor' }).click();
  await expect(name).toHaveValue('Operations dashboard');
  await expect(page.locator('.workflow-step-number')).toHaveCount(0);
  expect(errors).toEqual([]);
});

test('audit filter changes ignore a late response for the previous query', async ({ page }) => {
  const errors = await prepare(page, path => path === 'session' ? { body: { ...session, scopes: [...session.scopes, 'admin.audit:read'] } } : undefined);
  let finishOld: (() => Promise<void>) | undefined;
  await page.route(`${entry}api/v1/audit/events**`, async route => {
    const type = new URL(route.request().url()).searchParams.get('type');
    const reply = (value: string) => ({ items: [{ id: value === 'older.event' ? 1 : 2, hash: 'fixture', type: value, occurred_at: '2026-10-06T00:00:00Z', outcome: 'success' }], next_cursor: null });
    if (type === 'older.event') await new Promise<void>(resolve => { finishOld = async () => { await route.fulfill({ json: reply('older.event') }); resolve(); }; });
    else await route.fulfill({ json: reply(type ?? 'initial.event') });
  });
  await page.goto(`${entry}#/audit`);
  await page.getByLabel('Event type', { exact: true }).fill('older.event');
  await page.getByRole('button', { name: 'Apply filters' }).click();
  await expect.poll(() => Boolean(finishOld)).toBe(true);
  await page.getByLabel('Event type', { exact: true }).fill('current.event');
  await page.getByRole('button', { name: 'Apply filters' }).click();
  await expect(page.getByRole('table')).toContainText('current.event');
  await finishOld!();
  await expect(page.getByRole('table')).not.toContainText('older.event');
  await expect(page.getByRole('table')).toContainText('current.event');
  expect(errors).toEqual([]);
});

test('directory column choices survive cursor pages without changing server queries', async ({ page }) => {
  const reads: string[] = [];
  const errors = await prepare(page, (path, route) => {
    if (path.split('?')[0] === 'users') {
      reads.push(new URL(route.request().url()).search);
      return { body: { items: [{ ...user, username: new URL(route.request().url()).searchParams.has('cursor') ? 'next@example.test' : user.username, claims: 0 }], next_cursor: new URL(route.request().url()).searchParams.has('cursor') ? null : 'page-2' } };
    }
    return undefined;
  });
  await page.goto(`${entry}#/users`);
  const columns = page.getByRole('button', { name: /^Columns/ });
  await columns.click();
  const picker = page.getByRole('dialog', { name: 'Visible columns' });
  await expect(picker.getByRole('checkbox', { name: /Username/ })).toBeDisabled();
  await expect(picker.getByRole('checkbox', { name: /Status/ })).toBeDisabled();
  await picker.getByRole('checkbox', { name: 'Claims', exact: true }).uncheck();
  await page.keyboard.press('Escape');
  await expect(columns).toBeFocused();
  await expect(page.getByRole('columnheader', { name: 'Claims', exact: true })).toHaveCount(0);
  expect(reads).toEqual(['']);
  await page.getByRole('button', { name: 'Next page', exact: true }).click();
  await expect(page.getByRole('button', { name: 'next@example.test', exact: true })).toBeVisible();
  await expect(page.getByRole('columnheader', { name: 'Claims', exact: true })).toHaveCount(0);
  expect(reads).toEqual(['', '?cursor=page-2']);
  await columns.click();
  for (const width of [390, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    for (const dark of [false, true]) {
      await page.evaluate(value => document.documentElement.classList.toggle('dark', value), dark);
      await expect(page.locator('[data-slot=sidebar-inset]')).toHaveCSS('background-color', dark ? 'rgb(20, 20, 20)' : 'rgb(255, 255, 255)');
      await expect(page.locator('.screen h2')).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
      expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
      if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/columns-${width}-${dark}.png` });
    }
  }
  await picker.getByRole('button', { name: 'Reset columns' }).click();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('columnheader', { name: 'Claims', exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});

test('role descriptions preserve empty workspace values and refused assignments', async ({ page }) => {
  const writes: unknown[] = [];
  const group = { id: 'group-1', name: 'operators', display_name: 'Operators', revision: 1 };
  const errors = await prepare(page, (path, route) => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.groups:read', 'admin.app_roles:read', 'admin.app_roles:write'] } };
    if (path === 'groups') return { body: { items: [group], next_cursor: null } };
    if (path === 'groups/group-1') return { body: group };
    if (path === 'groups/group-1/app-roles') {
      if (route.request().method() === 'POST') { writes.push(route.request().postDataJSON()); return { status: 409, body: { error: { message: 'Assignment refused.' } } }; }
      return { body: { roles: [], resource_access: {} } };
    }
    if (path === 'app-roles') return { body: { roles: [{ name: 'reader', description: 'Read published reports' }] } };
    if (path === 'clients') return { body: { items: [{ client_id: 'reports' }], next_cursor: null } };
    if (path === 'clients/reports/app-roles') return { body: { roles: [{ name: 'editor', description: 'Edit report drafts' }] } };
    return undefined;
  });
  await page.goto(`${entry}#/groups`);
  await page.getByRole('button', { name: 'View Operators' }).click();
  await page.getByRole('button', { name: 'Assign role', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Assign application role' });
  const application = dialog.getByRole('combobox', { name: 'Application', exact: true });
  await application.click(); await page.getByRole('option', { name: 'reports', exact: true }).click();
  const role = dialog.getByRole('combobox', { name: 'Role', exact: true });
  await expect(role).toBeEnabled(); await role.click();
  await expect(page.getByRole('option', { name: /editor/ })).toContainText('Edit report drafts');
  await page.getByRole('option', { name: /editor/ }).click();
  await application.click(); await page.getByRole('option', { name: /Workspace/ }).click();
  await expect(role).toBeEnabled(); await role.click();
  await expect(page.getByRole('option', { name: /reader/ })).toContainText('Read published reports');
  await expect(page.getByRole('option', { name: /editor/ })).toHaveCount(0);
  await page.getByRole('option', { name: /reader/ }).click();
  await expect(role).toHaveText('reader');
  expect(writes).toEqual([]);
  await dialog.getByRole('button', { name: 'Assign role', exact: true }).click();
  await expect(dialog).toContainText('Assignment refused.');
  await expect(role).toHaveText('reader');
  expect(writes).toEqual([{ name: 'reader' }]);
  expect(errors).toEqual([]);
});

test('policy timeline presents actual publications to read-only operators', async ({ page }) => {
  const policy = { document: { version: 1, rules: [] }, revision: null, rule_count: 0, updated_at: '2026-10-06T12:00:00Z' };
  const errors = await prepare(page, path => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.policies:read'] } };
    if (path === 'policies') return { body: policy };
    if (path === 'policies/history') return { body: { items: [{ id: 8, policy }, { id: 7, policy: { ...policy, updated_at: '2026-10-05T12:00:00Z' } }] } };
    return undefined;
  });
  await page.goto(`${entry}#/policy`);
  const history = page.getByRole('list', { name: 'Published policy versions' });
  await expect(history.getByRole('listitem')).toHaveCount(2);
  await expect(history.getByText('Latest publication', { exact: true })).toHaveCount(1);
  await history.locator('summary').first().press('Enter');
  await expect(history.locator('details').first()).toHaveAttribute('open', '');
  await expect(page.getByRole('button', { name: /^Restore version/ })).toHaveCount(0);
  for (const width of [390, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    for (const dark of [false, true]) {
      await page.evaluate(value => document.documentElement.classList.toggle('dark', value), dark);
      await expect(page.locator('[data-slot=sidebar-inset]')).toHaveCSS('background-color', dark ? 'rgb(20, 20, 20)' : 'rgb(255, 255, 255)');
      await expect(page.locator('.screen h2')).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
      expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/history-${width}-${dark}.png` });
    }
  }
  expect(errors).toEqual([]);
});

test('changing role scope ignores a catalogue response from the previous application', async ({ page }) => {
  const group = { id: 'group-1', name: 'operators', display_name: 'Operators', revision: 1 };
  const errors = await prepare(page, path => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.groups:read', 'admin.app_roles:read', 'admin.app_roles:write'] } };
    if (path === 'groups') return { body: { items: [group], next_cursor: null } };
    if (path === 'groups/group-1') return { body: group };
    if (path === 'groups/group-1/app-roles') return { body: { roles: [], resource_access: {} } };
    if (path === 'clients') return { body: { items: [{ client_id: 'reports' }], next_cursor: null } };
    if (path === 'app-roles') return { body: { roles: [{ name: 'reader', description: 'Workspace reports' }] } };
    return undefined;
  });
  let finish: (() => Promise<void>) | undefined;
  await page.route('**/clients/reports/app-roles', async route => {
    await new Promise<void>(resolve => { finish = async () => { await route.fulfill({ json: { roles: [{ name: 'late-editor', description: 'Previous application' }] } }); resolve(); }; });
  });
  await page.goto(`${entry}#/groups`);
  await page.getByRole('button', { name: 'View Operators' }).click();
  await page.getByRole('button', { name: 'Assign role', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Assign application role' });
  const application = dialog.getByRole('combobox', { name: 'Application', exact: true });
  const role = dialog.getByRole('combobox', { name: 'Role', exact: true });
  await application.click(); await page.getByRole('option', { name: 'reports', exact: true }).click();
  await expect.poll(() => Boolean(finish)).toBe(true);
  await expect(role).toBeDisabled();
  await application.click(); await page.getByRole('option', { name: /Workspace/ }).click();
  await expect(role).toBeEnabled(); await finish!();
  await role.click();
  await expect(page.getByRole('option', { name: /reader/ })).toBeVisible();
  await expect(page.getByRole('option', { name: /late-editor/ })).toHaveCount(0);
  expect(errors).toEqual([]);
});

test('JSON code panels label and number source, preserve exact copy and bound keyboard scrolling', async ({ page }) => {
  const claims = { sub: 'alex', literal: '<img src=x onerror=alert(1)>', unicode: 'Élodie 日本語', multiline: 'first\nsecond', long: 'x'.repeat(2000), ...Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`claim_${i}`, `value ${i}`])) };
  const jwt = [Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url'), Buffer.from(JSON.stringify(claims)).toString('base64url'), 'fixture'].join('.');
  const errors = await prepare(page, path => path === 'session' ? { body: { ...session, scopes: [...session.scopes, 'admin.test_tokens:write'] } } : undefined);
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto(`${entry}#/token-console`);
  await page.getByRole('textbox', { name: 'Encoded token' }).fill(jwt);
  const source = page.getByRole('region', { name: 'JWT claims', exact: true });
  await expect(source).toContainText('<img src=x onerror=alert(1)>');
  expect(await source.textContent()).toBe(JSON.stringify(claims, null, 2));
  await expect(source.locator('img')).toHaveCount(0);
  await expect(source.locator('.code-panel-gutter').first()).toHaveAttribute('data-line', '1');
  await expect(source.locator('.code-panel-gutter').first()).toHaveAttribute('aria-hidden', 'true');
  await page.getByRole('button', { name: 'Copy JWT claims', exact: true }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(JSON.stringify(claims, null, 2));
  expect(await source.evaluate(element => element.clientHeight)).toBeLessThanOrEqual(360);
  await source.focus(); await source.press('PageDown');
  await expect.poll(() => source.evaluate(element => element.scrollTop)).toBeGreaterThan(0);
  const wrap = page.getByRole('switch', { name: 'Wrap lines in JWT claims', exact: true });
  await expect(wrap).toBeChecked();
  await wrap.focus(); await page.keyboard.press('Space');
  await expect(wrap).not.toBeChecked();
  expect(await source.evaluate(element => element.scrollWidth > element.clientWidth)).toBe(true);
  await page.getByRole('button', { name: 'Copy JWT claims', exact: true }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(JSON.stringify(claims, null, 2));
  await wrap.click();
  for (const width of [320, 390, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    for (const dark of [false, true]) {
      await page.evaluate(value => document.documentElement.classList.toggle('dark', value), dark);
      await expect(page.locator('[data-slot=sidebar-inset]')).toHaveCSS('background-color', dark ? 'rgb(20, 20, 20)' : 'rgb(255, 255, 255)');
      await expect(page.locator('.screen h2')).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
      if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/json-code-${width}-${dark}.png` });
    }
  }
  expect(errors).toEqual([]);
});

test('YAML code panels retain multi-document separators and trailing newlines in copy', async ({ page }) => {
  const rbac = [{ apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'RoleBinding', metadata: { name: 'view' } }, { apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'RoleBinding', metadata: { name: 'read' } }];
  const profile = { cluster_id: 'production', client_id: 'broker', namespace: 'apps', group_ids: [], revision: 2, issuer: 'https://issuer.example.test', audience: 'https://cluster.example.test', registration_compatible: true, authentication_configuration: { apiVersion: 'apiserver.config.k8s.io/v1beta1', kind: 'AuthenticationConfiguration', enabled: true }, rbac_bindings: rbac, legacy_flags: [] };
  const errors = await prepare(page, path => {
    if (path === 'clients') return { body: { items: [{ client_id: 'broker', client_name: 'Cluster broker', status: 'active' }], next_cursor: null } };
    if (path === 'clients/broker/kubernetes/online') return { status: 404, body: {} };
    if (path === 'clients/broker/kubernetes') return { body: profile };
    return undefined;
  });
  const expected = 'apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: view\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: read\n';
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto(`${entry}#/kubernetes`);
  await page.getByRole('button', { name: 'View production', exact: true }).click();
  const source = page.getByRole('region', { name: 'Namespace RBAC examples', exact: true });
  await expect(source).toBeVisible();
  expect(await source.textContent()).toBe(expected);
  await page.getByRole('button', { name: 'Copy Namespace RBAC examples', exact: true }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(expected);
  for (const width of [390, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    for (const dark of [false, true]) {
      await page.evaluate(value => document.documentElement.classList.toggle('dark', value), dark);
      await expect(page.locator('[data-slot=sidebar-inset]')).toHaveCSS('background-color', dark ? 'rgb(20, 20, 20)' : 'rgb(255, 255, 255)');
      await expect(page.locator('.screen h2')).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
      expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
      if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/yaml-code-${width}-${dark}.png` });
    }
  }
  await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: () => Promise.reject(new Error('Clipboard denied')) } }));
  await page.getByRole('button', { name: 'Copy Namespace RBAC examples', exact: true }).click();
  await expect(page.getByText('Could not copy the YAML', { exact: true })).toBeVisible();
  expect(await source.textContent()).toBe(expected);
  expect(errors).toEqual([]);
});

test('optional rate limits keep inheritance, raw drafts and explicit refused saves', async ({ page }) => {
  const bounds = { login: { per_address: { max: 5, window_seconds: 60 }, per_account: { max: 3, window_seconds: 60 } } };
  const fixture = { ...settings, limits: { max_authorization_code_lifetime_seconds: 60, max_access_token_lifetime_seconds: 3600 }, rate_limit_bounds: bounds, effective_rate_limits: bounds, rate_limits: { login: { per_account: 2 } } };
  const writes: { rate_limits: unknown }[] = [];
  const errors = await prepare(page, (path, route) => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.tenants:read'] } };
    if (path === 'tenants/review/settings') {
      if (route.request().method() === 'PUT') { writes.push(route.request().postDataJSON()); return { status: 409, body: { error: { message: 'rate_limits.login.per_address: Limit change refused.' } } }; }
      return { body: fixture };
    }
    return undefined;
  });
  let releaseSave: (() => Promise<void>) | undefined;
  await page.route('**/api/v1/tenants/review/settings', async route => {
    if (route.request().method() !== 'PUT' || writes.length > 0) return route.fallback();
    writes.push(route.request().postDataJSON());
    await new Promise<void>(resolve => { releaseSave = async () => {
      await route.fulfill({ status: 409, json: { error: { message: 'rate_limits.login.per_address: Limit change refused.' } } }); resolve();
    }; });
  });
  await page.goto(`${entry}#/settings`);
  await page.getByRole('tab', { name: 'Rate limits', exact: true }).click();
  const input = page.getByRole('spinbutton', { name: 'Sign-in failures per address', exact: true });
  const increase = page.getByRole('button', { name: 'Increase Sign-in failures per address', exact: true });
  const decrease = page.getByRole('button', { name: 'Decrease Sign-in failures per address', exact: true });
  const inherit = page.getByRole('button', { name: 'Use inherited limit for Sign-in failures per address', exact: true });
  await expect(input).toHaveValue('');
  await expect(input).toHaveAttribute('aria-valuetext', 'Inherited deployment maximum: 5');
  await expect(increase).toBeDisabled(); await expect(inherit).toBeDisabled();
  await expect(input.locator('..')).toHaveCSS('opacity', '1');
  await input.press('ArrowUp'); await expect(input).toHaveValue('');
  await decrease.click(); await expect(input).toHaveValue('4');
  await input.press('ArrowDown'); await expect(input).toHaveValue('3');
  await input.press('ArrowUp'); await expect(input).toHaveValue('4');
  await increase.click(); await expect(input).toHaveValue('5'); await expect(increase).toBeDisabled();
  expect(writes).toEqual([]);
  await inherit.click(); await expect(input).toHaveValue('');
  await input.fill('6'); await input.blur(); await expect(input).toHaveValue('6');
  await expect(increase).toBeDisabled(); await expect(decrease).toBeDisabled();
  await expect(input).toHaveAttribute('aria-invalid', 'true');
  await page.getByRole('button', { name: 'Save settings', exact: true }).click();
  await expect(input).toBeDisabled();
  await expect(increase).toBeDisabled(); await expect(decrease).toBeDisabled(); await expect(inherit).toBeDisabled();
  await expect.poll(() => Boolean(releaseSave)).toBe(true); await releaseSave!();
  await expect(input).toBeEnabled();
  await expect(page.getByText('rate_limits.login.per_address: Limit change refused.', { exact: true }).first()).toBeVisible();
  await expect(input).toHaveValue('6');
  expect(writes[0]?.rate_limits).toEqual({ login: { per_address: 6, per_account: 2 } });
  await input.fill('2.5'); await input.blur(); await expect(input).toHaveValue('2.5');
  await expect(decrease).toBeDisabled();
  await inherit.click();
  await page.getByRole('button', { name: 'Use inherited limit for Sign-in failures per account', exact: true }).click();
  await page.getByRole('button', { name: 'Save settings', exact: true }).click();
  await expect.poll(() => writes.length).toBe(2);
  expect(writes[1]?.rate_limits).toEqual({});
  await input.fill('1'); await expect(decrease).toBeDisabled();
  for (const width of [320, 390, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    for (const dark of [false, true]) {
      await page.evaluate(value => document.documentElement.classList.toggle('dark', value), dark);
      await expect(page.locator('[data-slot=sidebar-inset]')).toHaveCSS('background-color', dark ? 'rgb(20, 20, 20)' : 'rgb(255, 255, 255)');
      await expect(page.locator('.screen h2')).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
      for (const group of await page.locator('.optional-number-input').all()) {
        await expect(group).toHaveCSS('background-color', dark ? 'rgb(28, 28, 28)' : 'rgb(255, 255, 255)');
        const control = group.locator('input');
        if (await control.getAttribute('aria-invalid') !== 'true') await expect(control).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
      }
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
      if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/rate-limits-${width}-${dark}.png` });
    }
  }
  expect(writes).toHaveLength(2);
  expect(errors).toEqual([]);
});


test('directory chips clear applied filters and preserve unapplied search drafts', async ({ page }) => {
  const requests: URL[] = [];
  const errors = await prepare(page, (path, route) => {
    if (path === 'users' || path === 'clients') requests.push(new URL(route.request().url()));
    return undefined;
  });
  for (const [screen, label] of [['users', 'Search'], ['clients', 'Search clients']]) {
    await page.goto(`${entry}#/${screen}`);
    const search = page.getByRole('searchbox', { name: label, exact: true });
    await search.fill('alex'); await search.press('Enter');
    await expect(page.getByLabel('Applied directory filters')).toContainText('Search: alex');
    await page.getByRole('button', { name: 'Filter by status: All statuses' }).click();
    await page.getByRole('menuitemradio', { name: 'Active', exact: true }).click();
    await expect(page.getByLabel('Applied directory filters')).toContainText('Status: active');
    await search.fill('unapplied draft');
    await page.getByRole('button', { name: 'Remove status filter' }).click();
    await expect(search).toHaveValue('unapplied draft');
    await expect.poll(() => requests.at(-1)?.searchParams.get('q')).toBe('alex');
    expect(requests.at(-1)?.searchParams.has('status')).toBe(false);
    await page.getByRole('button', { name: 'Remove search filter' }).click();
    await expect(search).toHaveValue('');
    await expect(page.getByLabel('Applied directory filters')).toHaveCount(0);
    await expect.poll(() => requests.at(-1)?.searchParams.has('q')).toBe(false);
    await page.setViewportSize({ width: 320, height: 900 });
    await search.fill('a very long search value '.repeat(10)); await search.press('Enter');
    await expect(page.getByRole('button', { name: 'Clear directory filters' })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.getByRole('button', { name: 'Clear directory filters' }).click();
    await expect(search).toHaveValue('');
  }
  expect(errors).toEqual([]);
});

test('session sorting and active filtering preserve the exact revocation target', async ({ page }) => {
  const rows = [
    { sid: 'older-active', authenticated_at: 1700000000, last_seen_at: 1700000010, expires_at: 1800000000, amr: ['pwd'], live: true, revoked_reason: null },
    { sid: 'ended', authenticated_at: 1750000000, last_seen_at: 1750000010, expires_at: 1800000000, amr: ['webauthn'], live: false, revoked_reason: 'logout' },
    { sid: 'newer-active', authenticated_at: 1760000000, last_seen_at: 1760000010, expires_at: 1800000000, amr: ['pwd', 'otp'], live: true, revoked_reason: null },
  ];
  const writes: string[] = [];
  const errors = await prepare(page, (path, route) => {
    if (path === 'users/alex/sessions') return { body: { items: rows } };
    if (path.startsWith('users/alex/sessions/') && route.request().method() === 'DELETE') { writes.push(path); return { status: 409, body: { error: { message: 'Session cannot be ended.' } } }; }
    return undefined;
  });
  await page.goto(`${entry}#/users?id=alex&tab=sessions`);
  await expect(page.getByText('2 active of 3 loaded')).toBeVisible();
  const table = page.getByRole('table', { name: 'Sign-in sessions' });
  await page.getByRole('switch', { name: 'Active only' }).click();
  await expect(table.locator('tbody tr')).toHaveCount(2);
  await table.getByRole('button', { name: /Signed in/ }).click();
  await table.getByRole('button', { name: /Signed in/ }).click();
  await table.locator('tbody tr').first().getByRole('button', { name: 'End session' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Session cannot be ended.' })).toBeVisible();
  expect(writes).toEqual(['users/alex/sessions/newer-active']);
  await expect(table.locator('tbody tr')).toHaveCount(2);
  await page.setViewportSize({ width: 390, height: 900 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
  if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/session-inspection.png` });
  expect(errors).toEqual([]);
});


test('copy feedback follows the displayed token and ignores stale clipboard completion', async ({ page }) => {
  const errors = await prepare(page, path => path === 'session' ? { body: { ...session, scopes: [...session.scopes, 'admin.test_tokens:write'] } } : undefined);
  await page.goto(`${entry}#/token-console`);
  const token = page.getByRole('textbox', { name: 'Encoded token' });
  await token.fill('first-value');
  await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async () => {} } }));
  const copy = page.getByRole('button', { name: 'Copy token', exact: true });
  await copy.click();
  await expect(page.getByText('Copied', { exact: true })).toBeVisible();
  await token.fill('second-value');
  await expect(page.getByText('Copied', { exact: true })).toHaveCount(0);
  await page.evaluate(() => {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: () => new Promise<void>(resolve => { (window as unknown as { finishCopy: () => void }).finishCopy = resolve; }) } });
  });
  await copy.click(); await expect(copy).toBeDisabled();
  await token.fill('third-value'); await expect(copy).toBeEnabled();
  await page.evaluate(() => (window as unknown as { finishCopy: () => void }).finishCopy());
  await expect(page.getByText('Copied', { exact: true })).toHaveCount(0);
  await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async () => { throw new Error('Denied'); } } }));
  await copy.click();
  await expect(page.getByText('Copy was unavailable. Select and copy the value manually.')).toBeVisible();
  await token.fill('fourth-value');
  await expect(page.getByText('Copy was unavailable. Select and copy the value manually.')).toHaveCount(0);
  expect(errors).toEqual([]);
});

test('recent sign-in activity preserves real outcomes and requires audit permission', async ({ page }) => {
  let reads = 0;
  const errors = await prepare(page, path => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.audit:read'] } };
    if (path === 'audit/events/42') return { body: { id: 42, hash: 'fixture', type: 'auth.login', outcome: 'failure', occurred_at: '2026-09-29T12:00:00Z', detail: {} } };
    if (path === 'audit/events') { reads++; return { body: { items: [{ id: 42, hash: 'fixture-42', type: 'auth.login', outcome: 'failure', occurred_at: '2026-09-29T12:00:00Z' }, { id: 41, hash: 'fixture-41', type: 'auth.login', outcome: 'success', occurred_at: '2026-09-28T12:00:00Z' }, { id: 40, hash: 'fixture-40', opaque: 'unreadable' }], next_cursor: null } }; }
    return undefined;
  });
  await page.goto(`${entry}#/users?id=alex`);
  const timeline = page.getByRole('list', { name: 'Recent sign-in activity' });
  await expect(timeline.locator('li')).toHaveCount(2);
  await expect(timeline.locator('li').first()).toContainText('failure');
  await expect(timeline.locator('li').first().getByRole('link', { name: 'Inspect event' })).toHaveAttribute('href', '#/audit?id=42');
  expect(reads).toBe(1);
  for (const width of [390, 1440]) for (const dark of [false, true]) {
    await page.setViewportSize({ width, height: 900 });
    await page.evaluate(value => document.documentElement.classList.toggle('dark', value), dark);
    const overview = page.getByRole('region', { name: 'Access overview', exact: true });
    await expect(overview).toHaveCSS('padding-top', '20px');
    await expect(overview).toHaveCSS('border-top-width', '1px');
    await expect(overview).toHaveCSS('background-color', dark ? 'rgb(28, 28, 28)' : 'rgb(255, 255, 255)');
    const inset = width <= 600 ? 16 : 24;
    for (const slot of ['card-header', 'card-content']) {
      await expect(overview.locator(`[data-slot=${slot}]`)).toHaveCSS('padding-left', `${inset}px`);
      await expect(overview.locator(`[data-slot=${slot}]`)).toHaveCSS('padding-right', `${inset}px`);
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await expect(page.locator('[data-slot=sidebar-inset]')).toHaveCSS('background-color', dark ? 'rgb(20, 20, 20)' : 'rgb(255, 255, 255)');
    await expect(page.locator('.screen h2')).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
    expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
    if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/signin-activity-${width}-${dark}.png` });
  }
  await timeline.locator('li').first().getByRole('link', { name: 'Inspect event' }).click();
  await expect(page.getByRole('heading', { name: 'Event #42', exact: true })).toBeVisible();
  await page.goto('about:blank');
  const previousReads = reads;
  await prepare(page, path => {
    if (path === 'audit/events') reads++;
    return undefined;
  });
  await page.goto(`${entry}#/users?id=alex`);
  await expect(page.getByText('Requires audit access.')).toBeVisible();
  await expect(page.locator('.app-topbar').getByRole('link', { name: 'Token test console', exact: true })).toHaveCount(0);
  await expect(timeline).toHaveCount(0);
  expect(reads).toBe(previousReads);
  expect(errors).toEqual([]);
});


test('owned empty states reset directory filters without a mutation', async ({ page }) => {
  let writes = 0;
  const errors = await prepare(page, (path, route) => {
    if (route.request().method() !== 'GET') writes++;
    if (path === 'users' || path === 'clients') {
      const filtered = new URL(route.request().url()).searchParams.has('q');
      return { body: { items: filtered ? [] : path === 'users' ? [{ ...user, claims: 0 }] : [{ client_id: 'reports', client_name: 'Reports', status: 'active', grant_types: ['authorization_code'], compliance_profile: 'oidc', token_endpoint_auth_method: 'client_secret_basic', jwks_source: 'none' }], next_cursor: null } };
    }
    return undefined;
  });
  for (const [screen, label, title, reset] of [['users', 'Search', 'No account matches.', 'Reset account filters'], ['clients', 'Search clients', 'No client matches.', 'Reset application filters']]) {
    await page.goto(`${entry}#/${screen}`);
    const input = page.getByRole('searchbox', { name: label, exact: true });
    await input.fill('missing'); await input.press('Enter');
    await expect(page.getByRole('heading', { name: title, exact: true })).toBeVisible();
    for (const dark of [false, true]) {
      await page.setViewportSize({ width: 320, height: 900 });
      await page.evaluate(value => document.documentElement.classList.toggle('dark', value), dark);
      await expect(page.locator('.screen h2')).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
      if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/empty-${screen}-${dark}.png` });
    }
    await page.getByRole('button', { name: reset, exact: true }).click();
    await expect(input).toHaveValue('');
    await expect(page.getByRole('heading', { name: title, exact: true })).toHaveCount(0);
  }
  expect(writes).toBe(0); expect(errors).toEqual([]);
});

test('Base segmented preferences retain one choice and persist keyboard changes', async ({ page }) => {
  const errors = await prepare(page);
  await page.goto(`${entry}#/preferences`);
  const theme = page.getByRole('group', { name: 'Colour theme', exact: true });
  const density = page.getByRole('group', { name: 'Table density', exact: true });
  await theme.getByRole('button', { name: 'Light', exact: true }).focus();
  await page.keyboard.press('ArrowRight'); await page.keyboard.press('Space');
  await expect(theme.getByRole('button', { name: 'Dark', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await density.getByRole('button', { name: 'Compact', exact: true }).click();
  await density.getByRole('button', { name: 'Compact', exact: true }).click();
  await expect(density.getByRole('button', { name: 'Compact', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await page.reload();
  await expect(theme.getByRole('button', { name: 'Dark', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(density.getByRole('button', { name: 'Compact', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('html')).toHaveAttribute('data-table-density', 'compact');
  await page.setViewportSize({ width: 320, height: 900 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
  if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/segmented-preferences.png` });
  expect(errors).toEqual([]);
});

test('secret input reveal is local, remasks on blur and keeps rejected raw drafts', async ({ page }) => {
  const writes: { password: string }[] = [];
  const errors = await prepare(page, (path, route) => {
    if (path === 'users' && route.request().method() === 'POST') { writes.push(route.request().postDataJSON()); return { status: 409, body: { error: { message: 'Account creation refused.' } } }; }
    return undefined;
  });
  await page.goto(`${entry}#/users?mode=new`);
  const password = page.getByLabel('Initial password (optional)', { exact: true });
  const show = page.getByRole('button', { name: 'Show initial password', exact: true });
  await expect(show).toBeDisabled();
  await password.fill('  raw credential  ');
  await expect(password).toHaveAttribute('type', 'password');
  // Decorations add no tab stop: native input → native reveal button.
  await password.focus(); await page.keyboard.press('Tab');
  await expect(show).toBeFocused(); await page.keyboard.press('Space');
  await expect(password).toHaveAttribute('type', 'text');
  expect(writes).toHaveLength(0);
  await page.getByRole('textbox', { name: 'Username', exact: true }).fill('new.user');
  await expect(password).toHaveAttribute('type', 'password');
  await page.getByRole('button', { name: 'Create user', exact: true }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Account creation refused.' })).toBeVisible();
  expect(writes).toHaveLength(1); expect(writes[0]?.password).toBe('  raw credential  ');
  await expect(password).toHaveValue('  raw credential  ');
  await show.click(); await expect(password).toHaveAttribute('type', 'text');
  await password.fill(''); await expect(show).toBeDisabled();
  await expect(password).toHaveAttribute('type', 'password');
  for (const dark of [false, true]) {
    await page.setViewportSize({ width: 390, height: 900 });
    await page.evaluate(value => document.documentElement.classList.toggle('dark', value), dark);
    await expect(page.locator('.screen h2')).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
    await expect(password.locator('..')).toHaveCSS('background-color', dark ? 'rgb(28, 28, 28)' : 'rgb(255, 255, 255)');
    expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
  }
  expect(await page.evaluate(() => Object.values(localStorage).some(value => String(value).includes('raw credential')))).toBe(false);
  expect(errors).toEqual([]);
});


test('replacement secret remains blank by default and pending save masks and disables reveal', async ({ page }) => {
  const writes: Record<string, unknown>[] = [];
  const errors = await prepare(page, (path, route) => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.oidc_providers:read', 'admin.oidc_providers:write'] } };
    if (path === 'oidc/providers/check') return { body: { checked_at: 1700000000, checks: [] } };
    if (path === 'oidc/providers' && route.request().method() === 'GET') return { body: { callback_url_template: 'https://idp.example.test/callback/{id}', providers: [{ id: 'external', name: 'External provider', issuer: 'https://issuer.example.test', client_id: 'console', enabled: true, secret_configured: true }] } };
    return undefined;
  });
  let release: (() => Promise<void>) | undefined;
  await page.route('**/api/v1/oidc/providers', async route => {
    if (route.request().method() !== 'PUT') return route.fallback();
    writes.push(route.request().postDataJSON());
    if (writes.length === 1) return route.fulfill({ status: 409, json: { error: { message: 'Replacement refused.' } } });
    await new Promise<void>(resolve => { release = async () => { await route.fulfill({ status: 409, json: { error: { message: 'Replacement refused.' } } }); resolve(); }; });
  });
  await page.goto(`${entry}#/oidc-providers`);
  await page.getByRole('button', { name: 'Edit', exact: true }).click();
  const input = page.getByLabel('Replace client secret', { exact: true });
  await expect(input).toHaveValue('');
  await expect(page.getByRole('button', { name: 'Show replacement client secret' })).toBeDisabled();
  await page.getByRole('button', { name: 'Save changes', exact: true }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Replacement refused.' })).toBeVisible();
  expect(writes[0]).not.toHaveProperty('client_secret');
  await input.fill('  replacement draft  ');
  await page.getByRole('button', { name: 'Show replacement client secret' }).click();
  await expect(input).toHaveAttribute('type', 'text');
  await page.getByRole('button', { name: 'Save changes', exact: true }).click();
  await expect(input).toBeDisabled(); await expect(input).toHaveAttribute('type', 'password');
  await expect(page.getByRole('button', { name: 'Show replacement client secret' })).toBeDisabled();
  await expect.poll(() => Boolean(release)).toBe(true); await release!();
  await expect(input).toBeEnabled(); await expect(input).toHaveValue('  replacement draft  ');
  expect(writes[1]?.client_secret).toBe('  replacement draft  ');
  expect(errors).toEqual([]);
});


const ownershipFixture = [
  { id: 'own-reader', target: { kind: 'user_tenant_role', user_id: 'alex', name: 'Reader' }, owner: 'admin', reviewers: ['admin'], revision: '1', enabled: true },
  { id: 'own-writer', target: { kind: 'user_tenant_role', user_id: 'alex', name: 'Writer' }, owner: 'admin', reviewers: ['admin'], revision: '2', enabled: true },
  { id: 'own-disabled', target: { kind: 'user_tenant_role', user_id: 'alex', name: 'Disabled' }, owner: null, reviewers: ['admin'], revision: '3', enabled: false },
];
const reviewFixture = { id: 'review-open', created_by: 'admin', created_at: '2026-09-29T12:00:00Z', due_at: '2030-09-29T12:00:00Z', completed_at: null, cancelled_at: null };
const reviewItemFixture = { id: 'item-reader', ownership_id: 'own-reader', ownership_revision: '1', target: ownershipFixture[0]!.target, assignment_generation: '1', assigned_reviewer: 'admin', decision: null, reason: null, apply_status: 'pending', snapshot: { observed_at: '2026-09-29T12:00:00Z', protected: false, affected_users: [{ user_id: 'alex', username: 'alex@example.test', account_status: 'active', standing_sources: [{ client_id: null, name: 'Reader', group_id: null }, { client_id: 'reports', name: 'Analyst', group_id: 'operators' }], temporary_sources: { entries: [{ activation_id: 'independent', client: 'reports', resource: 'https://reports.example.test', role_name: 'Temporary reader', permissions: ['read'], expires_at: '2030-09-29T12:00:00Z' }] } }] } };
async function prepareReviews(page: Page, writable: boolean, override?: (path: string, route: Route) => Reply | undefined) {
  return prepare(page, (path, route) => {
    const custom = override?.(path, route); if (custom) return custom;
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.governance:read', 'admin.groups:read', ...(writable ? ['admin.governance:write'] : [])] } };
    if (path === 'governance/ownership') return { body: { items: ownershipFixture } };
    if (path === 'governance/reviewers') return { body: { items: [{ user_id: 'admin', username: 'admin@example.test' }] } };
    if (path === 'governance/reviews') return { body: { items: [reviewFixture, { ...reviewFixture, id: 'review-completed', created_at: '2026-09-28T12:00:00Z', completed_at: '2026-09-29T12:00:00Z' }, { ...reviewFixture, id: 'review-cancelled', created_at: '2026-09-27T12:00:00Z', cancelled_at: '2026-09-28T12:00:00Z' }] } };
    if (path === 'governance/reviews/review-open') return { body: reviewFixture };
    if (path === 'governance/reviews/review-open/items') return { body: { items: [reviewItemFixture] } };
    return undefined;
  });
}

test('ownership grid and selection bar preserve bounded IDs through sorting and refused creation', async ({ page }) => {
  const writes: Record<string, unknown>[] = [];
  const errors = await prepareReviews(page, true, (path, route) => {
    if (path === 'governance/reviews' && route.request().method() === 'POST') { writes.push(route.request().postDataJSON()); return { status: 409, body: { error: { message: 'Review creation refused.' } } }; }
    return undefined;
  });
  await page.goto(`${entry}#/access-reviews`);
  const table = page.getByRole('table', { name: 'Owned standing assignments' });
  await expect(table).toBeVisible();
  await table.getByRole('checkbox', { name: 'Select User tenant role: Reader for alex@example.test' }).check();
  await expect(table.getByRole('checkbox', { name: 'Select User tenant role: Disabled for alex@example.test' })).toBeDisabled();
  await expect(page.getByRole('group', { name: 'Selected ownership records' })).toContainText('1 record selected');
  await table.getByRole('button', { name: 'Standing source', exact: true }).click();
  const panel = page.locator('section').filter({ has: page.getByRole('heading', { name: 'Current ownership', exact: true }) }).last();
  await panel.getByRole('button', { name: 'Columns' }).click();
  await page.getByRole('checkbox', { name: 'Owner', exact: true }).uncheck();
  await page.keyboard.press('Escape');
  await expect(table.getByRole('columnheader', { name: 'Owner', exact: true })).toHaveCount(0);
  if (process.env.E2E_SHOTS) await panel.screenshot({ path: `${process.env.E2E_SHOTS}/ownership-grid.png` });
  await page.getByRole('combobox', { name: 'Assigned reviewer', exact: true }).click();
  await page.getByRole('option', { name: 'admin@example.test', exact: true }).click();
  await page.getByRole('button', { name: 'Create review (1 selected)', exact: true }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Review creation refused.' })).toBeVisible();
  expect(writes[0]?.ownership_ids).toEqual(['own-reader']);
  await expect(table.getByRole('checkbox', { name: 'Select User tenant role: Reader for alex@example.test' })).toBeChecked();
  await page.getByRole('button', { name: 'Clear selection', exact: true }).click();
  await expect(page.getByRole('group', { name: 'Selected ownership records' })).toContainText('0 records selected');
  await expect(page.getByRole('button', { name: 'Create review (0 selected)', exact: true })).toBeDisabled();
  expect(writes).toHaveLength(1); expect(errors).toEqual([]);
});

test('review history displays actual states and read-only users cannot select or create', async ({ page }) => {
  const errors = await prepareReviews(page, false);
  await page.goto(`${entry}#/access-reviews`);
  const table = page.getByRole('table', { name: 'Access review history' });
  for (const state of ['Open', 'Completed', 'Cancelled']) await expect(table.getByText(state, { exact: true })).toBeVisible();
  await table.getByRole('button', { name: 'Created', exact: true }).click();
  await expect(table.locator('tbody tr').first()).toContainText('Cancelled');
  await expect(page.getByRole('button', { name: 'Clear selection', exact: true })).toHaveCount(0);
  for (const control of await page.getByRole('table', { name: 'Owned standing assignments' }).getByRole('checkbox').all()) await expect(control).toBeDisabled();
  await table.getByRole('button', { name: 'Created', exact: true }).click();
  await table.locator('tbody tr').first().getByRole('button', { name: 'Open review', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Selected review', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Record retain', exact: true })).toHaveCount(0);
  expect(errors).toEqual([]);
});

test('snapshot accordion preserves evidence and reason drafts through refusal, keyboard and themes', async ({ page }) => {
  const writes: { decision: string; reason: string }[] = [];
  const errors = await prepareReviews(page, true, (path, route) => {
    if (path.endsWith('/decision') && route.request().method() === 'PUT') { writes.push(route.request().postDataJSON()); return { status: 409, body: { error: { message: 'Decision refused.' } } }; }
    return undefined;
  });
  await page.goto(`${entry}#/access-reviews`);
  await page.getByRole('table', { name: 'Access review history' }).locator('tbody tr').first().getByRole('button', { name: 'Open review', exact: true }).click();
  const toggle = page.getByRole('button', { name: 'Snapshot access for alex@example.test', exact: true });
  await expect(toggle).toHaveAttribute('aria-expanded', 'true');
  expect((await toggle.locator('[data-slot=badge]').boundingBox())?.width).toBeLessThan(120);
  await expect(page.getByText('Independent temporary activations', { exact: false })).toBeVisible();
  await expect(page.getByText('2 standing sources · 1 temporary activation', { exact: true })).toBeVisible();
  const reason = page.getByRole('textbox', { name: 'Decision reason', exact: true });
  await reason.fill('  Actual raw reason  ');
  await toggle.focus(); await page.keyboard.press('Space');
  await expect(toggle).toHaveAttribute('aria-expanded', 'false');
  await expect(reason).toHaveValue('  Actual raw reason  ');
  await page.keyboard.press('Space');
  await page.getByRole('button', { name: 'Record retain', exact: true }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Decision refused.' })).toBeVisible();
  expect(writes).toEqual([{ decision: 'retain', reason: '  Actual raw reason  ' }]);
  await expect(reason).toHaveValue('  Actual raw reason  ');
  await reason.fill('x'.repeat(1000));
  await expect(page.getByText('1000 / 1000 characters', { exact: true })).toBeVisible();
  await expect(reason).toHaveAttribute('maxLength', '1000');
  await expect(page.getByText('Character limit reached.', { exact: true })).toHaveCount(1);
  for (const width of [390, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    for (const dark of [false, true]) {
      await page.evaluate(value => document.documentElement.classList.toggle('dark', value), dark);
      await expect(page.locator('.screen h2')).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
      await expect(reason.locator('..')).toHaveCSS('background-color', dark ? 'rgb(28, 28, 28)' : 'rgb(255, 255, 255)');
      await expect(reason).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
      if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/access-review-${width}-${dark}.png`, fullPage: true });
    }
  }
  expect(errors).toEqual([]);
});


test('recorded review removal still requires confirmation and displays a refused apply in the dialog', async ({ page }) => {
  const writes: string[] = [];
  const errors = await prepareReviews(page, true, (path, route) => {
    if (path === 'governance/reviews/review-open/items') return { body: { items: [{ ...reviewItemFixture, decision: 'remove', reason: 'Recorded reason', snapshot: { ...reviewItemFixture.snapshot, protected: true } }] } };
    if (path.endsWith('/apply') && route.request().method() === 'POST') { writes.push(path); return { status: 409, body: { error: { message: 'Source changed; apply refused.' } } }; }
    return undefined;
  });
  await page.goto(`${entry}#/access-reviews`);
  await page.getByRole('table', { name: 'Access review history' }).locator('tbody tr').first().getByRole('button', { name: 'Open review', exact: true }).click();
  await expect(page.getByText('This source is managed.', { exact: false })).toBeVisible();
  await expect(page.getByText('Recorded reason', { exact: false })).toBeVisible();
  await expect(page.getByRole('textbox', { name: 'Decision reason', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Apply recorded decision', exact: true }).click();
  const dialog = page.getByRole('alertdialog');
  await expect(dialog).toBeVisible(); expect(writes).toHaveLength(0);
  await dialog.getByRole('button', { name: 'Apply decision', exact: true }).click();
  await expect(dialog.getByRole('alert').filter({ hasText: 'Source changed; apply refused.' })).toBeVisible();
  await expect(dialog.getByRole('button', { name: 'Apply decision', exact: true })).toBeEnabled();
  expect(writes).toEqual(['governance/reviews/review-open/items/item-reader/apply']);
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(page.getByText('Independent temporary activations', { exact: false })).toBeVisible();
  expect(errors).toEqual([]);
});

test('application sensitivity uses styled keyboard choices and fences a stale classification', async ({ page }) => {
  const client = { client_id: 'reports', client_name: 'Reports', compliance_profile: 'oidc', status: 'active', application_type: 'web',
    token_endpoint_auth_method: 'client_secret_basic', redirect_uris: [], post_logout_redirect_uris: [], grant_types: ['authorization_code'],
    scope: 'openid', id_token_signed_response_alg: 'EdDSA', subject_type: 'public', resources: [], authorization_details_types: [] };
  let written: unknown = null;
  const errors = await prepare(page, (path, route) => {
    if (path === 'clients/reports') return { body: client };
    if (path === 'clients/reports/conditional-access') {
      if (route.request().method() === 'PUT') {
        written = route.request().postDataJSON();
        return { status: 409, body: { error: { message: 'Classification revision changed' } } };
      }
      return { body: { sensitivity: null, revision: null } };
    }
    return undefined;
  });
  await page.goto(`${entry}#/clients?id=reports&tab=policy`);
  const classification = page.getByRole('combobox', { name: 'Application sensitivity', exact: true });
  await expect(classification).toContainText('Unclassified (absent)');
  expect(await classification.evaluate(element => element.tagName)).toBe('BUTTON');
  await classification.focus();
  await page.keyboard.press('ArrowDown');
  await expect(page.getByRole('listbox')).toBeVisible();
  await page.getByRole('option', { name: 'Sensitive', exact: true }).click();
  expect(written).toBeNull();
  await page.getByRole('button', { name: 'Review classification change' }).click();
  expect(written).toBeNull();
  await page.getByRole('button', { name: 'Save reviewed classification' }).click();
  await expect(page.getByRole('alertdialog', { name: 'Change application sensitivity?' }).getByText('Classification revision changed')).toBeVisible();
  expect(written).toEqual({ sensitivity: 'sensitive', expected_revision: null });
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(classification).toBeDisabled();
  await expect(page.getByText('Another operator changed this classification.', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'Reload classification' }).click();
  await expect(classification).toBeEnabled();
  await expect(classification).toContainText('Unclassified (absent)');
  await classification.click();
  await expect(page.getByRole('listbox')).toBeVisible();
  if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/application-sensitivity-select.png` });
  const audit = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze();
  expect(audit.violations.filter(v => v.impact === 'critical' || v.impact === 'serious')).toEqual([]);
  await page.keyboard.press('Escape');
  await expect(classification).toBeFocused();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.evaluate(() => document.documentElement.classList.add('dark'));
  await expect(page.locator('.screen h2')).toHaveCSS('color', 'rgb(250, 250, 250)');
  await classification.click();
  await expect(page.getByRole('listbox')).toBeVisible();
  const mobileAudit = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze();
  expect(mobileAudit.violations.filter(v => v.impact === 'critical' || v.impact === 'serious')).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/application-sensitivity-select-mobile.png` });
  expect(errors).toEqual([]);
});

test('schema workbench formats explicitly, retains rejected raw drafts and offers a read-only inspector', async ({ page }) => {
  const storedSchema = { type: 'object', properties: { amount: { type: 'number' } } };
  let submitted: unknown = null;
  const errors = await prepare(page, (path, route) => {
    if (path === 'authorization-details-types') return { body: { items: [{ type: 'payment', schema: storedSchema, consent_template: 'Make a payment' }] } };
    if (path === 'authorization-details-types/payment' && route.request().method() === 'PUT') {
      submitted = route.request().postDataJSON(); return { status: 409, body: { error: { message: 'Registration refused.' } } };
    }
    return undefined;
  });
  await page.goto(`${entry}#/authorization-details`);
  const inspect = page.getByRole('button', { name: 'View schema for payment' });
  await inspect.click();
  await expect(page.getByRole('dialog', { name: 'Schema for payment' })).toContainText('amount');
  expect(submitted).toBeNull();
  await page.keyboard.press('Escape');
  await expect(inspect).toBeFocused();
  await page.getByRole('button', { name: 'Edit payment', exact: true }).click();
  const schema = page.getByRole('textbox', { name: 'JSON Schema', exact: true });
  const definition = page.getByRole('region', { name: 'Schema definition', exact: true });
  const raw = '  {"type":"object", "properties":{"amount":{"type":"number"}}}  ';
  await schema.fill(raw);
  await page.getByRole('button', { name: 'Save changes', exact: true }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Registration refused.' })).toBeVisible();
  await expect(schema).toHaveValue(raw);
  expect(submitted).toEqual({ schema: storedSchema, consent_template: 'Make a payment' });
  await definition.getByRole('button', { name: 'Format JSON' }).click();
  await expect(schema).toHaveValue(JSON.stringify(storedSchema, null, 2));
  await schema.fill('{');
  await expect(schema).toHaveAttribute('aria-invalid', 'true');
  await expect(definition.getByRole('button', { name: 'Format JSON' })).toBeDisabled();
  await expect(page.getByRole('navigation', { name: 'Page sections' })).toHaveCount(0);
  expect(new URL(page.url()).hash).toBe('#/authorization-details');
  expect(errors).toEqual([]);
});

test('single audit filter editor applies only its value and preserves unrelated draft filters', async ({ page }) => {
  const queries: string[] = [];
  const errors = await prepare(page, (path, route) => {
    if (path === 'session') return { body: { ...session, scopes: [...session.scopes, 'admin.audit:read'] } };
    if (path === 'audit/events') { queries.push(new URL(route.request().url()).search); return { body: { items: [], next_cursor: null } }; }
    return undefined;
  });
  await page.goto(`${entry}#/audit`);
  await page.getByLabel('Event type', { exact: true }).fill('session.revoked');
  await page.getByRole('button', { name: 'Apply filters' }).click();
  await page.getByLabel('User', { exact: true }).fill('unapplied-user');
  await page.getByRole('button', { name: 'Edit Event type filter' }).click();
  await page.getByLabel('New Event type value').fill('token.issued');
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  expect(queries.at(-1)).toBe('?type=session.revoked');
  await page.getByRole('button', { name: 'Edit Event type filter' }).click();
  await expect(page.getByLabel('New Event type value')).toHaveValue('session.revoked');
  await page.getByLabel('New Event type value').fill('token.issued');
  await page.getByRole('button', { name: 'Apply this filter' }).click();
  await expect.poll(() => queries.at(-1)).toBe('?type=token.issued');
  await expect(page.getByLabel('User', { exact: true })).toHaveValue('unapplied-user');
  expect(errors).toEqual([]);
});

test('session inspector exposes recorded metadata without revoking or losing the list context', async ({ page }) => {
  const sid = 'known-session';
  let writes = 0;
  const errors = await prepare(page, (path, route) => {
    if (route.request().method() === 'DELETE') writes++;
    if (path === 'users/alex/sessions') return { body: { items: [{ sid, created_at: 1700000000, authenticated_at: 1700000000, last_seen_at: 1700000010, expires_at: 1900000000, amr: ['pwd', 'otp'], acr: 'urn:assurance:mfa', live: true, revoked_at: null, revoked_reason: null }] } };
    return undefined;
  });
  await page.goto(`${entry}#/users?id=alex&tab=sessions`);
  const inspect = page.getByRole('button', { name: 'Inspect session' });
  await inspect.click();
  const sheet = page.getByRole('dialog', { name: 'Session details' });
  await expect(sheet).toContainText('urn:assurance:mfa');
  await expect(sheet).toContainText('pwd, otp');
  await expect(sheet.getByText(sid, { exact: true })).toBeVisible();
  await expect(sheet.getByRole('button', { name: 'End session' })).toHaveCount(0);
  await page.setViewportSize({ width: 390, height: 844 });
  expect((await sheet.boundingBox())?.width).toBe(390);
  expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
  if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/session-detail-sheet.png` });
  await page.keyboard.press('Escape');
  await expect(inspect).toBeFocused();
  await expect(page.getByRole('table', { name: 'Sign-in sessions' })).toBeVisible();
  expect(writes).toBe(0);
  expect(errors).toEqual([]);
});

test('every console destination retains hierarchy and reflows when its reads are unavailable', async ({ page }) => {
  test.setTimeout(120_000);
  const { DESTINATIONS } = await import('../../console/src/navigation');
  const allScopes = [...new Set(DESTINATIONS.flatMap(destination => destination.scope ? [destination.scope] : []))];
  const errors = await prepare(page, path => path === 'session'
    ? { body: { ...session, scopes: [...session.scopes, ...allScopes], deployment_scopes: allScopes } }
    : { status: 503, body: { error: { message: 'Fixture read is temporarily unavailable.' } } });
  for (const destination of DESTINATIONS) {
    await page.goto(`${entry}#/${destination.route}`);
    await expect(page.locator('.screen-head h2').first()).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Asterius console', exact: true })).toHaveCount(1);
    await expect(page.getByRole('heading', { name: 'Signed out', exact: true })).toHaveCount(0);
    for (const [width, dark] of [[1440, false], [1440, true], [390, true]] as const) {
      await page.setViewportSize({ width, height: 900 });
      await page.evaluate(dark => document.documentElement.classList.toggle('dark', dark), dark);
      await expect(page.locator('.screen h2').first()).toHaveCSS('color', dark ? 'rgb(250, 250, 250)' : 'rgb(16, 24, 40)');
      await expect(page.locator('.page-illustration')).toHaveCount(1);
      await expect(page.locator('.page-illustration')).toHaveAttribute('aria-hidden', 'true');
      await expect(page.getByRole('navigation', { name: 'Page sections' })).toHaveCount(0);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), destination.route).toBe(true);
      if (process.env.E2E_SHOTS) await page.screenshot({ path: `${process.env.E2E_SHOTS}/route-${destination.route}-${width}-${dark}.png` });
    }
  }
  expect(errors).toEqual([]);
});


test('architecture OIDC integration keeps credentials apply-only and clears failed attempts', async ({ page }) => {
  const id='a0000000-0000-4000-8000-000000000066';
  let saved: any={id,name:'Integration architecture',revision:1,updated_at:'2026-10-08T00:00:00Z',graph:{schema_version:1,nodes:[{id:'provider',kind:'identity_provider',mode:'managed',label:'Corporate',identifier:'corp',x:0,y:0,settings:{integration:true,issuer:'https://login.example',client_id:'upstream',enabled:false,allow_registration:false}}],edges:[]}};
  let apply: any=null; let storedDraft: any=null;
  const errors=await prepare(page,(path,route)=>{
    if(path==='session')return {body:{...session,scopes:[...session.scopes,'admin.flows:write','admin.oidc_providers:read','admin.oidc_providers:write']}};
    if(path===`flows/${id}`){if(route.request().method()==='PUT'){storedDraft=route.request().postDataJSON();saved={...saved,...storedDraft,revision:2};}return {body:saved};}
    if(path===`flows/${id}/plan`)return {body:{flow_id:id,revision:saved.revision,digest:'reviewed',applicable:true,steps:[{id:'provider',label:'Corporate',kind:'identity_provider',action:'create',scope:'admin.oidc_providers:write',resource_id:'corp',explanation:'Discovery checked; no account binding is created.',live:{requires_credential:true}}]}};
    if(path===`flows/${id}/apply`){apply=route.request().postDataJSON();return {status:409,body:{error:{message:'Discovery changed; preview again'}}};}
    return undefined;
  });
  await page.goto(`${entry}#/architecture?flow=${id}&mode=edit`);
  await page.getByRole('button',{name:'Show object list',exact:true}).click();
  await page.getByRole('button',{name:'Corporate · External identity provider',exact:true}).click();
  await page.getByLabel('Upstream client ID',{exact:true}).fill('reviewed-client');
  await page.getByRole('button',{name:'Save draft',exact:true}).click();
  await expect.poll(()=>storedDraft?.graph.nodes[0].settings.client_id).toBe('reviewed-client');
  await page.getByRole('button',{name:'Review changes',exact:true}).click();
  await expect(page.getByRole('button',{name:'Apply this plan',exact:true})).toBeDisabled();
  await page.getByLabel('Corporate: Client secret required',{exact:true}).fill('apply-only-browser-secret');
  expect(JSON.stringify(storedDraft)).not.toContain('apply-only-browser-secret');
  await expect(page.getByRole('button',{name:'Apply this plan',exact:true})).toBeEnabled();
  await expect(page.getByRole('button',{name:'Apply this plan',exact:true})).toHaveCSS('opacity', '1');
  expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze()).violations).toEqual([]);
  await page.getByRole('button',{name:'Apply this plan',exact:true}).click();
  await expect.poll(()=>apply?.credentials.provider).toBe('apply-only-browser-secret');
  expect(apply).toEqual({revision:2,digest:'reviewed',credentials:{provider:'apply-only-browser-secret'}});
  await page.getByRole('button',{name:'Review changes',exact:true}).click();
  await expect(page.getByLabel('Corporate: Client secret required',{exact:true})).toHaveValue('');
  expect(await page.evaluate(()=>JSON.stringify(localStorage))).not.toContain('apply-only-browser-secret');
  expect(errors).toEqual([]);
});

test('architecture stream integration pins configured peer policy without storing credentials', async ({ page }) => {
  const id='a0000000-0000-4000-8000-000000000067';const peer='https://transmitter.example';
  let saved: any={id,name:'Signals architecture',revision:1,updated_at:'2026-10-08T00:00:00Z',graph:{schema_version:1,nodes:[{id:'stream',kind:'stream',mode:'managed',label:'Security signals',identifier:'',x:0,y:0,settings:{integration:true}}],edges:[]}};
  let written: any=null;
  const errors=await prepare(page,(path,route)=>{
    if(path==='session')return {body:{...session,scopes:[...session.scopes,'admin.flows:write','admin.ssf:read','admin.ssf:write']}};
    if(path==='ssf/upstream/peers')return {body:{items:[{peer_client_id:peer,state:'not_started',expected_audience:'https://as.example/ssf/receiver',allow_all_subjects:true}]}};
    if(path===`flows/${id}`){if(route.request().method()==='PUT'){written=route.request().postDataJSON();saved={...saved,...written,revision:2};}return {body:saved};}
    if(path===`flows/${id}/plan`)return {body:{flow_id:id,revision:2,digest:'signals',applicable:true,steps:[{id:'stream',kind:'stream',label:'Security signals',action:'create',scope:'admin.ssf:write',resource_id:peer,explanation:'Setup does not prove signed event delivery. Request verification in Shared signals.'}]}};
    return undefined;
  });
  await page.goto(`${entry}#/architecture?flow=${id}&mode=edit`);
  await page.getByRole('button',{name:'Show object list',exact:true}).click();
  await page.getByRole('button',{name:'Security signals · Security event stream',exact:true}).click();
  await page.getByLabel('Configured upstream transmitter',{exact:true}).focus();
  await page.keyboard.press('Space');
  await expect(page.getByRole('option', {name: `${peer} · not_started`, exact:true})).toBeVisible();
  await page.keyboard.press('End');
  await page.keyboard.press('Enter');
  await expect(page.getByText('The operator allows ALL-subject delivery.',{exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Save draft',exact:true}).click();
  await expect.poll(()=>written?.graph.nodes[0].identifier).toBe(peer);
  expect(written.graph.nodes[0].settings).toEqual({integration:true,expected_audience:'https://as.example/ssf/receiver',allow_all_subjects:true});
  await page.getByRole('button',{name:'Review changes',exact:true}).click();
  await expect(page.getByText('Setup does not prove signed event delivery. Request verification in Shared signals.',{exact:true})).toBeVisible();
  expect(errors).toEqual([]);
});
