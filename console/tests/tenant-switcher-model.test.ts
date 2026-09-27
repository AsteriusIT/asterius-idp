import assert from 'node:assert/strict';
import test from 'node:test';
import { loadAllTenants, tenantSwitchUrl } from '../src/tenant-switcher-model.ts';
import type { TenantPage, TenantRow } from '../src/tenants.tsx';

function tenant(id: string): TenantRow {
  return { tenant_id: id, issuer: `https://id.example/t/${id}`, display_name: id,
    default_resource: 'https://api.example', custom_host: null, status: 'active' };
}

test('switcher reads every page and encodes opaque cursors', async () => {
  const paths: string[] = [];
  const result = await loadAllTenants(async (path): Promise<TenantPage> => {
    paths.push(path);
    return path === 'tenants'
      ? { items: [tenant('first')], next_cursor: 'next/page+1' }
      : { items: [tenant('second')], next_cursor: null };
  });
  assert.deepEqual(result.map((item) => item.tenant_id), ['first', 'second']);
  assert.deepEqual(paths, ['tenants', 'tenants?cursor=next%2Fpage%2B1']);
});

test('switcher rejects a repeated cursor instead of looping forever', async () => {
  await assert.rejects(
    loadAllTenants(async (): Promise<TenantPage> => ({ items: [], next_cursor: 'repeat' })),
    /repeated a page/,
  );
});

test('switcher keeps a session on a host that serves the target tenant', () => {
  const target = { ...tenant('other'), custom_host: 'console.example' };
  assert.equal(tenantSwitchUrl(target, 'https://console.example', 'overview'),
    'https://console.example/t/other/admin/#/overview');
  assert.equal(tenantSwitchUrl(target, 'https://unrelated.example', 'overview'),
    'https://id.example/t/other/admin/#/overview');
});
