import type { TenantPage, TenantRow } from './tenants';

/** Exhaust a cursor-paginated tenant list before offering switch targets. */
export async function loadAllTenants(
  readPage: (path: string) => Promise<TenantPage>,
): Promise<readonly TenantRow[]> {
  const tenants: TenantRow[] = [];
  const seen = new Set<string>();
  let cursor: string | null = null;
  do {
    const path: string = cursor === null ? 'tenants' : `tenants?cursor=${encodeURIComponent(cursor)}`;
    const page = await readPage(path);
    tenants.push(...page.items);
    cursor = page.next_cursor;
    if (cursor !== null) {
      if (seen.has(cursor)) throw new Error('The tenant list repeated a page. Try again.');
      seen.add(cursor);
    }
  } while (cursor !== null);
  return tenants;
}

/** Keep a deployment session on its current host when that host serves the target. */
export function tenantSwitchUrl(tenant: TenantRow, currentOrigin: string, route: string): string {
  const issuer = new URL(tenant.issuer);
  const current = new URL(currentOrigin);
  if (tenant.custom_host?.toLowerCase() === current.host.toLowerCase()
    && issuer.origin !== current.origin) {
    return `${current.origin}/t/${encodeURIComponent(tenant.tenant_id)}/admin/#/${route}`;
  }
  return `${tenant.issuer.replace(/\/+$/, '')}/admin/#/${route}`;
}
