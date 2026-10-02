import { FormSelect } from './components/ui/select';
import { DirectorySearch } from './directory-controls';
import { ConnectionDocument } from './components/connection-document';
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { read, type Session } from './api';
import type { ClientDocument } from './client-draft';
import { hrefOf } from './routes';
import { Badge, EmptyState, Field, LoadFailure, Panel, Screen, Skeleton } from './ui';

interface ClientSummary {
  readonly client_id: string;
  readonly client_name: string;
}

interface ClientPage {
  readonly items: readonly ClientSummary[];
  readonly next_cursor: string | null;
}

type Inventory =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly page: ClientPage }
  | { readonly kind: 'failed'; readonly message: string };

type Inspection =
  | { readonly kind: 'idle' }
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly client: ClientDocument }
  | { readonly kind: 'failed'; readonly message: string };

interface ResourceServer {
  readonly identifier: string;
  readonly scopes: readonly string[] | null;
}

type ResourceCheck =
  | { readonly kind: 'unavailable' }
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly items: readonly ResourceServer[] }
  | { readonly kind: 'failed' };

const READ_SCOPE = 'admin.scim:read';
const WRITE_SCOPE = 'admin.scim:write';

/** These routes are tenant relative, just like console API requests. */
function scimUrls(): { readonly base: string; readonly audience: string } {
  return {
    base: new URL('api/v1/scim/v2', document.baseURI).href,
    audience: new URL('api/v1', document.baseURI).href,
  };
}

function scopeSet(client: ClientDocument): ReadonlySet<string> {
  return new Set(client.scope.split(/\s+/).filter(Boolean));
}

export function ScimProvisioning({ session }: Readonly<{ session: Session }>): JSX.Element {
  const [inventory, setInventory] = useState<Inventory>({ kind: 'loading' });
  const [inspection, setInspection] = useState<Inspection>({ kind: 'idle' });
  const [query, setQuery] = useState('');
  const [selectedId, setSelectedId] = useState('');
  const [resources, setResources] = useState<ResourceCheck>({ kind: 'unavailable' });
  const urls = scimUrls();

  const loadClients = useCallback((term: string) => {
    setInventory({ kind: 'loading' });
    const path = term.trim() === '' ? 'clients' : `clients?q=${encodeURIComponent(term.trim())}`;
    read(path).then(
      (body) => setInventory({ kind: 'ready', page: body as ClientPage }),
      (error: unknown) => setInventory({
        kind: 'failed',
        message: error instanceof Error ? error.message : 'Client registrations could not be read.',
      }),
    );
  }, []);

  useEffect(() => loadClients(''), [loadClients]);

  useEffect(() => {
    if (!session.scopes.includes('admin.resource_servers:read')) return;
    let active = true;
    setResources({ kind: 'loading' });
    read('resource-servers').then(
      (body) => { if (active) setResources({ kind: 'ready', items: (body as { items: readonly ResourceServer[] }).items }); },
      () => { if (active) setResources({ kind: 'failed' }); },
    );
    return () => { active = false; };
  }, [session.scopes]);

  const inspect = useCallback((id: string) => {
    setSelectedId(id);
    setInspection({ kind: 'loading' });
    read(`clients/${encodeURIComponent(id)}`).then(
      (body) => setInspection({ kind: 'ready', client: body as ClientDocument }),
      (error: unknown) => setInspection({
        kind: 'failed',
        message: error instanceof Error ? error.message : 'The client could not be read.',
      }),
    );
  }, []);

  const selected = inspection.kind === 'ready' ? inspection.client : null;
  const scopes = selected === null ? new Set<string>() : scopeSet(selected);
  const grantReady = selected?.grant_types.includes('client_credentials') ?? false;
  const readReady = scopes.has(READ_SCOPE);
  const writeReady = scopes.has(WRITE_SCOPE);
  const dpopReady = selected?.dpop_bound_access_tokens === true;
  const audienceReady = selected?.resources.includes(urls.audience) ?? false;
  const audience = resources.kind === 'ready'
    ? resources.items.find((item) => item.identifier === urls.audience)
    : undefined;
  const resourceReady = audience !== undefined
    && (audience.scopes === null || (audience.scopes.includes(READ_SCOPE) && audience.scopes.includes(WRITE_SCOPE)));
  const active = selected?.status === 'active';
  const authenticated = selected !== null && selected.token_endpoint_auth_method !== 'none';
  const ready = active && authenticated && grantReady && dpopReady && audienceReady && readReady && writeReady && resourceReady;

  return (
    <Screen title="SCIM provisioning" description={`Configure an automation client for tenant ${session.workspace}. The provisioning API accepts client credentials tokens and DPoP proofs.`}>
      <Panel title="Connection values" description="Give these values to the external identity provider. Use the token endpoint from this tenant's discovery document.">
        <ConnectionDocument entries={[
          { label: 'SCIM base URL', value: urls.base, description: 'Users and groups provisioning endpoint.' },
          { label: 'Token resource audience', value: urls.audience, description: 'Request this resource when obtaining an access token.' },
          { label: 'Read scope', value: READ_SCOPE },
          { label: 'Write scope', value: WRITE_SCOPE },
        ]} />
        <p className="muted">The client must request a token with <code>grant_type=client_credentials</code>, <code>resource</code> set to the admin API audience, and the required scopes. It must send a DPoP proof with every SCIM request.</p>
      </Panel>

      <Panel title="Provisioning client" description="Inspect a registered application. This checks its stored configuration; it does not issue a token or call the SCIM endpoint.">
        <div className="directory-toolbar"><DirectorySearch label="Find application" value={query} placeholder="Name or client ID" onChange={setQuery} onSubmit={() => loadClients(query)} actionLabel="Search applications" /></div>
        {inventory.kind === 'loading' && <Skeleton label="Loading applications" />}
        {inventory.kind === 'failed' && <LoadFailure message={inventory.message} onRetry={() => loadClients(query)} />}
        {inventory.kind === 'ready' && inventory.page.items.length === 0 && (
          <EmptyState title="No matching applications" body="Register a client in Applications or search by another name." />
        )}
        {inventory.kind === 'ready' && inventory.page.items.length > 0 && <>
          <Field label="Application">{props => <FormSelect {...props} value={selectedId} onValueChange={value => value === '' ? (setSelectedId(''), setInspection({ kind: 'idle' })) : inspect(value)} options={[{ value: '', label: 'Choose an application' }, ...inventory.page.items.map(client => ({ value: client.client_id, label: `${client.client_name} (${client.client_id})` }))]} />}</Field>
          {inventory.page.next_cursor !== null && <p className="muted">More applications exist. Search by name or client ID to find one outside this page.</p>}
        </>}
        {inspection.kind === 'loading' && <Skeleton label="Checking client registration" />}
        {inspection.kind === 'failed' && <LoadFailure message={inspection.message} onRetry={() => inspect(selectedId)} />}
        {selected !== null && <>
          <p role="status"><Badge tone={ready ? 'ok' : 'warn'}>{ready ? 'Configuration checks pass' : 'Configuration needs review'}</Badge> <strong>{selected.client_name}</strong> <code>{selected.client_id}</code></p>
          <ul>
            <li>{active ? '✓' : 'Needs change:'} client is active</li>
            <li>{authenticated ? '✓' : 'Needs change:'} client authentication is configured ({selected.token_endpoint_auth_method})</li>
            <li>{grantReady ? '✓' : 'Needs change:'} client credentials grant is enabled</li>
            <li>{dpopReady ? '✓' : 'Needs change:'} DPoP-bound access tokens are required</li>
            <li>{audienceReady ? '✓' : 'Needs change:'} admin API audience is in the client resource allow-list</li>
            <li>{resources.kind === 'ready' ? resourceReady ? '✓' : 'Needs change:' : 'Not checked:'} admin API audience is registered as a resource server allowing both SCIM scopes</li>
            <li>{readReady ? '✓' : 'Needs change:'} <code>{READ_SCOPE}</code> is registered</li>
            <li>{writeReady ? '✓' : 'Needs change:'} <code>{WRITE_SCOPE}</code> is registered</li>
          </ul>
          {resources.kind !== 'ready' && <p className="muted">Resource server registration could not be checked with this session. Confirm the audience and both SCIM scopes in Resource servers.</p>}
        </>}
        <p><a href={hrefOf('clients')}>Open Applications to register or edit the client</a></p>
        <p><a href={hrefOf('resources')}>Open Resource servers to register the admin API audience</a></p>
      </Panel>

      <Panel title="Supported operations" description="This service provides Users and Groups with conditional updates and offset pagination.">
        <p>SCIM <code>GET</code>, <code>POST</code>, <code>PUT</code>, <code>PATCH</code> and <code>DELETE</code> are available for Users and Groups. Read and write use separate scopes. Bulk, cursor pagination, sorting and password changes are unavailable.</p>
        <p className="muted">The protected <code>ServiceProviderConfig</code>, <code>Schemas</code> and <code>ResourceTypes</code> routes give clients the authoritative capability document after authentication.</p>
      </Panel>
    </Screen>
  );
}
