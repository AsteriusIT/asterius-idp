import { ConnectionDocument } from './components/connection-document';
import { Command, CommandInput, CommandItem, CommandList } from './components/ui/command';
import { Popover, PopoverContent, PopoverTrigger } from './components/ui/popover';
import { CheckIcon, ChevronsUpDownIcon } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { JSX } from 'react';
import { read, type Session } from './api';
import type { ClientDocument } from './client-draft';
import { hrefOf } from './routes';
import { Badge, Button, LoadFailure, Panel, Screen, Skeleton } from './ui';

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
  const [pickerOpen, setPickerOpen] = useState(false);
  const [selectedId, setSelectedId] = useState('');
  const [selectedName, setSelectedName] = useState('');
  const clientRequest = useRef(0);
  const inspectionRequest = useRef(0);
  const [resources, setResources] = useState<ResourceCheck>({ kind: 'unavailable' });
  const urls = scimUrls();

  const loadClients = useCallback((term: string) => {
    const request = ++clientRequest.current;
    setInventory({ kind: 'loading' });
    const path = term.trim() === '' ? 'clients' : `clients?q=${encodeURIComponent(term.trim())}`;
    read(path).then(
      (body) => { if (request === clientRequest.current) setInventory({ kind: 'ready', page: body as ClientPage }); },
      (error: unknown) => { if (request === clientRequest.current) setInventory({
        kind: 'failed',
        message: error instanceof Error ? error.message : 'Client registrations could not be read.',
      }); },
    );
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => loadClients(query), query === '' ? 0 : 220);
    return () => { window.clearTimeout(timer); clientRequest.current++; };
  }, [loadClients, query]);

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
    const request = ++inspectionRequest.current;
    setSelectedId(id);
    setInspection({ kind: 'loading' });
    read(`clients/${encodeURIComponent(id)}`).then(
      (body) => { if (request === inspectionRequest.current) setInspection({ kind: 'ready', client: body as ClientDocument }); },
      (error: unknown) => { if (request === inspectionRequest.current) setInspection({
        kind: 'failed',
        message: error instanceof Error ? error.message : 'The client could not be read.',
      }); },
    );
  }, []);
  const chooseClient = (client: ClientSummary): void => {
    setSelectedName(client.client_name);
    setPickerOpen(false);
    setQuery('');
    inspect(client.client_id);
  };
  const clearClient = (): void => {
    inspectionRequest.current++;
    setSelectedId('');
    setSelectedName('');
    setInspection({ kind: 'idle' });
    setPickerOpen(false);
  };

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
        <div className="field"><label id="provisioning-client-label">Application</label>
          <Popover open={pickerOpen} onOpenChange={open => { setPickerOpen(open); if (open) setQuery(''); }}>
            <PopoverTrigger asChild><Button variant="secondary" role="combobox" aria-labelledby="provisioning-client-label" aria-expanded={pickerOpen} className="kubernetes-picker-trigger">
              <span>{selectedId === '' ? 'Choose an application' : `${selectedName} (${selectedId})`}</span><ChevronsUpDownIcon aria-hidden="true" />
            </Button></PopoverTrigger>
            <PopoverContent align="start" className="kubernetes-picker-popover"><Command shouldFilter={false}>
              <CommandInput value={query} onValueChange={value => { setQuery(value); setInventory({ kind: 'loading' }); }} placeholder="Search by name or client ID…" aria-label="Search provisioning applications" />
              <CommandList>
                {inventory.kind === 'loading' && <p className="kubernetes-picker-note" role="status">Searching applications…</p>}
                {inventory.kind === 'failed' && <div className="kubernetes-picker-note"><p>{inventory.message}</p><Button small onClick={() => loadClients(query)}>Retry search</Button></div>}
                {inventory.kind === 'ready' && inventory.page.items.length === 0 && <p className="kubernetes-picker-note">No applications match. Try a name or client ID.</p>}
                {inventory.kind === 'ready' && inventory.page.items.map(client => <CommandItem key={client.client_id} value={client.client_id} onSelect={() => chooseClient(client)}>
                  <span className="kubernetes-picker-option"><strong>{client.client_name}</strong><small>{client.client_id}</small></span>
                  {selectedId === client.client_id && <CheckIcon className="ml-auto size-4" aria-hidden="true" />}
                </CommandItem>)}
              </CommandList>
              {(selectedId !== '' || (inventory.kind === 'ready' && inventory.page.next_cursor !== null)) && <div className="kubernetes-picker-footer">
                {inventory.kind === 'ready' && inventory.page.next_cursor !== null && <span className="muted">More results exist. Refine your search.</span>}
                {selectedId !== '' && <Button small variant="ghost" onClick={clearClient}>Clear selection</Button>}
              </div>}
            </Command></PopoverContent>
          </Popover>
        </div>
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
