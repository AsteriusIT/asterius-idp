/** Tenant-managed upstream sign-in providers. */
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { mutate, read, type Session } from './api';
import { toast } from './components/ui/toast';
import { providerCommand, draftFor, type OidcProvider, type ProviderDraft } from './oidc-providers-model';
import { Badge, Button, ConfirmDialog, Field, LoadFailure, Message, Panel, Screen, Skeleton } from './ui';

interface Inventory {
  readonly providers: readonly OidcProvider[];
  readonly callback_url_template: string;
}

const EMPTY: ProviderDraft = { id: '', name: '', issuer: '', clientId: '', clientSecret: '', enabled: true, allowRegistration: false };

type Load =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly inventory: Inventory }
  | { readonly kind: 'failed'; readonly message: string };

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'The provider request failed';
}

export function OidcProviders({ session }: Readonly<{ session: Session }>): JSX.Element {
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [draft, setDraft] = useState<ProviderDraft | null>(null);
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState<OidcProvider | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const canWrite = session.scopes.includes('admin.oidc_providers:write');

  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    read('oidc/providers').then(
      (value) => setLoad({ kind: 'ready', inventory: value as Inventory }),
      (cause: unknown) => setLoad({ kind: 'failed', message: errorMessage(cause) }),
    );
  }, []);
  useEffect(refresh, [refresh]);

  const save = (): void => {
    if (draft === null) return;
    if (draft.id.trim() === '' || draft.name.trim() === '' || draft.issuer.trim() === '' || draft.clientId.trim() === '' || (!editing && draft.clientSecret === '')) {
      setError('Complete the provider ID, name, issuer, client ID and initial client secret.');
      return;
    }
    setBusy(true);
    setError(null);
    mutate('oidc/providers', 'PUT', session, providerCommand(draft)).then(
      () => {
        setBusy(false);
        setDraft(null);
        toast.success(editing ? 'Provider updated' : 'Provider added');
        refresh();
      },
      (cause: unknown) => { setBusy(false); setError(errorMessage(cause)); },
    );
  };

  const remove = (): void => {
    if (deleting === null) return;
    setBusy(true);
    setError(null);
    mutate('oidc/providers', 'DELETE', session, { id: deleting.id }).then(
      () => {
        setBusy(false);
        setDeleting(null);
        toast.success('Provider removed');
        refresh();
      },
      (cause: unknown) => { setBusy(false); setDeleting(null); setError(errorMessage(cause)); },
    );
  };

  const ready = load.kind === 'ready' ? load.inventory : null;
  const change = (patch: Partial<ProviderDraft>): void => setDraft((current) => current === null ? null : { ...current, ...patch });

  return <Screen title="Sign-in providers" description="Register external sign-in providers for this tenant. Each provider has its own callback URL.">
    <Message tone="info">Provider setup stores connection details. Users can then sign in through an enabled provider and link their account.</Message>
    {error !== null && <Message tone="error">{error}</Message>}
    <Panel title="External sign-in providers" description="Endpoint metadata is discovered from the exact issuer and checked before it is stored."
      actions={canWrite && draft === null ? <Button variant="primary" onClick={() => { setDraft(EMPTY); setEditing(false); setError(null); }}>Add provider</Button> : undefined}>
      {load.kind === 'loading' && <Skeleton rows={3} label="Reading sign-in providers." />}
      {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
      {ready !== null && (ready.providers.length === 0 ? <p className="muted">No upstream sign-in providers are configured.</p> :
        <div className="overflow-x-auto"><table>
          <caption className="visually-hidden">External sign-in providers</caption>
          <thead><tr><th>Provider</th><th>Issuer</th><th>Status</th><th>Callback URL</th>{canWrite && <th>Actions</th>}</tr></thead>
          <tbody>{ready.providers.map((provider) => <tr key={provider.id}>
            <td><strong>{provider.name}</strong><br /><small>{provider.id}</small></td>
            <td><code>{provider.issuer}</code><br /><small>Client: {provider.client_id}</small></td>
            <td><Badge tone={provider.enabled ? 'ok' : 'neutral'}>{provider.enabled ? 'Enabled' : 'Disabled'}</Badge><br /><small>{provider.secret_configured ? 'Secret configured' : 'Secret needed'}</small><br /><small>{provider.allow_registration ? 'First login creates an account' : 'Existing linked accounts only'}</small></td>
            <td><code className="break-all">{provider.callback_url}</code></td>
            {canWrite && <td><div className="flex flex-wrap gap-2">
              <Button small disabled={busy} onClick={() => { setDraft(draftFor(provider)); setEditing(true); setError(null); }}>Edit</Button>
              <Button small variant="danger" disabled={busy} onClick={() => setDeleting(provider)}>Delete</Button>
            </div></td>}
          </tr>)}</tbody>
        </table></div>)}
    </Panel>
    {draft !== null && canWrite && <Panel title={editing ? `Edit ${draft.name}` : 'Add a provider'} description="Use the issuer URL published by the external provider. The server fetches its discovery document securely.">
      <fieldset disabled={busy} className="flex flex-col gap-3">
        <Field label="Provider ID" required hint="A stable URL-safe name for this provider and its callback path.">{props => <input {...props} value={draft.id} disabled={editing} autoComplete="off" onChange={event => change({ id: event.target.value })} />}</Field>
        <Field label="Display name" required>{props => <input {...props} value={draft.name} onChange={event => change({ name: event.target.value })} />}</Field>
        <Field label="Issuer URL" required hint="Exact HTTPS issuer from the provider's discovery document.">{props => <input {...props} type="url" value={draft.issuer} placeholder="https://login.example.com" onChange={event => change({ issuer: event.target.value })} />}</Field>
        <Field label="Client ID" required hint="Register this tenant as a client at the external provider first.">{props => <input {...props} value={draft.clientId} autoComplete="off" onChange={event => change({ clientId: event.target.value })} />}</Field>
        <Field label={editing ? 'Replace client secret' : 'Client secret'} required={!editing} hint={editing ? 'Leave blank to keep the existing secret. Existing secrets are never shown.' : 'Saved encrypted; it cannot be read back.'}>{props => <input {...props} type="password" value={draft.clientSecret} autoComplete="new-password" onChange={event => change({ clientSecret: event.target.value })} />}</Field>
        <label className="flex items-center gap-2"><input type="checkbox" checked={draft.enabled} onChange={event => change({ enabled: event.target.checked })} /> Enable this provider</label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={draft.allowRegistration} onChange={event => change({ allowRegistration: event.target.checked })} /> Create a new local account on first verified sign-in</label>
        <p className="muted">When off, only explicitly linked identities can sign in. New accounts never inherit an existing account through an email address.</p>
        {ready !== null && <p className="muted">Callback URL: <code className="break-all">{ready.callback_url_template.replace('{id}', draft.id || '{id}')}</code></p>}
        <div className="flex flex-wrap gap-2"><Button variant="primary" onClick={save} disabled={busy}>{busy ? 'Saving…' : 'Save provider'}</Button><Button onClick={() => { setDraft(null); setError(null); }} disabled={busy}>Cancel</Button></div>
      </fieldset>
    </Panel>}
    {deleting !== null && <ConfirmDialog title={`Delete ${deleting.name}?`} body="The provider configuration and stored credential will be removed. Existing sign-in sessions are unaffected." confirmLabel="Delete provider" busy={busy} onConfirm={remove} onCancel={() => setDeleting(null)} />}
  </Screen>;
}
