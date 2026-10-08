import { FlowOrigin } from './flow-origin';
import { SecretInput } from './components/secret-input';
import { ProviderHealth } from './provider-health';
import { useUnsavedChanges } from './navigation-guard';
/** Tenant-managed upstream sign-in providers. */
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { mutate, read, type Session } from './api';
import { toast } from './components/ui/toast';
import { providerCommand, draftFor, type OidcProvider, type ProviderDraft } from './oidc-providers-model';
import { Actions, Badge, Button, ConfirmDialog, DataTable, EmptyState, Field, LoadFailure, Message, Panel, Screen, Skeleton } from './ui';

interface Inventory {
  readonly providers: readonly OidcProvider[];
  readonly callback_url_template: string;
}

const EMPTY: ProviderDraft = { id: '', name: '', issuer: '', clientId: '', usernameClaim: '', clientSecret: '', enabled: true, allowRegistration: false };

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
  const [baseline, setBaseline] = useState(JSON.stringify(EMPTY));
  const leave = useUnsavedChanges(draft !== null && JSON.stringify(draft) !== baseline);
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
      (cause: unknown) => { setBusy(false); setError(errorMessage(cause)); },
    );
  };

  const ready = load.kind === 'ready' ? load.inventory : null;
  const change = (patch: Partial<ProviderDraft>): void => setDraft((current) => current === null ? null : { ...current, ...patch });
  const closeEditor = (): void => leave(() => { setDraft(null); setError(null); });
  const openCreate = (): void => { setBaseline(JSON.stringify(EMPTY)); setDraft(EMPTY); setEditing(false); setError(null); };

  if (draft !== null && canWrite) return <Screen
    title={editing ? 'Edit sign-in provider' : 'Add a provider'}
    description="Use the issuer URL published by the external provider. The server fetches its discovery document securely."
    back={{ label: 'Back to sign-in providers', onClick: closeEditor }}
  >
    <Panel title="Connection and sign-in settings" className="max-w-3xl">
      {error !== null && <Message tone="error">{error}</Message>}
      <fieldset disabled={busy} className="editor-fields">
        <Field label="Provider ID" required hint="A stable URL-safe name for this provider and its callback path.">{props => <input {...props} value={draft.id} disabled={editing} autoComplete="off" onChange={event => change({ id: event.target.value })} />}</Field>
        <Field label="Display name" required>{props => <input {...props} value={draft.name} onChange={event => change({ name: event.target.value })} />}</Field>
        <Field label="Issuer URL" required hint="Exact HTTPS issuer from the provider's discovery document.">{props => <input {...props} type="url" value={draft.issuer} placeholder="https://login.example.com" onChange={event => change({ issuer: event.target.value })} />}</Field>
        <Field label="Client ID" required hint="Register this tenant as a client at the external provider first.">{props => <input {...props} value={draft.clientId} autoComplete="off" onChange={event => change({ clientId: event.target.value })} />}</Field>
        <Field label="Username claim" hint="Optional top-level ID token claim. New accounts use it, and linked account usernames sync on every sign-in. A missing or already used name blocks sign-in. Leave blank to keep generated names.">{props => <input {...props} value={draft.usernameClaim} placeholder="preferred_username" autoComplete="off" onChange={event => change({ usernameClaim: event.target.value })} />}</Field>
        <Field label={editing ? 'Replace client secret' : 'Client secret'} required={!editing} hint={editing ? 'Leave blank to keep the existing secret. Existing secrets are never shown.' : 'Saved encrypted; it cannot be read back.'}>{props => <SecretInput {...props} secretLabel={editing ? 'replacement client secret' : 'client secret'} disabled={busy} value={draft.clientSecret} autoComplete="new-password" onChange={event => change({ clientSecret: event.target.value })} />}</Field>
        <label className="flex items-center gap-2"><input type="checkbox" checked={draft.enabled} onChange={event => change({ enabled: event.target.checked })} /> Enable this provider</label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={draft.allowRegistration} onChange={event => change({ allowRegistration: event.target.checked })} /> Create a new local account on first verified sign-in</label>
        <p className="muted">When off, only explicitly linked identities can sign in. New accounts never inherit an existing account through an email address.</p>
        {ready !== null && <p className="muted">Callback URL: <code className="break-all">{ready.callback_url_template.replace('{id}', draft.id || '{id}')}</code></p>}
        <Actions><Button onClick={closeEditor} disabled={busy}>Cancel</Button><Button variant="primary" onClick={save} disabled={busy}>{busy ? 'Saving…' : editing ? 'Save changes' : 'Add provider'}</Button></Actions>
      </fieldset>
    </Panel>
  </Screen>;

  return <Screen title="Sign-in providers" description="Register external sign-in providers for this tenant. Each provider has its own callback URL.">
    <Message tone="info">Provider setup stores connection details. Users can then sign in through an enabled provider and link their account.</Message>
    {error !== null && deleting === null && <Message tone="error">{error}</Message>}
    <Panel title="External sign-in providers" description="Discovery and public keys are checked automatically while this page is visible, once per minute. These checks do not test client credentials or prove sign-in succeeds."
      actions={canWrite ? <Button variant="primary" onClick={openCreate}>Add provider</Button> : undefined}>
      {load.kind === 'loading' && <Skeleton rows={3} label="Reading sign-in providers." />}
      {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
      {ready !== null && <DataTable
        caption="External sign-in providers"
        rows={ready.providers}
        rowKey={provider => provider.id}
        search={{ of: provider => `${provider.name} ${provider.id} ${provider.issuer}`, label: 'Filter loaded sign-in providers' }}
        empty={<EmptyState title="No sign-in providers" body="Add a provider to let people sign in with an external account." action={canWrite ? <Button onClick={openCreate}>Add provider</Button> : undefined} />}
        columns={[
          { key: 'health', header: 'Metadata health', cell: provider => <ProviderHealth id={provider.id} session={session} /> },
          { key: 'provider', header: 'Provider', sortBy: provider => provider.name, cell: provider => <><strong>{provider.name}</strong><br /><small>{provider.id}</small><FlowOrigin session={session} kind="identity_provider" resource={provider.id} /></> },
          { key: 'issuer', header: 'Issuer', cell: provider => <><code>{provider.issuer}</code><br /><small>Client: {provider.client_id}</small><br /><small>Username claim: {provider.username_claim ?? 'Generated name'}</small></> },
          { key: 'status', header: 'Status', sortBy: provider => provider.enabled ? 1 : 0, cell: provider => <><Badge tone={provider.enabled ? 'ok' : 'neutral'}>{provider.enabled ? 'Enabled' : 'Disabled'}</Badge><br /><small>{provider.secret_configured ? 'Secret configured' : 'Secret needed'}</small><br /><small>{provider.allow_registration ? 'First login creates an account' : 'Existing linked accounts only'}</small></> },
          { key: 'callback', header: 'Callback URL', cell: provider => <code className="break-all">{provider.callback_url}</code> },
          ...(canWrite ? [{ key: 'actions', header: 'Actions', actions: true, cell: (provider: OidcProvider) => <div className="flex flex-wrap gap-2">
              <Button small disabled={busy} onClick={() => leave(() => { setBaseline(JSON.stringify(draftFor(provider))); setDraft(draftFor(provider)); setEditing(true); setError(null); })}>Edit</Button>
              <Button small variant="danger" disabled={busy} onClick={() => setDeleting(provider)}>Delete</Button>
            </div> }] : []),
        ]}
      />}
    </Panel>
    {deleting !== null && <ConfirmDialog title={`Delete ${deleting.name}?`} body={<><p>The provider configuration and stored credential will be removed. Existing sign-in sessions are unaffected.</p>{error !== null && <Message tone="error">{error}</Message>}</>} confirmLabel="Delete provider" busy={busy} onConfirm={remove} onCancel={() => { setDeleting(null); setError(null); }} />}
  </Screen>;
}
