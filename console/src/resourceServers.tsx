import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { mutate, read, type Session } from './api';
import { audienceError, parseScopes, scopesError } from './resource-server-model';
import { Button, Field, LoadFailure, Message, Panel, Screen, Skeleton } from './ui';

interface ResourceServer {
  readonly identifier: string;
  readonly scopes: readonly string[] | null;
}

type Load = { readonly kind: 'loading' } | { readonly kind: 'failed'; readonly message: string }
  | { readonly kind: 'ready'; readonly items: readonly ResourceServer[] };

export function ResourceServers({ session }: { session: Session }): JSX.Element {
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [audience, setAudience] = useState('');
  const [scopes, setScopes] = useState('');
  const [unrestricted, setUnrestricted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mayWrite = session.scopes.includes('admin.resource_servers:write');

  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    read('resource-servers').then(
      value => setLoad({ kind: 'ready', items: (value as { items: readonly ResourceServer[] }).items }),
      reason => setLoad({ kind: 'failed', message: reason instanceof Error ? reason.message : 'The audiences could not be read.' }),
    );
  }, []);
  useEffect(refresh, [refresh]);

  const save = async (): Promise<void> => {
    const validation = audienceError(audience) ?? (unrestricted ? null : scopesError(scopes));
    if (validation !== null) { setError(validation); return; }
    setBusy(true); setError(null); setNotice(null);
    try {
      await mutate(`resource-servers/${encodeURIComponent(audience)}`, 'PUT', session, {
        scopes: unrestricted ? null : parseScopes(scopes),
      });
      setNotice(`${audience} is registered.`); setAudience(''); setScopes(''); refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'The resource server could not be saved.');
    } finally { setBusy(false); }
  };

  const withdraw = async (identifier: string): Promise<void> => {
    setBusy(true); setError(null); setNotice(null);
    try {
      await mutate(`resource-servers/${encodeURIComponent(identifier)}`, 'DELETE', session);
      setNotice(`${identifier} was withdrawn.`); refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'The resource server could not be withdrawn.');
    } finally { setBusy(false); }
  };

  return <Screen title="Resource servers" description={`Audiences and supported scopes for ${session.workspace}.`}>
    {notice !== null && <Message tone="success">{notice}</Message>}
    {error !== null && <Message tone="error">{error}</Message>}
    {mayWrite && <Panel title="Register or update an audience">
      <Field label="Audience URL">{props => <input {...props} type="url" value={audience} onChange={event => setAudience(event.target.value)} placeholder="https://api.example/" />}</Field>
      <Field label="Supported scopes" hint="Space-separated. Leave empty to support no scopes.">{props => <input {...props} value={scopes} disabled={unrestricted} onChange={event => setScopes(event.target.value)} placeholder="accounts:read accounts:write" />}</Field>
      <label><input type="checkbox" checked={unrestricted} onChange={event => setUnrestricted(event.target.checked)} /> Do not restrict granted scopes</label>
      <Button variant="primary" disabled={busy} onClick={() => void save()}>{busy ? 'Saving…' : 'Save audience'}</Button>
    </Panel>}
    <Panel title="Registered audiences">
      {load.kind === 'loading' && <Skeleton rows={3} label="Reading the resource servers." />}
      {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
      {load.kind === 'ready' && (load.items.length === 0 ? <p className="muted">No resource servers are registered.</p> :
        <table><caption className="visually-hidden">Registered resource servers</caption><thead><tr><th>Audience</th><th>Supported scopes</th>{mayWrite && <th>Actions</th>}</tr></thead>
          <tbody>{load.items.map(item => <tr key={item.identifier}><td><code>{item.identifier}</code></td><td>{item.scopes === null ? 'All granted scopes' : item.scopes.length === 0 ? 'No scopes' : item.scopes.join(' ')}</td>
            {mayWrite && <td><Button small disabled={busy} onClick={() => { setAudience(item.identifier); setScopes(item.scopes?.join(' ') ?? ''); setUnrestricted(item.scopes === null); }}>Edit</Button> <Button small variant="danger" disabled={busy} onClick={() => void withdraw(item.identifier)}>Withdraw</Button></td>}</tr>)}</tbody></table>)}
    </Panel>
  </Screen>;
}
