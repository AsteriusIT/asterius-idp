import { useCallback, useEffect, useRef, useState } from 'react';
import type { JSX } from 'react';
import { mutate, read, type Session } from './api';
import { Button, ConfirmDialog, Field, LoadFailure, Panel, Skeleton } from './ui';

interface Binding {
  readonly provider_id: string;
  readonly issuer: string;
  readonly upstream_subject: string;
  readonly created_at: string;
}

type IdentityInput = Pick<Binding, 'provider_id' | 'issuer' | 'upstream_subject'>;
type Load =
  | { readonly userId: string; readonly kind: 'loading' }
  | { readonly userId: string; readonly kind: 'ready'; readonly rows: readonly Binding[] }
  | { readonly userId: string; readonly kind: 'failed'; readonly message: string };

export function OidcBindings({ session, userId }: Readonly<{ session: Session; userId: string }>): JSX.Element | null {
  const canRead = session.scopes.includes('admin.users:read');
  const canWrite = session.scopes.includes('admin.users:write');
  const path = `users/${encodeURIComponent(userId)}/oidc-bindings`;
  const [load, setLoad] = useState<Load>({ userId, kind: 'loading' });
  const [actionError, setActionError] = useState<{ userId: string; message: string } | null>(null);
  const [providerId, setProviderId] = useState('');
  const [issuer, setIssuer] = useState('');
  const [subject, setSubject] = useState('');
  const [removing, setRemoving] = useState<Binding | null>(null);
  const [linking, setLinking] = useState<IdentityInput | null>(null);
  const [busy, setBusy] = useState(false);
  const request = useRef(0);
  const currentUser = useRef(userId);
  currentUser.current = userId;
  const refresh = useCallback(() => {
    if (!canRead) return;
    const number = ++request.current;
    setLoad({ userId, kind: 'loading' });
    setActionError(null);
    read(path).then(
      value => { if (number === request.current) setLoad({ userId, kind: 'ready', rows: (value as { bindings: Binding[] }).bindings }); },
      cause => { if (number === request.current) setLoad({ userId, kind: 'failed', message: cause instanceof Error ? cause.message : 'Could not read linked identities' }); },
    );
  }, [canRead, path, userId]);
  useEffect(() => {
    setProviderId(''); setIssuer(''); setSubject(''); setRemoving(null); setLinking(null); setBusy(false);
    refresh();
    return () => { request.current += 1; };
  }, [refresh]);
  if (!canRead) return null;
  const visible = load.userId === userId ? load : { userId, kind: 'loading' } as const;
  const link = (input: IdentityInput): void => {
    setBusy(true);
    mutate(path, 'PUT', session, input)
      .then(() => { if (currentUser.current !== userId) return; setBusy(false); setLinking(null); setProviderId(''); setIssuer(''); setSubject(''); refresh(); },
        cause => { if (currentUser.current !== userId) return; setBusy(false); setLinking(null); setActionError({ userId, message: cause instanceof Error ? cause.message : 'Could not link identity' }); });
  };
  const unlink = (): void => {
    if (removing === null) return;
    setBusy(true);
    const { provider_id, issuer: exactIssuer, upstream_subject } = removing;
    mutate(path, 'DELETE', session, { provider_id, issuer: exactIssuer, upstream_subject })
      .then(() => { if (currentUser.current !== userId) return; setBusy(false); setRemoving(null); refresh(); },
        cause => { if (currentUser.current !== userId) return; setBusy(false); setRemoving(null); setActionError({ userId, message: cause instanceof Error ? cause.message : 'Could not unlink identity' }); });
  };
  return <Panel title="Linked sign-in identities" description="Exact provider issuer and subject bindings. Email addresses never link accounts automatically.">
    {actionError?.userId === userId && <p role="alert" className="message error">{actionError.message}</p>}
    {visible.kind === 'failed' && <LoadFailure message={visible.message} onRetry={refresh} />}
    {visible.kind === 'loading' && <Skeleton rows={2} label="Reading linked identities." />}
    {visible.kind === 'ready' && visible.rows.length === 0 && <p className="muted">No upstream identities are linked to this account.</p>}
    {visible.kind === 'ready' && visible.rows.map(row => <div key={`${row.provider_id}:${row.issuer}:${row.upstream_subject}`} className="flex flex-wrap gap-2 items-center">
      <strong>{row.provider_id}</strong><code>{row.issuer}</code><code>{row.upstream_subject}</code>
      {canWrite && <Button small variant="danger" disabled={busy} onClick={() => setRemoving(row)}>Unlink</Button>}
    </div>)}
    {canWrite && load.userId === userId && <fieldset disabled={busy} className="flex flex-col gap-2">
      <legend>Link an operator-confirmed upstream identity</legend>
      <p className="muted">Confirm the exact issuer and subject in a trusted provider record before linking. Never use an email address as the subject.</p>
      <Field label="Provider ID">{props => <input {...props} value={providerId} onChange={event => setProviderId(event.target.value)} />}</Field>
      <Field label="Exact issuer URL">{props => <input {...props} value={issuer} onChange={event => setIssuer(event.target.value)} />}</Field>
      <Field label="Exact upstream subject">{props => <input {...props} value={subject} onChange={event => setSubject(event.target.value)} />}</Field>
      <Button onClick={() => setLinking({ provider_id: providerId.trim(), issuer: issuer.trim(), upstream_subject: subject })} disabled={!providerId.trim() || !issuer.trim() || !subject || busy}>Link identity</Button>
    </fieldset>}
    {load.userId === userId && linking !== null && <ConfirmDialog title="Link this upstream identity?"
      body={`A person who signs in to ${linking.provider_id} as the exact subject entered here will access this local account. Confirm the issuer and subject against a trusted provider record before continuing.`}
      confirmLabel="Link identity" busy={busy} onConfirm={() => link(linking)} onCancel={() => setLinking(null)} />}
    {load.userId === userId && removing !== null && <ConfirmDialog title="Unlink this identity?" body="This upstream identity will no longer sign in to this account." confirmLabel="Unlink identity" busy={busy} onConfirm={unlink} onCancel={() => setRemoving(null)} />}
  </Panel>;
}
