import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from './components/ui/dialog';
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
  const [editorOpen, setEditorOpen] = useState(false);
  const [discarding, setDiscarding] = useState(false);
  const [editorError, setEditorError] = useState<string | null>(null);
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
    setProviderId(''); setIssuer(''); setSubject(''); setRemoving(null); setLinking(null); setEditorOpen(false); setBusy(false);
    refresh();
    return () => { request.current += 1; };
  }, [refresh]);
  if (!canRead) return null;
  const visible = load.userId === userId ? load : { userId, kind: 'loading' } as const;
  const link = (input: IdentityInput): void => {
    setBusy(true);
    mutate(path, 'PUT', session, input)
      .then(() => { if (currentUser.current !== userId) return; setBusy(false); setLinking(null); setEditorOpen(false); setProviderId(''); setIssuer(''); setSubject(''); refresh(); },
        cause => { if (currentUser.current !== userId) return; setBusy(false); setLinking(null); setEditorError(cause instanceof Error ? cause.message : 'Could not link identity'); });
  };
  const unlink = (): void => {
    if (removing === null) return;
    setBusy(true);
    const { provider_id, issuer: exactIssuer, upstream_subject } = removing;
    mutate(path, 'DELETE', session, { provider_id, issuer: exactIssuer, upstream_subject })
      .then(() => { if (currentUser.current !== userId) return; setBusy(false); setRemoving(null); refresh(); },
        cause => { if (currentUser.current !== userId) return; setBusy(false); setRemoving(null); setActionError({ userId, message: cause instanceof Error ? cause.message : 'Could not unlink identity' }); });
  };
  const requestClose = () => {
    if (busy) return;
    if (providerId || issuer || subject) setDiscarding(true);
    else setEditorOpen(false);
  };
  return <Panel title="Linked sign-in identities" description="Exact provider issuer and subject bindings. Email addresses never link accounts automatically."
    actions={canWrite ? <Button onClick={() => { setEditorError(null); setEditorOpen(true); }}>Link identity</Button> : undefined}>
    {actionError?.userId === userId && <p role="alert" className="message error">{actionError.message}</p>}
    {visible.kind === 'failed' && <LoadFailure message={visible.message} onRetry={refresh} />}
    {visible.kind === 'loading' && <Skeleton rows={2} label="Reading linked identities." />}
    {visible.kind === 'ready' && visible.rows.length === 0 && <p className="muted">No upstream identities are linked to this account.</p>}
    {visible.kind === 'ready' && visible.rows.map(row => <div key={`${row.provider_id}:${row.issuer}:${row.upstream_subject}`} className="flex flex-wrap gap-2 items-center">
      <strong>{row.provider_id}</strong><code>{row.issuer}</code><code>{row.upstream_subject}</code>
      {canWrite && <Button small variant="danger" disabled={busy} onClick={() => setRemoving(row)}>Unlink</Button>}
    </div>)}
    <Dialog open={editorOpen && load.userId === userId} onOpenChange={open => { if (!open) requestClose(); }}>
      <DialogContent showCloseButton={false} aria-describedby="identity-editor-description">
        <DialogHeader><DialogTitle>Link an upstream identity</DialogTitle>
          <DialogDescription id="identity-editor-description">Confirm the exact issuer and subject in a trusted provider record. Never use an email address as the subject.</DialogDescription></DialogHeader>
        {editorError && <p role="alert" className="message error">{editorError}</p>}
        {discarding ? <div className="message warning" role="alert"><p>Discard this identity draft?</p><div className="actions"><Button autoFocus onClick={() => setDiscarding(false)}>Keep editing</Button><Button variant="danger" onClick={() => { setDiscarding(false); setEditorOpen(false); setLinking(null); setProviderId(''); setIssuer(''); setSubject(''); }}>Discard</Button></div></div>
        : linking ? <div className="stack"><p>A person who signs in to <strong>{linking.provider_id}</strong> as this exact subject will access this account.</p><p className="muted">Issuer: {linking.issuer}<br />Subject: {linking.upstream_subject}</p><div className="actions"><Button onClick={() => setLinking(null)} disabled={busy}>Back</Button><Button variant="primary" onClick={() => link(linking)} disabled={busy}>{busy ? 'Linking…' : 'Confirm link'}</Button></div></div>
        : <fieldset disabled={busy} className="flex flex-col gap-2">
          <Field label="Provider ID">{props => <input {...props} value={providerId} onChange={event => setProviderId(event.target.value)} />}</Field>
          <Field label="Exact issuer URL">{props => <input {...props} type="url" value={issuer} onChange={event => setIssuer(event.target.value)} />}</Field>
          <Field label="Exact upstream subject">{props => <input {...props} value={subject} onChange={event => setSubject(event.target.value)} />}</Field>
          <div className="actions"><Button onClick={requestClose}>Cancel</Button><Button variant="primary" onClick={() => setLinking({ provider_id: providerId.trim(), issuer: issuer.trim(), upstream_subject: subject })} disabled={!providerId.trim() || !issuer.trim() || !subject || busy}>Review link</Button></div>
        </fieldset>}
      </DialogContent>
    </Dialog>
    {load.userId === userId && removing !== null && <ConfirmDialog title="Unlink this identity?" body="This upstream identity will no longer sign in to this account." confirmLabel="Unlink identity" busy={busy} onConfirm={unlink} onCancel={() => setRemoving(null)} />}
  </Panel>;
}
