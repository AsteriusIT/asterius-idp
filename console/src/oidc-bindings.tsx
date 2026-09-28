import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { mutate, read, type Session } from './api';
import { Button, ConfirmDialog, Field, LoadFailure, Panel, Skeleton } from './ui';

interface Binding {
  readonly provider_id: string;
  readonly issuer: string;
  readonly upstream_subject: string;
  readonly created_at: string;
}

export function OidcBindings({ session, userId }: Readonly<{ session: Session; userId: string }>): JSX.Element | null {
  const canRead = session.scopes.includes('admin.users:read');
  const canWrite = session.scopes.includes('admin.users:write');
  const path = `users/${encodeURIComponent(userId)}/oidc-bindings`;
  const [rows, setRows] = useState<readonly Binding[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [providerId, setProviderId] = useState('');
  const [issuer, setIssuer] = useState('');
  const [subject, setSubject] = useState('');
  const [removing, setRemoving] = useState<Binding | null>(null);
  const [busy, setBusy] = useState(false);
  const refresh = useCallback(() => {
    if (!canRead) return;
    read(path).then(
      value => { setRows((value as { bindings: Binding[] }).bindings); setError(null); },
      cause => setError(cause instanceof Error ? cause.message : 'Could not read linked identities'),
    );
  }, [canRead, path]);
  useEffect(refresh, [refresh]);
  if (!canRead) return null;
  const link = (): void => {
    setBusy(true);
    mutate(path, 'PUT', session, { provider_id: providerId.trim(), issuer: issuer.trim(), upstream_subject: subject })
      .then(() => { setBusy(false); setProviderId(''); setIssuer(''); setSubject(''); refresh(); },
        cause => { setBusy(false); setError(cause instanceof Error ? cause.message : 'Could not link identity'); });
  };
  const unlink = (): void => {
    if (removing === null) return;
    setBusy(true);
    mutate(path, 'DELETE', session, removing)
      .then(() => { setBusy(false); setRemoving(null); refresh(); },
        cause => { setBusy(false); setRemoving(null); setError(cause instanceof Error ? cause.message : 'Could not unlink identity'); });
  };
  return <Panel title="Linked sign-in identities" description="Exact provider issuer and subject bindings. Email addresses never link accounts automatically.">
    {error !== null && <LoadFailure message={error} onRetry={refresh} />}
    {rows === null && error === null && <Skeleton rows={2} label="Reading linked identities." />}
    {rows?.length === 0 && <p className="muted">No upstream identities are linked to this account.</p>}
    {rows?.map(row => <div key={`${row.provider_id}:${row.issuer}:${row.upstream_subject}`} className="flex flex-wrap gap-2 items-center">
      <strong>{row.provider_id}</strong><code>{row.issuer}</code><code>{row.upstream_subject}</code>
      {canWrite && <Button small variant="danger" disabled={busy} onClick={() => setRemoving(row)}>Unlink</Button>}
    </div>)}
    {canWrite && <fieldset disabled={busy} className="flex flex-col gap-2">
      <legend>Link an operator-confirmed upstream identity</legend>
      <p className="muted">Confirm the exact issuer and subject in a trusted provider record before linking. Never use an email address as the subject.</p>
      <Field label="Provider ID">{props => <input {...props} value={providerId} onChange={event => setProviderId(event.target.value)} />}</Field>
      <Field label="Exact issuer URL">{props => <input {...props} value={issuer} onChange={event => setIssuer(event.target.value)} />}</Field>
      <Field label="Exact upstream subject">{props => <input {...props} value={subject} onChange={event => setSubject(event.target.value)} />}</Field>
      <Button onClick={link} disabled={!providerId.trim() || !issuer.trim() || !subject || busy}>Link identity</Button>
    </fieldset>}
    {removing !== null && <ConfirmDialog title="Unlink this identity?" body="This upstream identity will no longer sign in to this account." confirmLabel="Unlink identity" busy={busy} onConfirm={unlink} onCancel={() => setRemoving(null)} />}
  </Panel>;
}
