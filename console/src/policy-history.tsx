import { useEffect, useState } from 'react';
import { mutate, read, type Session } from './api';
import type { PolicyDocument } from './policy';
import { JsonValue } from './components/json-view';
import { Button, ConfirmDialog, LoadFailure, Message, Panel, Skeleton, Timestamp } from './ui';

interface Revision { readonly id: number; readonly policy: PolicyDocument }

export function PolicyHistory({ session, dirty, onRestored }: Readonly<{
  session: Session; dirty: boolean; onRestored: () => void;
}>) {
  const [items, setItems] = useState<readonly Revision[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [retry, setRetry] = useState(0);
  const [selected, setSelected] = useState<Revision | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    setError(null);
    read('policies/history').then(value => {
      if (active) setItems((value as { items: Revision[] }).items);
    }, reason => { if (active) setError(reason instanceof Error ? reason.message : 'History could not be read.'); });
    return () => { active = false; };
  }, [retry]);
  const restore = async () => {
    if (!selected || dirty) return;
    setBusy(true); setError(null);
    try {
      await mutate('policies', 'PUT', session, selected.policy.document);
      setSelected(null); onRestored();
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'The version could not be restored.'); }
    finally { setBusy(false); }
  };
  return <Panel className="policy-history" title="Published versions" description="Saving publishes immediately. The last 100 versions are retained, starting when history was enabled. Restoring a version publishes a new version; it does not erase later history.">
    {error && !selected && <LoadFailure message={error} onRetry={() => setRetry(retry + 1)} />}
    {!items && !error && <Skeleton rows={2} label="Reading policy history." />}
    {items?.length === 0 && <p>No published versions have been recorded yet.</p>}
    {dirty && <p className="muted">Save or discard your editor changes before restoring a version.</p>}
    {items?.map((revision, index) => <details key={revision.id}>
      <summary>Version {revision.id}{index === 0 ? ' · Latest publication' : ''} · {revision.policy.rule_count} rules · {revision.policy.updated_at && <Timestamp value={revision.policy.updated_at} />}</summary>
      <JsonValue value={revision.policy.document} />
      {session.scopes.includes('admin.policies:write') && <Button disabled={busy || dirty} onClick={() => { setError(null); setSelected(revision); }}>Restore version {revision.id}</Button>}
    </details>)}
    {selected && <ConfirmDialog title={`Restore version ${selected.id}?`}
      body={<><p>This immediately replaces the active access policy in {session.workspace}. Access decisions may change. A new version will be recorded.</p>{error && <Message tone="error">{error}</Message>}</>}
      confirmLabel="Restore and publish" busy={busy} onCancel={() => setSelected(null)} onConfirm={() => void restore()} />}
  </Panel>;
}
