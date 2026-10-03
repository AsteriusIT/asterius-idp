import { useEffect, useState, useCallback } from 'react';
import type { JSX } from 'react';
import { read, mutate, type Session } from './api';
import { Actions, Button, ConfirmDialog, EmptyState, LoadFailure, Panel, Timestamp } from './ui';
import { JsonValue } from './components/json-view';
import { taskPageQuery, snapshotAge, lineageTree, type LineageTreeNode, type TaskPage, type TaskSnapshot, type TaskIdentity } from './agent-task-model';

/** Current task authority is fetched independently of the historical audit trail. */
export function AgentTaskViewer({ session, onAudit }: Readonly<{ session: Session; onAudit: (task: string) => void }>): JSX.Element {
  const [page, setPage] = useState<TaskPage>();
  const [snapshot, setSnapshot] = useState<TaskSnapshot>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<TaskIdentity>();
  const [clock, setClock] = useState(Date.now());
  const canRevoke = session.scopes.includes('admin.grants:write');
  const loadTasks = useCallback(async (cursor?: string): Promise<void> => {
    setBusy(true); setError('');
    try {
      const next = await read(`agents/tasks${taskPageQuery(cursor)}`) as TaskPage;
      setPage(previous => cursor === undefined ? next : { ...next, items: [...(previous?.items ?? []), ...next.items] });
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Tasks could not be read'); }
    finally { setBusy(false); }
  }, []);
  useEffect(() => { void loadTasks(); }, [loadTasks]);
  useEffect(() => { const timer = window.setInterval(() => setClock(Date.now()), 5_000); return () => window.clearInterval(timer); }, []);
  const inspect = async (task: string, cursor?: string): Promise<void> => {
    setBusy(true); setError('');
    try {
      const next = await read(`agents/tasks/${encodeURIComponent(task)}${taskPageQuery(cursor)}`) as TaskSnapshot;
      // A new page is a new snapshot. Do not merge older authority observations into it.
      setSnapshot(next);
    } catch (cause) { setSnapshot(undefined); setError(cause instanceof Error ? cause.message : 'Task could not be read'); }
    finally { setBusy(false); }
  };
  const revoke = async (): Promise<void> => {
    if (confirm === undefined) return;
    setBusy(true); setError('');
    try {
      await mutate(`users/${encodeURIComponent(confirm.owner_user_id)}/grants/${encodeURIComponent(confirm.root_grant_id)}`, 'DELETE', session);
      const task = confirm.task_id;
      setConfirm(undefined);
      await inspect(task);
      await loadTasks();
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Withdrawal failed'); }
    finally { setBusy(false); }
  };
  return <Panel title="Task authorizations">
    <p className="muted">Current lifecycle and permission ceilings, observed independently of audit history. A request still requires authentication and policy evaluation.</p>
    <Actions><Button disabled={busy} onClick={() => { setSnapshot(undefined); void loadTasks(); }}>Refresh tasks</Button></Actions>
    {error !== '' && <LoadFailure message={error} onRetry={() => { void loadTasks(); }} />}
    {page === undefined ? (error === '' ? <p role="status">Loading task authorizations…</p> : null) : page.items.length === 0 ? <EmptyState title="No task authorizations" body="No tasks are visible in this tenant." /> : <ul>
      {page.items.map(task => <li key={task.task_id}><Button disabled={busy} onClick={() => { void inspect(task.task_id); }}>{task.label}</Button> <span>{task.state.replaceAll('_', ' ')} · revision {task.approval_revision} · expires <Timestamp value={task.expires_at} /></span></li>)}
    </ul>}
    {page?.next_cursor !== null && page?.next_cursor !== undefined && <Button disabled={busy} onClick={() => { void loadTasks(page.next_cursor ?? undefined); }}>More tasks</Button>}
    {snapshot !== undefined && <section aria-label="Task details">
      <h3>{snapshot.task.label}</h3>
      <p role="status">{snapshotAge(snapshot.observed_at, clock)} · observed <Timestamp value={snapshot.observed_at} /> · {snapshot.task.state.replaceAll('_', ' ')}</p>
      <dl><dt>Task</dt><dd>{snapshot.task.task_id}</dd><dt>Root authorization</dt><dd>{snapshot.task.root_grant_id}</dd><dt>Owner identifier</dt><dd>{snapshot.task.owner_user_id}</dd><dt>Initiating client</dt><dd>{snapshot.task.initiating_client_id}</dd><dt>Approval revision</dt><dd>{snapshot.task.approval_revision}</dd><dt>Approved</dt><dd><Timestamp value={snapshot.task.approved_at} /></dd><dt>Approval expires</dt><dd><Timestamp value={snapshot.task.expires_at} /></dd><dt>Withdrawn</dt><dd><Timestamp value={snapshot.task.revoked_at} /></dd></dl>
      <Actions><Button disabled={busy} onClick={() => { void inspect(snapshot.task.task_id); }}>Refresh authority</Button><Button onClick={() => onAudit(snapshot.task.task_id)}>Recorded timeline</Button>{canRevoke && snapshot.task.state === 'active' && <Button disabled={busy} onClick={() => setConfirm(snapshot.task)}>Withdraw task</Button>}</Actions>
      <h4>Approved ceiling</h4><JsonValue value={snapshot.approved_ceiling} />
      <h4>Current issuance ceiling</h4><JsonValue value={snapshot.current_issuance_ceiling} />
      <p>Current grant types: {snapshot.current_grant_types.length === 0 ? 'none' : snapshot.current_grant_types.join(', ')}.</p>
      <p>Maximum new token lifetime: {snapshot.maximum_new_token_ttl_seconds} seconds. Conditional decision: not evaluated for this view.</p>
      <h4>Grant lineage</h4><p className="muted">One bounded page, at most 50 grants and 10 stored ancestry nodes. Each path starts at the root. Recorded constraints describe their ceiling within this task; existing JWTs retain their signed expiry.</p>
      <LineageTree nodes={lineageTree(snapshot.lineage)} />
      {snapshot.next_cursor !== null && <Button disabled={busy} onClick={() => { void inspect(snapshot.task.task_id, snapshot.next_cursor ?? undefined); }}>Next lineage page</Button>}
    </section>}
    {confirm !== undefined && <ConfirmDialog title="Withdraw this task?" body={<><p>Withdraw {confirm.label}, approval revision {confirm.approval_revision}, and its descendants. Online checks and future issuance will refuse them.</p><p>Offline JWT validation can continue until the signed expiry. To shorten an approval, withdraw it and obtain a fresh approval with a shorter lifetime.</p></>} confirmLabel="Withdraw task" busy={busy} onConfirm={() => { void revoke(); }} onCancel={() => setConfirm(undefined)} />}
  </Panel>;
}

function LineageTree({ nodes }: Readonly<{ nodes: readonly LineageTreeNode[] }>): JSX.Element {
  return <ul className="space-y-2 border-l pl-4">{nodes.map(entry => <li key={entry.id}>
    {entry.node === undefined ? <p className="muted">Grant {entry.id} · parent details outside this page</p> : <details>
      <summary>{entry.node.client_id} · depth {entry.node.depth} · {entry.node.state.replaceAll('_', ' ')}</summary>
      <p>Grant {entry.id}</p><p>Expires <Timestamp value={entry.node.expires_at} /> · withdrawn <Timestamp value={entry.node.revoked_at} /></p><h5>Recorded constraints within approval</h5><JsonValue value={entry.node.recorded_ceiling} />
      <h5>Current issuance ceiling</h5><JsonValue value={entry.node.current_issuance_ceiling} />
    </details>}
    {entry.children.length > 0 && <LineageTree nodes={entry.children} />}
  </li>)}</ul>;
}
