import { useCallback, useEffect, useRef, useState } from 'react';
import type { JSX } from 'react';
import { mutate, read, type Session } from './api';
import { userIdForUsername } from './user-lookup';
import type { Directory } from './users';
import { useDialogDraft } from './dialog-draft';
import { activationDuration, boundedReason, approverUsernames, eligibilityInterval, entitlementDeadline } from './temporary-entitlement-model';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from './components/ui/dialog';
import { FormSelect } from './components/ui/select';
import { Actions, Badge, Button, ConfirmDialog, DataTable, Field, LoadFailure, Message, Panel, Screen, Skeleton } from './ui';

// Reuse the console's Geist type, white surface, zinc text/borders, indigo action
// and restrained warning/danger tones. The permission tuple and its expiry lead
// the detail view; changes stay in labelled dialogs beside the existing table.
interface Entitlement {
  readonly entitlement_id: string;
  readonly owner_user_id: string;
  readonly revision: string;
  readonly client_id: string;
  readonly resource: string;
  readonly role_name: string;
  readonly permissions: readonly string[];
  readonly approver_user_ids: readonly string[];
  readonly requester_acr: string;
  readonly approver_acr: string;
  readonly max_duration_seconds: number;
  readonly max_eligibility_seconds: number;
  readonly enabled: boolean;
}
interface Eligibility {
  readonly eligibility_id: string;
  readonly revision: string;
  readonly user_id: string;
  readonly not_before: number;
  readonly expires_at: number;
  readonly revoked_at: number | null;
}
interface Activation {
  readonly activation_id: string;
  readonly user_id: string;
  readonly expires_at: number;
  readonly revoked_at: number | null;
  readonly status: string;
}
interface Request {
  readonly request_id: string;
  readonly requester_user_id: string;
  readonly role_name: string;
  readonly permissions: readonly string[];
  readonly duration_seconds: number;
  readonly reason: string;
  readonly deadline: number;
  readonly status: string;
}
interface Draft {
  client: string; resource: string; role: string; permissions: string;
  approvers: string; requesterAcr: string; approverAcr: string;
  minutes: string; eligibilityDays: string;
}
const emptyDraft = (): Draft => ({ client: '', resource: '', role: '', permissions: '', approvers: '', requesterAcr: 'urn:asterius:acr:pwd', approverAcr: 'phr', minutes: '15', eligibilityDays: '1' });
const pathOf = (item: Entitlement): string => `temporary-entitlements/${encodeURIComponent(item.entitlement_id)}`;
const failure = (error: unknown): string => error instanceof Error ? error.message : 'The change could not be saved. Try again.';

export function TemporaryEntitlements({ session }: Readonly<{ session: Session }>): JSX.Element {
  const [items, setItems] = useState<readonly Entitlement[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Entitlement | null>(null);
  const [detail, setDetail] = useState<{ eligibility: readonly Eligibility[]; requests: readonly Request[]; activations: readonly Activation[] } | null>(null);
  const detailGeneration = useRef(0);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [draft, setDraft] = useState<Draft>(emptyDraft);
  const [creating, setCreating] = useState(false);
  const [eligibilityOpen, setEligibilityOpen] = useState(false);
  const [username, setUsername] = useState('');
  const [start, setStart] = useState('');
  const [end, setEnd] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<{ item: Entitlement; enabled: boolean } | null>(null);
  const [withdrawing, setWithdrawing] = useState<Eligibility | null>(null);
  const [revoking, setRevoking] = useState<{ activation: Activation; key: string } | null>(null);
  const [revokeReason, setRevokeReason] = useState('');
  const [clients, setClients] = useState<readonly { client_id: string; client_name?: string }[]>([]);
  const [resources, setResources] = useState<readonly { identifier: string; scopes: readonly string[] | null }[]>([]);
  const [roles, setRoles] = useState<readonly { name: string }[]>([]);
  const mayWrite = session.scopes.includes('admin.app_roles:write');
  const mayLookup = session.scopes.includes('admin.users:read');
  const closeCreate = useCallback(() => { setCreating(false); setError(null); }, []);
  const closeEligibility = useCallback(() => { setEligibilityOpen(false); setError(null); }, []);
  const closeRevoke = useCallback(() => { setRevoking(null); setError(null); }, []);
  const createGuard = useDialogDraft(creating && JSON.stringify(draft) !== JSON.stringify(emptyDraft()), busy, closeCreate);
  const eligibilityGuard = useDialogDraft(eligibilityOpen && Boolean(username || start || end), busy, closeEligibility);
  const revokeGuard = useDialogDraft(revoking !== null && Boolean(revokeReason), busy, closeRevoke);
  const refresh = useCallback(() => {
    setLoadError(null);
    read('temporary-entitlements').then(value => setItems((value as { items: readonly Entitlement[] }).items), reason => setLoadError(failure(reason)));
  }, []);
  useEffect(refresh, [refresh]);
  useEffect(() => {
    if (!creating) return;
    Promise.all([read('clients?limit=100'), read('resource-servers')]).then(([applications, registered]) => {
      setClients((applications as { items: typeof clients }).items);
      setResources((registered as { items: typeof resources }).items);
    }, reason => setError(failure(reason)));
  }, [creating]);
  useEffect(() => {
    setRoles([]);
    if (!draft.client || !creating) return;
    let current = true;
    read(`clients/${encodeURIComponent(draft.client)}/app-roles`).then(value => {
      if (current) setRoles((value as { roles: typeof roles }).roles);
    }, reason => { if (current) setError(failure(reason)); });
    return () => { current = false; };
  }, [draft.client, creating]);
  const loadDetail = useCallback((item: Entitlement) => {
    const generation = ++detailGeneration.current;
    setSelected(item); setDetail(null); setDetailError(null);
    const path = pathOf(item);
    Promise.all([read(`${path}/eligibilities`), read(`${path}/requests`), read(`${path}/activations`)]).then(([eligibility, requests, activations]) => { if (generation !== detailGeneration.current) return; setDetail({
      eligibility: (eligibility as { items: readonly Eligibility[] }).items,
      requests: (requests as { items: readonly Request[] }).items,
      activations: (activations as { items: readonly Activation[] }).items,
    }); }, reason => { if (generation === detailGeneration.current) setDetailError(failure(reason)); });
  }, []);
  const set = (key: keyof Draft, value: string): void => setDraft(current => ({ ...current, [key]: value }));
  async function userId(name: string): Promise<string> {
    const id = await userIdForUsername(name, path => read(path) as Promise<Directory>);
    if (id === null) throw new Error(`No account matches the exact username ${name}.`);
    return id;
  }
  async function create(): Promise<void> {
    setBusy(true); setError(null);
    try {
      const approvers = approverUsernames(draft.approvers);
      const days = Number(draft.eligibilityDays);
      if (!Number.isInteger(days) || days < 1 || days > 30) throw new Error('Choose an eligibility maximum from 1 to 30 days.');
      const ids = await Promise.all(approvers.map(userId));
      if (new Set(ids).size !== ids.length) throw new Error('Approvers must be different accounts.');
      const saved = await mutate('temporary-entitlements', 'POST', session, {
        owner_user_id: session.user, client_id: draft.client, resource: draft.resource, role_name: draft.role,
        permissions: draft.permissions.split(/\s+/).filter(Boolean), approver_user_ids: ids,
        requester_acr: draft.requesterAcr, approver_acr: draft.approverAcr,
        max_duration_seconds: activationDuration(draft.minutes), max_eligibility_seconds: days * 86400, enabled: false,
      }) as Entitlement;
      closeCreate(); setNotice('Entitlement created disabled. Add eligibility and enable it when the approval policy is ready.'); refresh(); loadDetail(saved);
    } catch (reason) { setError(failure(reason)); } finally { setBusy(false); }
  }
  async function configure(): Promise<void> {
    if (confirm === null) return;
    setBusy(true); setError(null);
    try {
      const { item, enabled } = confirm;
      const saved = await mutate(pathOf(item), 'PUT', session, {
        owner_user_id: item.owner_user_id, client_id: item.client_id, resource: item.resource,
        role_name: item.role_name, permissions: item.permissions, approver_user_ids: item.approver_user_ids,
        requester_acr: item.requester_acr, approver_acr: item.approver_acr,
        max_duration_seconds: item.max_duration_seconds, max_eligibility_seconds: item.max_eligibility_seconds,
        enabled, expected_revision: item.revision,
      }) as Entitlement;
      setConfirm(null); setNotice(enabled ? 'Entitlement enabled.' : 'Entitlement disabled. Current activations no longer supply this role.'); refresh(); loadDetail(saved);
    } catch (reason) { setError(failure(reason)); } finally { setBusy(false); }
  }
  async function grantEligibility(): Promise<void> {
    if (selected === null) return;
    setBusy(true); setError(null);
    try {
      await mutate(`${pathOf(selected)}/eligibilities`, 'POST', session, { user_id: await userId(username), ...eligibilityInterval(start, end), expected_revision: null });
      closeEligibility(); setNotice('Eligibility granted. The account still needs an independent approval to activate the role.'); loadDetail(selected);
    } catch (reason) { setError(failure(reason)); } finally { setBusy(false); }
  }
  async function removeEligibility(): Promise<void> {
    if (selected === null || withdrawing === null) return;
    setBusy(true); setError(null);
    try {
      await mutate(`${pathOf(selected)}/eligibilities/${encodeURIComponent(withdrawing.eligibility_id)}`, 'DELETE', session, { expected_revision: withdrawing.revision });
      setWithdrawing(null); setNotice('Eligibility removed. Further activation and privileged issuance are refused.'); loadDetail(selected);
    } catch (reason) { setError(failure(reason)); } finally { setBusy(false); }
  }
  async function revokeActivation(): Promise<void> {
    if (selected === null || revoking === null) return;
    setBusy(true); setError(null);
    try {
      await mutate(`${pathOf(selected)}/activations/${encodeURIComponent(revoking.activation.activation_id)}/revoke`, 'POST', session, {
        activation_id: revoking.activation.activation_id, reason: boundedReason(revokeReason), idempotency_key: revoking.key,
      });
      setRevoking(null); setNotice('Activation revoked. Online access and new privileged issuance now refuse this activation.'); loadDetail(selected);
    } catch (reason) { setError(failure(reason)); } finally { setBusy(false); }
  }
  return <Screen title="Temporary privileges" description="Eligible accounts request a bounded role; an independent approver authorizes each activation."
    actions={<Actions><a className="text-link" href="../account/entitlements">My requests and approvals</a>{mayWrite && <Button onClick={() => { setDraft(emptyDraft()); setError(null); setCreating(true); }} disabled={!mayLookup}>Create entitlement</Button>}</Actions>}>
    {notice && <Message tone="success">{notice}</Message>}{error && !creating && !eligibilityOpen && <Message tone="error">{error}</Message>}
    {loadError ? <LoadFailure message={loadError} onRetry={refresh} /> : items === null ? <Skeleton label="Loading temporary privilege records" /> : <DataTable caption="Temporary entitlement policies" rows={items} rowKey={item => item.entitlement_id}
      empty={mayWrite ? "No temporary entitlements are configured for your account. Create one with a role, resource and independent approvers." : "No temporary entitlements are owned by your account."}
      columns={[
        { key: 'role', header: 'Role', cell: item => <button className="text-link" onClick={() => loadDetail(item)}>{item.role_name}</button> },
        { key: 'client', header: 'Application', cell: item => item.client_id },
        { key: 'resource', header: 'Resource', cell: item => <span className="break-all">{item.resource}</span> },
        { key: 'duration', header: 'Maximum activation', cell: item => `${item.max_duration_seconds / 60} ${item.max_duration_seconds === 60 ? 'minute' : 'minutes'}` },
        { key: 'state', header: 'Policy', cell: item => <Badge tone={item.enabled ? 'ok' : 'neutral'}>{item.enabled ? 'Enabled' : 'Disabled'}</Badge> },
      ]} />}
    {selected && <Panel title={`${selected.role_name} · ${selected.client_id}`} actions={<Actions><Button onClick={() => loadDetail(selected)} disabled={busy}>Refresh details</Button>{mayWrite && selected.owner_user_id === session.user && <Button onClick={() => { setUsername(''); setStart(''); setEnd(''); setError(null); setEligibilityOpen(true); }} disabled={busy || !mayLookup}>Grant eligibility</Button>}{mayWrite && selected.owner_user_id === session.user && <Button onClick={() => { setError(null); setConfirm({ item: selected, enabled: !selected.enabled }); }} disabled={busy}>{selected.enabled ? 'Disable entitlement' : 'Enable entitlement'}</Button>}</Actions>}>
      <p className="break-all">Resource: {selected.resource}</p><p>Permissions: {selected.permissions.join(' ')}</p>
      <p className="muted">Eligibility permits a request. Standing role assignments keep their existing authority. Issued tokens remain usable until their capped expiry unless the resource checks current access.</p>
      {detailError ? <LoadFailure message={detailError} onRetry={() => loadDetail(selected)} /> : detail === null ? <Skeleton label="Loading temporary privilege records" /> : <>
        <section className="mt-6" aria-label="Eligibility">{detail.eligibility.length === 0 && <h3 className="mb-2 font-medium">Eligibility</h3>}
        <DataTable caption="Eligibility" rows={detail.eligibility} rowKey={row => row.eligibility_id} empty="No accounts are eligible for this entitlement." columns={[
          { key: 'user', header: 'Account ID', cell: row => <span className="break-all">{row.user_id}</span> },
          { key: 'from', header: 'From', cell: row => entitlementDeadline(row.not_before) },
          { key: 'until', header: 'Until', cell: row => entitlementDeadline(row.expires_at) },
          { key: 'state', header: 'State', cell: row => row.revoked_at === null ? 'Eligibility recorded' : 'Removed' },
          { key: 'actions', header: 'Actions', actions: true, cell: row => mayWrite && selected.owner_user_id === session.user && row.revoked_at === null && <Button onClick={() => { setError(null); setWithdrawing(row); }}>Remove eligibility</Button> },
        ]} /></section>
        <section className="mt-6" aria-label="Requests">{detail.requests.length === 0 && <h3 className="mb-2 font-medium">Requests</h3>}
        <DataTable caption="Requests" rows={detail.requests} rowKey={row => row.request_id} empty="No activation requests." columns={[
          { key: 'who', header: 'Requester ID', cell: row => <span className="break-all">{row.requester_user_id}</span> },
          { key: 'reason', header: 'Reason', cell: row => row.reason },
          { key: 'duration', header: 'Requested duration', cell: row => `${row.duration_seconds / 60} ${row.duration_seconds === 60 ? 'minute' : 'minutes'}` },
          { key: 'deadline', header: 'Decision deadline', cell: row => entitlementDeadline(row.deadline) },
          { key: 'status', header: 'State', cell: row => row.status },
        ]} /></section>
        <section className="mt-6" aria-label="Activations">{detail.activations.length === 0 && <h3 className="mb-2 font-medium">Activations</h3>}
        <DataTable caption="Activations" rows={detail.activations} rowKey={row => row.activation_id} empty="No approved activations." columns={[
          { key: 'who', header: 'Account ID', cell: row => <span className="break-all">{row.user_id}</span> },
          { key: 'end', header: 'Exclusive expiry', cell: row => entitlementDeadline(row.expires_at) },
          { key: 'status', header: 'State', cell: row => row.status },
          { key: 'actions', header: 'Actions', actions: true, cell: row => mayWrite && selected.owner_user_id === session.user && row.revoked_at === null && row.status === 'active' && <Button onClick={() => { setError(null); setRevokeReason(''); setRevoking({ activation: row, key: crypto.randomUUID() }); }}>Revoke activation</Button> },
        ]} /></section>
      </>}
    </Panel>}
    {creating && <Dialog open onOpenChange={open => { if (!open) createGuard.requestClose(); }}><DialogContent><DialogHeader><DialogTitle>Create temporary entitlement</DialogTitle><DialogDescription>You own this policy. Creation grants no role; eligibility and independent approval remain required.</DialogDescription></DialogHeader>
      <form onSubmit={event => { event.preventDefault(); void create(); }}>
        {error && <Message tone="error">{error}</Message>}{createGuard.confirmation}
        <Field label="Application" required>{props => <FormSelect {...props} value={draft.client} onValueChange={value => { set('client', value); set('role', ''); }} options={[{ value: '', label: 'Choose an application' }, ...clients.map(client => ({ value: client.client_id, label: client.client_name || client.client_id }))]} />}</Field>
        <Field label="Client role" required>{props => <FormSelect {...props} value={draft.role} onValueChange={value => set('role', value)} options={[{ value: '', label: 'Choose an existing role' }, ...roles.map(role => ({ value: role.name, label: role.name }))]} />}</Field>
        <Field label="Resource" required>{props => <FormSelect {...props} value={draft.resource} onValueChange={value => set('resource', value)} options={[{ value: '', label: 'Choose a registered resource' }, ...resources.map(resource => ({ value: resource.identifier, label: resource.identifier }))]} />}</Field>
        <Field label="Required granted permissions" hint="Space-separated scopes already registered for this resource." required>{props => <input {...props} value={draft.permissions} onChange={event => set('permissions', event.target.value)} />}</Field>
        <Field label="Independent approver usernames" hint="One exact username per line. Configuration and eligibility editors cannot approve requests enabled by their edit." required>{props => <textarea {...props} value={draft.approvers} onChange={event => set('approvers', event.target.value)} />}</Field>
        <Field label="Requester assurance" required>{props => <input {...props} value={draft.requesterAcr} onChange={event => set('requesterAcr', event.target.value)} />}</Field>
        <Field label="Approver assurance" required>{props => <input {...props} value={draft.approverAcr} onChange={event => set('approverAcr', event.target.value)} />}</Field>
        <Field label="Maximum activation in minutes" required>{props => <input {...props} type="number" min="1" max="60" step="1" value={draft.minutes} onChange={event => set('minutes', event.target.value)} />}</Field>
        <Field label="Maximum eligibility in days" required>{props => <input {...props} type="number" min="1" max="30" step="1" value={draft.eligibilityDays} onChange={event => set('eligibilityDays', event.target.value)} />}</Field>
        <Actions><Button type="button" onClick={createGuard.requestClose} disabled={busy}>Cancel</Button><Button type="submit" disabled={busy}>{busy ? 'Creating…' : 'Create disabled entitlement'}</Button></Actions>
      </form>
    </DialogContent></Dialog>}
    {eligibilityOpen && <Dialog open onOpenChange={open => { if (!open) eligibilityGuard.requestClose(); }}><DialogContent><DialogHeader><DialogTitle>Grant eligibility</DialogTitle><DialogDescription>Choose who may request this fixed role and the interval in which they are eligible.</DialogDescription></DialogHeader><form onSubmit={event => { event.preventDefault(); void grantEligibility(); }}>
      {error && <Message tone="error">{error}</Message>}{eligibilityGuard.confirmation}
      <Field label="Exact account username" required>{props => <input {...props} value={username} onChange={event => setUsername(event.target.value)} />}</Field>
      <Field label="Eligible from" hint="Times use your browser's local time zone." required>{props => <input {...props} type="datetime-local" value={start} onChange={event => setStart(event.target.value)} />}</Field>
      <Field label="Eligible until" required>{props => <input {...props} type="datetime-local" value={end} onChange={event => setEnd(event.target.value)} />}</Field>
      <Actions><Button type="button" onClick={eligibilityGuard.requestClose} disabled={busy}>Cancel</Button><Button type="submit" disabled={busy}>{busy ? 'Granting…' : 'Grant eligibility'}</Button></Actions>
    </form></DialogContent></Dialog>}
    {confirm && <ConfirmDialog title={confirm.enabled ? 'Enable entitlement?' : 'Disable entitlement?'} body={confirm.enabled ? 'Eligible accounts may request independent approval for this fixed role.' : 'Live activations stop supplying the role on the next online decision or issuance. Issued offline tokens expire at their recorded deadline.'} confirmLabel={confirm.enabled ? 'Enable entitlement' : 'Disable entitlement'} busy={busy} onConfirm={() => void configure()} onCancel={() => setConfirm(null)} />}
    {withdrawing && <ConfirmDialog title="Remove eligibility?" body="Pending and active privileges based on this eligibility stop authorizing access. Already issued offline tokens retain their capped expiry." confirmLabel="Remove eligibility" busy={busy} onConfirm={() => void removeEligibility()} onCancel={() => setWithdrawing(null)} />}
    {revoking && <Dialog open onOpenChange={open => { if (!open) revokeGuard.requestClose(); }}><DialogContent><DialogHeader><DialogTitle>Revoke activation</DialogTitle><DialogDescription>Online decisions and new tokens stop using this activation. Already issued offline tokens remain valid until their capped expiry.</DialogDescription></DialogHeader><form onSubmit={event => { event.preventDefault(); void revokeActivation(); }}>
      {error && <Message tone="error">{error}</Message>}{revokeGuard.confirmation}
      <Field label="Reason for revocation" required>{props => <textarea {...props} value={revokeReason} onChange={event => setRevokeReason(event.target.value)} />}</Field>
      <Actions><Button type="button" disabled={busy} onClick={revokeGuard.requestClose}>Cancel</Button><Button type="submit" disabled={busy}>{busy ? 'Revoking…' : 'Revoke activation'}</Button></Actions>
    </form></DialogContent></Dialog>}
  </Screen>;
}
