import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { mutate, read, type Session } from './api';
import { assignmentsOf, clientCatalogue, TENANT_CATALOGUE, type AppRole, type HeldRoles } from './appRoles';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from './components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';
import { toast } from './components/ui/toast';
import {
  GROUP_MEMBERSHIP_CHANGED_EVENT, groupPath, groupRolesPath, groupRoleWithdrawPath, memberPath,
  type GroupPage, type GroupRow, type MemberPage,
} from './groups-model';
import {
  Actions, Button, ConfirmDialog, DataTable, EmptyState, Field, LoadFailure,
  Message, Panel, Screen, Skeleton,
} from './ui';

const GROUPS_READ = 'admin.groups:read';
const GROUPS_WRITE = 'admin.groups:write';
const MEMBERS_READ = 'admin.memberships:read';
const MEMBERS_WRITE = 'admin.memberships:write';
const ROLES_READ = 'admin.app_roles:read';
const ROLES_WRITE = 'admin.app_roles:write';

type Load<T> = { readonly kind: 'loading' } | { readonly kind: 'ready'; readonly value: T }
  | { readonly kind: 'failed'; readonly message: string };

function failure(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

export function Groups({ session }: Readonly<{ session: Session }>): JSX.Element {
  const [selected, setSelected] = useState<string | null>(null);
  return selected === null
    ? <GroupDirectory session={session} onOpen={setSelected} />
    : <GroupDetail session={session} id={selected} onBack={() => setSelected(null)} />;
}

function GroupDirectory({ session, onOpen }: Readonly<{
  session: Session; onOpen: (id: string) => void;
}>): JSX.Element {
  const [load, setLoad] = useState<Load<GroupPage>>({ kind: 'loading' });
  const [typed, setTyped] = useState('');
  const [term, setTerm] = useState('');
  const [cursor, setCursor] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const writable = session.scopes.includes(GROUPS_WRITE);

  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    const query = new URLSearchParams();
    if (term !== '') query.set('q', term);
    if (cursor !== null) query.set('cursor', cursor);
    const suffix = query.toString();
    read(suffix === '' ? 'groups' : `groups?${suffix}`).then(
      (value) => setLoad({ kind: 'ready', value: value as GroupPage }),
      (error: unknown) => setLoad({ kind: 'failed', message: failure(error, 'Groups could not be read') }),
    );
  }, [cursor, term]);
  useEffect(refresh, [refresh]);

  return <Screen title="Groups" description="Manage reusable membership and application access for this workspace."
    actions={writable ? <Button variant="primary" onClick={() => setCreating(true)}>Create group</Button> : undefined}>
    <Panel title="Group directory" description="Search machine names or display names. Both names stay visible wherever a group is used.">
      <form className="toolbar" onSubmit={(event) => { event.preventDefault(); setCursor(null); setTerm(typed.trim()); }}>
        <Field label="Search groups">{props => <input {...props} type="search" value={typed}
          placeholder="Search groups" onChange={event => setTyped(event.target.value)} />}</Field>
        <Button type="submit">Search</Button>
      </form>
      {load.kind === 'loading' && <Skeleton rows={4} label="Reading groups." />}
      {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
      {load.kind === 'ready' && <>
        <DataTable caption="Groups" rows={load.value.items} rowKey={group => group.id}
          empty={<EmptyState title="No group matches." body={term === '' ? 'Create a group to organize access.' : 'Clear the search to see all groups.'} />}
          columns={[
            { key: 'display', header: 'Group', sortBy: group => group.display_name,
              cell: group => <><strong>{group.display_name}</strong><br /><code>{group.name}</code></> },
            { key: 'revision', header: 'Revision', sortBy: group => group.revision, cell: group => group.revision },
            { key: 'open', header: 'Open', actions: true, cell: group => <Button small onClick={() => onOpen(group.id)}>Manage <span className="visually-hidden">{group.display_name}</span></Button> },
          ]} />
        <Actions><Button disabled={cursor === null} onClick={() => setCursor(null)}>First page</Button>
          <Button disabled={load.value.next_cursor === null} onClick={() => setCursor(load.value.next_cursor)}>Next page</Button></Actions>
      </>}
    </Panel>
    {creating && <GroupForm session={session} onCancel={() => setCreating(false)} onSaved={group => {
      setCreating(false); toast.success('Group created', group.display_name); onOpen(group.id);
    }} />}
  </Screen>;
}

function GroupForm({ session, group, onCancel, onSaved }: Readonly<{
  session: Session; group?: GroupRow; onCancel: () => void; onSaved: (group: GroupRow) => void;
}>): JSX.Element {
  const [name, setName] = useState(group?.name ?? '');
  const [display, setDisplay] = useState(group?.display_name ?? '');
  const [busy, setBusy] = useState(false);
  const [refusal, setRefusal] = useState<string | null>(null);
  const editing = group !== undefined;
  const save = (): void => {
    setBusy(true); setRefusal(null);
    mutate(editing ? groupPath(group.id) : 'groups', editing ? 'PUT' : 'POST', session,
      { name: name.trim(), display_name: display.trim(), ...(editing ? { revision: group.revision } : {}) }).then(
      value => { setBusy(false); onSaved(value as GroupRow); },
      error => { setBusy(false); setRefusal(failure(error, 'The group was not saved')); },
    );
  };
  return <Dialog open onOpenChange={open => { if (!open && !busy) onCancel(); }}><DialogContent>
    <DialogHeader><DialogTitle>{editing ? 'Edit group' : 'Create group'}</DialogTitle>
      <DialogDescription>The machine name is used by policy; the display name is for administrators.</DialogDescription></DialogHeader>
    {refusal !== null && <Message tone="error">{refusal} Your draft is still here.</Message>}
    <form onSubmit={event => { event.preventDefault(); save(); }}>
      <fieldset disabled={busy}><Field label="Machine name" required hint="Lowercase letters, numbers, and -_.: only.">
        {props => <input {...props} value={name} onChange={event => setName(event.target.value)} />}</Field>
        <Field label="Display name" required>{props => <input {...props} value={display} onChange={event => setDisplay(event.target.value)} />}</Field>
        <Actions end><Button onClick={onCancel}>Cancel</Button><Button variant="primary" type="submit" disabled={name.trim() === '' || display.trim() === ''}>Save group</Button></Actions>
      </fieldset>
    </form>
  </DialogContent></Dialog>;
}

function GroupDetail({ session, id, onBack }: Readonly<{ session: Session; id: string; onBack: () => void }>): JSX.Element {
  const [load, setLoad] = useState<Load<GroupRow>>({ kind: 'loading' });
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [busy, setBusy] = useState(false);
  const [refusal, setRefusal] = useState<string | null>(null);
  const writable = session.scopes.includes(GROUPS_WRITE);
  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    read(groupPath(id)).then(value => setLoad({ kind: 'ready', value: value as GroupRow }),
      error => setLoad({ kind: 'failed', message: failure(error, 'The group could not be read') }));
  }, [id]);
  useEffect(refresh, [refresh]);
  if (load.kind === 'loading') return <Screen title="Group"><Skeleton rows={5} label="Reading the group." /></Screen>;
  if (load.kind === 'failed') return <Screen title="Group" back={{ label: 'Back to groups', onClick: onBack }}><LoadFailure message={load.message} onRetry={refresh} /></Screen>;
  const group = load.value;
  const remove = (): void => {
    setBusy(true); setRefusal(null);
    mutate(groupPath(id), 'DELETE', session, { revision: group.revision }).then(
      () => { toast.success('Group deleted', group.display_name); onBack(); },
      error => { setBusy(false); setDeleting(false); setRefusal(failure(error, 'The group was not deleted')); },
    );
  };
  return <Screen title={group.display_name} identity={group.display_name} back={{ label: 'Back to groups', onClick: onBack }}
    description={<>Machine name: <code>{group.name}</code></>} actions={writable ? <><Button onClick={() => setEditing(true)}>Edit</Button>
      <Button variant="danger" onClick={() => setDeleting(true)}>Delete</Button></> : undefined}>
    {refusal !== null && <Message tone="error">{refusal}</Message>}
    <Tabs defaultValue={session.scopes.includes(MEMBERS_READ) ? 'members' : session.scopes.includes(ROLES_READ) ? 'roles' : 'details'}><TabsList aria-label="Group sections">
      {session.scopes.includes(MEMBERS_READ) && <TabsTrigger value="members">Members</TabsTrigger>}
      {session.scopes.includes(ROLES_READ) && <TabsTrigger value="roles">Roles</TabsTrigger>}
      <TabsTrigger value="details">Details</TabsTrigger>
    </TabsList>
      {session.scopes.includes(MEMBERS_READ) && <TabsContent value="members"><GroupMembers session={session} group={group} /></TabsContent>}
      {session.scopes.includes(ROLES_READ) && <TabsContent value="roles"><GroupRoles session={session} group={group} /></TabsContent>}
      <TabsContent value="details"><Panel title="Group details"><dl className="stats">
        <div className="stat"><dt>Machine name</dt><dd><code>{group.name}</code></dd></div>
        <div className="stat"><dt>Revision</dt><dd>{group.revision}</dd></div>
      </dl></Panel></TabsContent>
    </Tabs>
    {editing && <GroupForm session={session} group={group} onCancel={() => setEditing(false)} onSaved={saved => {
      setEditing(false); setLoad({ kind: 'ready', value: saved }); toast.success('Group updated', saved.display_name);
    }} />}
    {deleting && <ConfirmDialog title={`Delete ${group.display_name}?`}
      body="This permanently removes the group, all memberships, and its role assignments. Users keep roles granted directly or by other groups; already-issued JWTs remain valid until expiry."
      confirmLabel="Delete group" busy={busy} onCancel={() => setDeleting(false)} onConfirm={remove} />}
  </Screen>;
}

function GroupMembers({ session, group }: Readonly<{ session: Session; group: GroupRow }>): JSX.Element {
  const [load, setLoad] = useState<Load<MemberPage>>({ kind: 'loading' });
  const [cursor, setCursor] = useState<string | null>(null);
  const [user, setUser] = useState('');
  const [refusal, setRefusal] = useState<string | null>(null);
  const writable = session.scopes.includes(MEMBERS_WRITE);
  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    read(`${groupPath(group.id)}/members${cursor === null ? '' : `?cursor=${encodeURIComponent(cursor)}`}`).then(
      value => setLoad({ kind: 'ready', value: value as MemberPage }), error => setLoad({ kind: 'failed', message: failure(error, 'Members could not be read') }));
  }, [cursor, group.id]);
  useEffect(refresh, [refresh]);
  const change = (id: string, add: boolean): void => {
    setRefusal(null); mutate(memberPath(group.id, id), add ? 'PUT' : 'DELETE', session).then(
      () => { setUser(''); toast.success(add ? 'Member added' : 'Member removed', id); refresh(); },
      error => setRefusal(failure(error, 'Membership could not be changed')),
    );
  };
  return <Panel title="Members" description="Membership changes affect the next authorization decision and token issuance. Existing JWTs remain valid until expiry.">
    {refusal !== null && <Message tone="error">{refusal}</Message>}
    {writable && <form className="toolbar" onSubmit={event => { event.preventDefault(); if (user.trim() !== '') change(user.trim(), true); }}>
      <Field label="User ID">{props => <input {...props} value={user} placeholder="UUID" onChange={event => setUser(event.target.value)} />}</Field>
      <Button type="submit" variant="primary" disabled={user.trim() === ''}>Add member</Button></form>}
    {load.kind === 'loading' && <Skeleton rows={3} label="Reading members." />}
    {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
    {load.kind === 'ready' && <><DataTable rows={load.value.items} rowKey={row => row.user_id}
      empty={<EmptyState title="No members yet." body="Add a user to make group roles effective." />}
      columns={[{ key: 'user', header: 'User ID', cell: row => <code>{row.user_id}</code> }, ...(writable ? [{ key: 'remove', header: 'Remove', actions: true,
        cell: (row: { user_id: string }) => <Button small variant="danger" onClick={() => change(row.user_id, false)}>Remove <span className="visually-hidden">{row.user_id}</span></Button> }] : [])]} />
      <Actions><Button disabled={cursor === null} onClick={() => setCursor(null)}>First page</Button><Button disabled={load.value.next_cursor === null} onClick={() => setCursor(load.value.next_cursor)}>Next page</Button></Actions></>}
  </Panel>;
}

function GroupRoles({ session, group }: Readonly<{ session: Session; group: GroupRow }>): JSX.Element {
  const [load, setLoad] = useState<Load<HeldRoles>>({ kind: 'loading' });
  const [catalogue, setCatalogue] = useState<readonly AppRole[]>([]);
  const [clients, setClients] = useState<readonly string[]>([]);
  const [owner, setOwner] = useState('');
  const [role, setRole] = useState('');
  const [refusal, setRefusal] = useState<string | null>(null);
  const writable = session.scopes.includes(ROLES_WRITE);
  const refresh = useCallback(() => { setLoad({ kind: 'loading' }); read(groupRolesPath(group.id)).then(
    value => setLoad({ kind: 'ready', value: value as HeldRoles }), error => setLoad({ kind: 'failed', message: failure(error, 'Group roles could not be read') })); }, [group.id]);
  useEffect(refresh, [refresh]);
  useEffect(() => { read(owner === '' ? TENANT_CATALOGUE : clientCatalogue(owner)).then(
    value => setCatalogue((value as { roles: readonly AppRole[] }).roles), () => setCatalogue([])); }, [owner]);
  useEffect(() => { if (session.scopes.includes('admin.clients:read')) read('clients').then(value => setClients(
    (value as { items: readonly { client_id: string }[] }).items.map(item => item.client_id)), () => setClients([])); }, [session.scopes]);
  const rows = load.kind === 'ready' ? assignmentsOf(load.value) : [];
  const assign = (): void => { const body: Record<string, string> = { name: role }; if (owner !== '') body.client_id = owner;
    setRefusal(null); mutate(groupRolesPath(group.id), 'POST', session, body).then(() => { setRole(''); toast.success('Role assigned', role); refresh(); },
      error => setRefusal(failure(error, 'The role was not assigned'))); };
  return <Panel title="Application roles" description="Every member inherits these roles. Group roles can never grant console administrator authority.">
    {refusal !== null && <Message tone="error">{refusal}</Message>}
    {writable && <form className="group-role-form" onSubmit={event => { event.preventDefault(); if (role !== '') assign(); }}>
      <Field label="Application">{props => <select {...props} value={owner} onChange={event => { setOwner(event.target.value); setRole(''); }}><option value="">Workspace</option>{clients.map(client => <option key={client} value={client}>{client}</option>)}</select>}</Field>
      <Field label="Role">{props => <select {...props} value={role} onChange={event => setRole(event.target.value)}><option value="">Choose a role</option>{catalogue.filter(item => !rows.some(row => row.role === item.name && row.clientId === (owner || null))).map(item => <option key={item.name} value={item.name}>{item.name}</option>)}</select>}</Field>
      <Button type="submit" variant="primary" disabled={role === ''}>Assign role</Button></form>}
    {load.kind === 'loading' && <Skeleton rows={3} label="Reading group roles." />}
    {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
    {load.kind === 'ready' && <DataTable rows={rows} rowKey={row => `${row.clientId ?? ''}:${row.role}`}
      empty={<EmptyState title="No roles assigned." body="Members inherit no application access from this group." />}
      columns={[{ key: 'role', header: 'Role', cell: row => <code>{row.role}</code> }, { key: 'application', header: 'Application', cell: row => row.clientId ?? 'Workspace' },
        ...(writable ? [{ key: 'withdraw', header: 'Withdraw', actions: true, cell: (row: { role: string; clientId: string | null }) => <Button small variant="danger" onClick={() => {
          setRefusal(null); mutate(groupRoleWithdrawPath(group.id, row.role, row.clientId), 'DELETE', session).then(() => refresh(), error => setRefusal(failure(error, 'The role was not withdrawn')));
        }}>Withdraw <span className="visually-hidden">{row.role}</span></Button> }] : [])]} />}
  </Panel>;
}

export function UserGroups({ session, userId }: Readonly<{ session: Session; userId: string }>): JSX.Element {
  const [load, setLoad] = useState<Load<GroupPage>>({ kind: 'loading' });
  const [cursor, setCursor] = useState<string | null>(null);
  const [typed, setTyped] = useState('');
  const [matches, setMatches] = useState<Load<GroupPage> | null>(null);
  const [chosen, setChosen] = useState<GroupRow | null>(null);
  const [saving, setSaving] = useState(false);
  const [refusal, setRefusal] = useState<string | null>(null);
  const writable = session.scopes.includes(MEMBERS_WRITE);
  const searchable = writable && session.scopes.includes(GROUPS_READ);
  const refresh = useCallback(() => { setLoad({ kind: 'loading' }); read(`users/${encodeURIComponent(userId)}/groups${cursor === null ? '' : `?cursor=${encodeURIComponent(cursor)}`}`).then(
    value => setLoad({ kind: 'ready', value: value as GroupPage }), error => setLoad({ kind: 'failed', message: failure(error, 'Groups could not be read') })); }, [cursor, userId]);
  useEffect(refresh, [refresh]);
  const search = (): void => {
    setMatches({ kind: 'loading' }); setChosen(null);
    const query = new URLSearchParams();
    if (typed.trim() !== '') query.set('q', typed.trim());
    read(query.size === 0 ? 'groups' : `groups?${query}`).then(
      value => setMatches({ kind: 'ready', value: value as GroupPage }),
      error => setMatches({ kind: 'failed', message: failure(error, 'Groups could not be searched') }),
    );
  };
  const assign = (): void => {
    if (chosen === null) return;
    setSaving(true); setRefusal(null);
    mutate(memberPath(chosen.id, userId), 'PUT', session).then(() => {
      toast.success('Membership added', `${chosen.display_name} (${chosen.name})`);
      window.dispatchEvent(new CustomEvent(GROUP_MEMBERSHIP_CHANGED_EVENT, { detail: { userId } }));
      setSaving(false); setChosen(null); setMatches(null); setTyped(''); refresh();
    }, error => { setSaving(false); setRefusal(failure(error, 'Membership could not be added')); });
  };
  return <Panel title="Groups" description="Direct managed-group memberships. Role inheritance is shown on the Roles tab with its source.">
    {refusal !== null && <Message tone="error">{refusal}</Message>}
    {searchable && <form onSubmit={event => { event.preventDefault(); search(); }}>
      <div className="toolbar"><Field label="Find a group">{props => <input {...props} type="search" value={typed}
        placeholder="Search display or machine name" onChange={event => setTyped(event.target.value)} />}</Field>
        <Button type="submit" disabled={saving}>Search groups</Button></div>
      {matches?.kind === 'loading' && <Skeleton rows={2} label="Searching groups." />}
      {matches?.kind === 'failed' && <LoadFailure message={matches.message} onRetry={search} />}
      {matches?.kind === 'ready' && <div className="role-picker" role="radiogroup" aria-label="Matching groups">
        {matches.value.items.filter(group => load.kind !== 'ready' || !load.value.items.some(member => member.id === group.id)).map(group =>
          <label className="role-choice" key={group.id}><input type="radio" name="group" value={group.id}
            checked={chosen?.id === group.id} disabled={saving} onChange={() => setChosen(group)} />
            <span><strong>{group.display_name}</strong><small><code>{group.name}</code></small></span></label>)}
        {matches.value.items.length === 0 && <p className="muted">No group matches that search.</p>}
      </div>}
      {matches?.kind === 'ready' && <Actions end><Button type="button" variant="primary" disabled={chosen === null || saving} onClick={assign}>Add to group</Button></Actions>}
    </form>}
    {load.kind === 'loading' && <Skeleton rows={3} label="Reading user groups." />}{load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
    {load.kind === 'ready' && <><DataTable rows={load.value.items} rowKey={row => row.id} empty={<EmptyState title="No group memberships." body="Add this user from a group’s Members tab." />}
      columns={[{ key: 'group', header: 'Group', cell: row => <><strong>{row.display_name}</strong><br /><code>{row.name}</code></> },
        ...(writable ? [{ key: 'remove', header: 'Remove', actions: true, cell: (row: GroupRow) => <Button small variant="danger" onClick={() => {
          setRefusal(null); mutate(memberPath(row.id, userId), 'DELETE', session).then(() => {
            window.dispatchEvent(new CustomEvent(GROUP_MEMBERSHIP_CHANGED_EVENT, { detail: { userId } })); refresh();
          }, error => setRefusal(failure(error, 'Membership could not be removed')));
        }}>Remove <span className="visually-hidden">{row.display_name}</span></Button> }] : [])]} />
      <Actions><Button disabled={cursor === null} onClick={() => setCursor(null)}>First page</Button><Button disabled={load.value.next_cursor === null} onClick={() => setCursor(load.value.next_cursor)}>Next page</Button></Actions></>}
  </Panel>;
}

export function mayReadGroups(session: Session): boolean { return session.scopes.includes(GROUPS_READ); }
export function mayReadMemberships(session: Session): boolean { return session.scopes.includes(MEMBERS_READ); }
