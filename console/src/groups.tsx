import { EntityPicker, type EntityOption, type EntityPage } from './components/entity-picker';
import { FormSelect } from './components/ui/select';
import { DirectorySearch } from './directory-controls';
import { PlusIcon, SearchIcon } from 'lucide-react';
import { useDialogDraft } from './dialog-draft';
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import type { Directory } from './users';
import { mutate, read, type Session } from './api';
import { FlowOrigin } from './flow-origin';
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
    actions={writable ? <Button variant="primary" onClick={() => setCreating(true)}><PlusIcon aria-hidden="true" />Create group</Button> : undefined}>
    <Panel className="directory-panel" title="Group directory" description="Search machine names or display names. Both names stay visible wherever a group is used.">
      <div className="directory-toolbar"><DirectorySearch label="Search groups" value={typed} placeholder="Name or display name" onChange={setTyped} onSubmit={() => { if (cursor === null && term === typed.trim()) refresh(); else { setCursor(null); setTerm(typed.trim()); } }} actionLabel="Search groups" /></div>
      {load.kind === 'loading' && <Skeleton rows={4} label="Reading groups." />}
      {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
      {load.kind === 'ready' && <>
        <DataTable caption="Groups" rows={load.value.items} rowKey={group => group.id}
          empty={<EmptyState title="No group matches." body={term === '' ? 'Create a group to organize access.' : 'Clear the search to see all groups.'} />}
          columns={[
            { key: 'display', header: 'Group', sortBy: group => group.display_name,
              cell: group => <><button type="button" className="identity-link" onClick={() => onOpen(group.id)}><strong>{group.display_name}</strong></button><br /><span className="muted">{group.name}</span></> },
            { key: 'revision', header: 'Revision', sortBy: group => group.revision, cell: group => group.revision },
            { key: 'open', header: 'Open', actions: true, cell: group => <Button small onClick={() => onOpen(group.id)}>View <span className="visually-hidden">{group.display_name}</span></Button> },
          ]} />
        {(cursor !== null || load.value.next_cursor !== null) && <Actions><Button variant="ghost" disabled={cursor === null} onClick={() => setCursor(null)}>First page</Button>
          <Button variant="ghost" disabled={load.value.next_cursor === null} onClick={() => setCursor(load.value.next_cursor)}>Next page</Button></Actions>}
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
  const { requestClose, confirmation } = useDialogDraft(name !== (group?.name ?? '') || display !== (group?.display_name ?? ''), busy, onCancel);
  return <Dialog open onOpenChange={open => { if (!open) requestClose(); }}><DialogContent>
    <DialogHeader><DialogTitle>{editing ? 'Edit group' : 'Create group'}</DialogTitle>
      <DialogDescription>The machine name is used by policy; the display name is for administrators.</DialogDescription></DialogHeader>
    {refusal !== null && <Message tone="error">{refusal} Your draft is still here.</Message>}
    <form onSubmit={event => { event.preventDefault(); save(); }}>
      <fieldset disabled={busy}><Field label="Machine name" required hint="Lowercase letters, numbers, and -_.: only.">
        {props => <input {...props} value={name} onChange={event => setName(event.target.value)} />}</Field>
        <Field label="Display name" required>{props => <input {...props} value={display} onChange={event => setDisplay(event.target.value)} />}</Field>
        {confirmation}<Actions end><Button onClick={requestClose}>Cancel</Button><Button variant="primary" type="submit" disabled={name.trim() === '' || display.trim() === ''}>Save group</Button></Actions>
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
    <FlowOrigin session={session} kind="group" resource={id} />
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
  const [selectedUser, setSelectedUser] = useState<EntityOption | null>(null);
  const [adding, setAdding] = useState(false);
  const [busy, setBusy] = useState(false);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [removingMember, setRemovingMember] = useState<{ user_id: string; username: string } | null>(null);
  const writable = session.scopes.includes(MEMBERS_WRITE);
  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    read(`${groupPath(group.id)}/members${cursor === null ? '' : `?cursor=${encodeURIComponent(cursor)}`}`).then(
      value => setLoad({ kind: 'ready', value: value as MemberPage }), error => setLoad({ kind: 'failed', message: failure(error, 'Members could not be read') }));
  }, [cursor, group.id]);
  useEffect(refresh, [refresh]);
  const change = (id: string, add: boolean, label: string): void => {
    setBusy(true);
    setRefusal(null); mutate(memberPath(group.id, id), add ? 'PUT' : 'DELETE', session).then(
      () => { setUser(''); setBusy(false); setRemovingMember(null); setAdding(false); setSelectedUser(null); toast.success(add ? 'Member added' : 'Member removed', label); refresh(); },
      error => { setBusy(false); setRemovingMember(null); setRefusal(failure(error, 'Membership could not be changed')); },
    );
  };
  const searchUsers = useCallback(async (query: string, cursor?: string): Promise<EntityPage> => {
    const params = new URLSearchParams();
    if (query) params.set('q', query);
    if (cursor) params.set('cursor', cursor);
    const result = await read(`users${params.size ? `?${params}` : ''}`) as Directory;
    return { items: result.items.map(row => ({ id: row.user_id, label: row.username, description: row.email ?? 'No email address' })), nextCursor: result.next_cursor };
  }, []);
  const addDraft = useDialogDraft(adding && user.trim() !== '', busy, () => { setAdding(false); setUser(''); setSelectedUser(null); });
  return <Panel title="Members" description="Membership changes affect the next authorization decision and token issuance. Existing JWTs remain valid until expiry." actions={writable && session.scopes.includes('admin.users:read') ? <Button onClick={() => setAdding(true)}>Add member</Button> : undefined}>
    {refusal !== null && !adding && <Message tone="error">{refusal}</Message>}
    <Dialog open={adding} onOpenChange={open => { if (!open) addDraft.requestClose(); }}><DialogContent>{addDraft.confirmation}<DialogHeader><DialogTitle>Add member</DialogTitle><DialogDescription>Find a user and add them to {group.display_name}.</DialogDescription></DialogHeader>
    {refusal !== null && <Message tone="error">{refusal}</Message>}
    {writable && session.scopes.includes('admin.users:read') && <EntityPicker label="Find a user"
      hint="Search by username or email, select the person, then choose Add member."
      query={user} onQueryChange={setUser} value={selectedUser} onChange={setSelectedUser}
      search={searchUsers} disabled={busy} />}
    {selectedUser && <p className="muted">Selected: {selectedUser.label} ({selectedUser.id})</p>}
    <Actions end><Button disabled={busy} onClick={addDraft.requestClose}>Cancel</Button><Button variant="primary"
      disabled={busy || selectedUser === null || (load.kind === 'ready' && load.value.items.some(member => member.user_id === selectedUser?.id))}
      onClick={() => { if (selectedUser) change(selectedUser.id, true, selectedUser.label); }}>Add member</Button></Actions></DialogContent></Dialog>
    {writable && !session.scopes.includes('admin.users:read') && <Message tone="info">Ask an administrator for user directory access to add members by username.</Message>}
    {load.kind === 'loading' && <Skeleton rows={3} label="Reading members." />}
    {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
    {load.kind === 'ready' && <><DataTable rows={load.value.items} rowKey={row => row.user_id}
      empty={<EmptyState title="No members yet." body="Add a user to make group roles effective." />}
      columns={[{ key: 'user', header: 'User', cell: row => <><strong>{row.username}</strong>{row.email && <span className="muted block">{row.email}</span>}</> }, ...(writable ? [{ key: 'remove', header: 'Remove', actions: true,
        cell: (row: { user_id: string; username: string }) => <Button small variant="danger" disabled={busy} onClick={() => setRemovingMember(row)}>Remove <span className="visually-hidden">{row.username}</span></Button> }] : [])]} />
      <Actions><Button disabled={cursor === null} onClick={() => setCursor(null)}>First page</Button><Button disabled={load.value.next_cursor === null} onClick={() => setCursor(load.value.next_cursor)}>Next page</Button></Actions></>}
    {removingMember !== null && <ConfirmDialog title={`Remove ${removingMember.username} from ${group.display_name}?`}
      body="The user will lose access inherited from this group in new authorization decisions and tokens."
      confirmLabel="Remove member" busy={busy} onCancel={() => setRemovingMember(null)}
      onConfirm={() => change(removingMember.user_id, false, removingMember.username)} />}
  </Panel>;
}

function GroupRoles({ session, group }: Readonly<{ session: Session; group: GroupRow }>): JSX.Element {
  const [load, setLoad] = useState<Load<HeldRoles>>({ kind: 'loading' });
  const [catalogue, setCatalogue] = useState<readonly AppRole[]>([]);
  const [catalogueLoading, setCatalogueLoading] = useState(true);
  const [catalogueError, setCatalogueError] = useState<string | null>(null);
  const [catalogueRetry, setCatalogueRetry] = useState(0);
  const [clients, setClients] = useState<readonly string[]>([]);
  const [owner, setOwner] = useState('');
  const [role, setRole] = useState('');
  const [assigning, setAssigning] = useState(false);
  const [withdrawing, setWithdrawing] = useState<{ role: string; clientId: string | null } | null>(null);
  const [changing, setChanging] = useState(false);
  const assignmentDraft = useDialogDraft(assigning && (owner !== '' || role !== ''), changing, () => { setAssigning(false); setOwner(''); setRole(''); });
  const [refusal, setRefusal] = useState<string | null>(null);
  const writable = session.scopes.includes(ROLES_WRITE);
  const refresh = useCallback(() => { setLoad({ kind: 'loading' }); read(groupRolesPath(group.id)).then(
    value => setLoad({ kind: 'ready', value: value as HeldRoles }), error => setLoad({ kind: 'failed', message: failure(error, 'Group roles could not be read') })); }, [group.id]);
  useEffect(refresh, [refresh]);
  useEffect(() => {
    let active = true;
    setCatalogue([]); setCatalogueLoading(true); setCatalogueError(null);
    read(owner === '' ? TENANT_CATALOGUE : clientCatalogue(owner)).then(value => {
      if (active) { setCatalogue((value as { roles: readonly AppRole[] }).roles); setCatalogueLoading(false); }
    }, error => { if (active) { setCatalogueLoading(false); setCatalogueError(failure(error, 'Role catalogue could not be read')); } });
    return () => { active = false; };
  }, [owner, catalogueRetry]);
  useEffect(() => { if (session.scopes.includes('admin.clients:read')) read('clients').then(value => setClients(
    (value as { items: readonly { client_id: string }[] }).items.map(item => item.client_id)), () => setClients([])); }, [session.scopes]);
  const rows = load.kind === 'ready' ? assignmentsOf(load.value) : [];
  const assign = (): void => { const body: Record<string, string> = { name: role }; if (owner !== '') body.client_id = owner;
    setChanging(true); setRefusal(null); mutate(groupRolesPath(group.id), 'POST', session, body).then(() => { setChanging(false); setRole(''); setAssigning(false); toast.success('Role assigned', role); refresh(); },
      error => { setChanging(false); setRefusal(failure(error, 'The role was not assigned')); }); };
  const withdraw = (row: { role: string; clientId: string | null }): void => {
    setChanging(true);
    setRefusal(null);
    mutate(groupRoleWithdrawPath(group.id, row.role, row.clientId), 'DELETE', session).then(
      () => { setChanging(false); setWithdrawing(null); refresh(); },
      error => { setChanging(false); setWithdrawing(null); setRefusal(failure(error, 'The role was not withdrawn')); },
    );
  };
  return <Panel title="Application roles" description="Every member inherits these roles. Group roles can never grant console administrator authority." actions={writable ? <Button onClick={() => setAssigning(true)}>Assign role</Button> : undefined}>
    {refusal !== null && !assigning && <Message tone="error">{refusal}</Message>}
    <Dialog open={assigning} onOpenChange={open => { if (!open) assignmentDraft.requestClose(); }}><DialogContent>{assignmentDraft.confirmation}<DialogHeader><DialogTitle>Assign application role</DialogTitle><DialogDescription>Every member of this group will inherit the selected role.</DialogDescription></DialogHeader>
    {writable && <form className="group-role-form" onSubmit={event => { event.preventDefault(); if (role !== '' && !changing && !catalogueLoading && !catalogueError) assign(); }}>
      <Field label="Application">{props => <FormSelect {...props} disabled={changing} value={owner} onValueChange={value => { setOwner(value); setRole(''); setCatalogue([]); setCatalogueLoading(true); }} options={[{value: '', label: 'Workspace', description: 'Roles shared across this workspace'}, ...clients.map(client => ({ value: client, label: client }))]} />}</Field>
      <Field label="Role">{props => <FormSelect {...props} disabled={changing || catalogueLoading || catalogueError !== null} value={role} onValueChange={setRole} options={[{ value: '', label: catalogueLoading ? 'Reading roles…' : 'Choose a role' }, ...catalogue.filter(item => !rows.some(row => row.role === item.name && row.clientId === (owner || null))).map(item => ({ value: item.name, label: item.name, ...(item.description ? { description: item.description } : {}) }))]} />}</Field>
      {catalogueError && <LoadFailure message={catalogueError} onRetry={() => setCatalogueRetry(value => value + 1)} />}
      {!catalogueLoading && !catalogueError && catalogue.length === 0 && <p className="muted">No roles are defined for this application.</p>}
      {refusal !== null && <Message tone="error">{refusal}</Message>}
      <div className="actions"><Button disabled={changing} onClick={assignmentDraft.requestClose}>Cancel</Button><Button type="submit" variant="primary" disabled={role === '' || changing || catalogueLoading || catalogueError !== null}>{changing ? 'Assigning…' : 'Assign role'}</Button></div></form>}</DialogContent></Dialog>
    {load.kind === 'loading' && <Skeleton rows={3} label="Reading group roles." />}
    {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
    {load.kind === 'ready' && <DataTable rows={rows} rowKey={row => `${row.clientId ?? ''}:${row.role}`}
      empty={<EmptyState title="No roles assigned." body="Members inherit no application access from this group." />}
      columns={[{ key: 'role', header: 'Role', cell: row => <code>{row.role}</code> }, { key: 'application', header: 'Application', cell: row => row.clientId ?? 'Workspace' },
        ...(writable ? [{ key: 'withdraw', header: 'Withdraw', actions: true, cell: (row: { role: string; clientId: string | null }) => <Button small variant="danger" disabled={changing} onClick={() => setWithdrawing(row)}>Withdraw <span className="visually-hidden">{row.role}</span></Button> }] : [])]} />}
    {withdrawing !== null && <ConfirmDialog title={`Withdraw ${withdrawing.role} from ${group.display_name}?`}
      body="Every group member will lose this inherited role in new authorization decisions and tokens."
      confirmLabel="Withdraw role" busy={changing} onCancel={() => setWithdrawing(null)} onConfirm={() => withdraw(withdrawing)} />}
  </Panel>;
}

export function UserGroups({ session, userId }: Readonly<{ session: Session; userId: string }>): JSX.Element {
  const [load, setLoad] = useState<Load<GroupPage>>({ kind: 'loading' });
  const [cursor, setCursor] = useState<string | null>(null);
  const [typed, setTyped] = useState('');
  const [matches, setMatches] = useState<Load<GroupPage> | null>(null);
  const [adding, setAdding] = useState(false);
  const [chosen, setChosen] = useState<GroupRow | null>(null);
  const [saving, setSaving] = useState(false);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [removingGroup, setRemovingGroup] = useState<GroupRow | null>(null);
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
      setSaving(false); setChosen(null); setMatches(null); setTyped(''); setAdding(false); refresh();
    }, error => { setSaving(false); setRefusal(failure(error, 'Membership could not be added')); });
  };
  const remove = (row: GroupRow): void => {
    setSaving(true); setRefusal(null);
    mutate(memberPath(row.id, userId), 'DELETE', session).then(() => {
      setSaving(false); setRemovingGroup(null);
      window.dispatchEvent(new CustomEvent(GROUP_MEMBERSHIP_CHANGED_EVENT, { detail: { userId } })); refresh();
    }, error => { setSaving(false); setRemovingGroup(null); setRefusal(failure(error, 'Membership could not be removed')); });
  };
  const addDraft = useDialogDraft(adding && (typed.trim() !== '' || chosen !== null), saving, () => { setAdding(false); setTyped(''); setMatches(null); setChosen(null); });
  return <Panel title="Groups" description="Direct managed-group memberships. Role inheritance is shown on the Roles tab with its source." actions={searchable ? <Button onClick={() => setAdding(true)}>Add to group</Button> : undefined}>
    {refusal !== null && <Message tone="error">{refusal}</Message>}
    <Dialog open={adding} onOpenChange={open => { if (!open) addDraft.requestClose(); }}><DialogContent>{addDraft.confirmation}<DialogHeader><DialogTitle>Add to group</DialogTitle><DialogDescription>Find a group and select it for this user.</DialogDescription></DialogHeader>
    {searchable && <form onSubmit={event => { event.preventDefault(); search(); }}>
      <div className="toolbar"><Field label="Find a group">{props => <input {...props} type="search" value={typed}
        placeholder="Search display or machine name" onChange={event => setTyped(event.target.value)} />}</Field>
        <Button type="submit" disabled={saving} aria-label="Search groups" title="Search groups"><SearchIcon aria-hidden="true" /><span className="visually-hidden">Search groups</span></Button></div>
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
    <Actions end><Button onClick={addDraft.requestClose}>Cancel</Button></Actions></DialogContent></Dialog>
    {load.kind === 'loading' && <Skeleton rows={3} label="Reading user groups." />}{load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
    {load.kind === 'ready' && <><DataTable rows={load.value.items} rowKey={row => row.id} empty={<EmptyState title="No group memberships." body="Add this user from a group’s Members tab." />}
      columns={[{ key: 'group', header: 'Group', cell: row => <><strong>{row.display_name}</strong><br /><code>{row.name}</code></> },
        ...(writable ? [{ key: 'remove', header: 'Remove', actions: true, cell: (row: GroupRow) => <Button small variant="danger" disabled={saving} onClick={() => setRemovingGroup(row)}>Remove <span className="visually-hidden">{row.display_name}</span></Button> }] : [])]} />
      <Actions><Button disabled={cursor === null} onClick={() => setCursor(null)}>First page</Button><Button disabled={load.value.next_cursor === null} onClick={() => setCursor(load.value.next_cursor)}>Next page</Button></Actions></>}
    {removingGroup !== null && <ConfirmDialog title={`Remove user from ${removingGroup.display_name}?`}
      body="The user will lose access inherited from this group in new authorization decisions and tokens."
      confirmLabel="Remove membership" busy={saving} onCancel={() => setRemovingGroup(null)} onConfirm={() => remove(removingGroup)} />}
  </Panel>;
}

export function mayReadGroups(session: Session): boolean { return session.scopes.includes(GROUPS_READ); }
export function mayReadMemberships(session: Session): boolean { return session.scopes.includes(MEMBERS_READ); }
