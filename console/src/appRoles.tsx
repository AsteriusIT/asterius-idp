/**
 * Application roles: the two catalogues, and what one account holds
 * (`ast-095`, `ast-mqt`).
 *
 * These are **not** the roles that administer this server. `ast-3t8`'s
 * `RoleEditor` on the account screen edits `asterius_domain::Role` under
 * `admin.roles:*` — who may read a tenant, rotate a key, disable an account.
 * What is here is a tenant's own vocabulary, under `admin.app_roles:*`: names
 * an application authorises against, issued in the `roles` and
 * `resource_access` claims. The two are deliberately separate screens with
 * separate scopes, because delegating the right to invent a role an
 * application reads is not delegating the right to appoint an administrator.
 *
 * # Nothing here is a security control
 *
 * A section this file hides is a section the caller's scopes say is not worth
 * drawing. Every route re-checks its own authority server-side
 * (`crates/admin-api/src/rbac.rs`), so a console that drew all of them would
 * produce 403s and leak nothing.
 *
 * # Two refusals this screen has to render rather than swallow
 *
 * * **Deleting a role somebody still holds is a 409**, on purpose: cascading
 *   would withdraw authority from an unbounded number of people in one request
 *   and record it as one audit event naming none of them. The server's
 *   sentence says to withdraw it first, and it is shown verbatim.
 * * **Assigning a role that is not in the catalogue is a 409** too, never a
 *   silent creation — an assignment must not be a way to invent a name that
 *   ends up in a token.
 */
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { mutate, read, type Session } from './api';
import { toast } from './components/ui/toast';
import {
  Actions,
  Button,
  DataTable,
  Field,
  LoadFailure,
  Message,
  Panel,
  Skeleton,
  Screen,
} from './ui';
import { FormSelect } from './components/ui/select';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from './components/ui/dialog';
import { roleDescription, roleName } from './validation';

/** The scope a catalogue is read with. */
export const READ_SCOPE = 'admin.app_roles:read';

/** The scope every change here needs. */
export const WRITE_SCOPE = 'admin.app_roles:write';

/** One catalogue entry, as the API renders it. */
export interface AppRole {
  readonly name: string;
  readonly description: string | null;
  /** `null` for a tenant role; the owning client otherwise. */
  readonly client_id: string | null;
  readonly created_at: number;
}

/** A whole catalogue. */
export interface Catalogue {
  readonly roles: readonly AppRole[];
}

/**
 * What one account holds, in the two shapes a token carries.
 *
 * The same document as `roles` / `resource_access` in a token, so an
 * administrator reading this screen and a developer reading a token are
 * looking at one structure rather than two.
 */
export interface HeldRoles {
  readonly roles: readonly string[];
  readonly resource_access: Readonly<Record<string, { readonly roles: readonly string[] }>>;
}

/** The tenant catalogue's path, relative to the API base. */
export const TENANT_CATALOGUE = 'app-roles';

/** One client's catalogue path. */
export function clientCatalogue(clientId: string): string {
  return `clients/${encodeURIComponent(clientId)}/app-roles`;
}

/** What one account holds. */
export function heldPath(userId: string): string {
  return `users/${encodeURIComponent(userId)}/app-roles`;
}

/**
 * The path that withdraws one role from one account.
 *
 * A client role has a path of its own rather than a query parameter, because
 * the pair identifies the assignment: a deletion whose target depended on an
 * optional parameter is one a proxy that drops query strings would aim at the
 * wrong role.
 */
export function withdrawPath(
  userId: string,
  role: string,
  clientId: string | null,
): string {
  const user = encodeURIComponent(userId);
  const name = encodeURIComponent(role);
  return clientId === null
    ? `users/${user}/app-roles/${name}`
    : `users/${user}/clients/${encodeURIComponent(clientId)}/app-roles/${name}`;
}

/** Whether this caller may see a catalogue at all. */
export function mayRead(session: Session): boolean {
  return session.scopes.includes(READ_SCOPE);
}

/** Whether this caller may change one. */
export function mayWrite(session: Session): boolean {
  return session.scopes.includes(WRITE_SCOPE);
}

/**
 * The flat list of what an account holds, one line per assignment.
 *
 * Exported because it is the one piece of logic on this screen worth reading
 * on its own: it is what turns the two token shapes back into the rows an
 * operator withdraws one by one.
 */
export function assignmentsOf(
  held: HeldRoles,
): readonly { readonly role: string; readonly clientId: string | null }[] {
  const tenant = held.roles.map((role) => ({ role, clientId: null }));
  const clients = Object.entries(held.resource_access).flatMap(([clientId, entry]) =>
    entry.roles.map((role) => ({ role, clientId })),
  );
  return [...tenant, ...clients];
}

function failure(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

/** What a load is doing. */
type Load<T> =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly value: T }
  | { readonly kind: 'failed'; readonly message: string };

/**
 * One catalogue: the entries, a form that adds to it, and a button per row
 * that removes one.
 *
 * Used twice with a different `path` — the tenant's catalogue on the settings
 * screen and a client's on the client editor — because they are the same
 * resource under two owners, and two components would be two chances to spell
 * the refusal differently.
 */
export function RoleCatalogue({
  session,
  path,
  title,
  explanation,
}: Readonly<{
  session: Session;
  path: string;
  title: string;
  explanation: string;
}>): JSX.Element {
  const [load, setLoad] = useState<Load<Catalogue>>({ kind: 'loading' });
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [notice, setNotice] = useState<string | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const writable = mayWrite(session);

  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    read(path).then(
      (value) => setLoad({ kind: 'ready', value: value as Catalogue }),
      (error: unknown) =>
        setLoad({ kind: 'failed', message: failure(error, 'the roles could not be read') }),
    );
  }, [path]);

  useEffect(refresh, [refresh]);

  const create = (): void => {
    setBusy(true);
    setNotice(null);
    setRefusal(null);
    const body: Record<string, unknown> = { name: name.trim() };
    if (description.trim() !== '') {
      body.description = description.trim();
    }
    mutate(path, 'POST', session, body).then(
      () => {
        setBusy(false);
        setCreating(false);
        setName('');
        setDescription('');
        setNotice(`${body.name as string} is in the catalogue.`);
        toast.success('Role added', `${body.name as string} is in the catalogue.`);
        refresh();
      },
      (error: unknown) => {
        setBusy(false);
        setRefusal(failure(error, 'the role was not created'));
      },
    );
  };

  const remove = (role: string): void => {
    setBusy(true);
    setNotice(null);
    setRefusal(null);
    mutate(`${path}/${encodeURIComponent(role)}`, 'DELETE', session).then(
      () => {
        setBusy(false);
        setNotice(`${role} is no longer in the catalogue.`);
        toast.success('Role removed', `${role} is no longer in the catalogue.`);
        refresh();
      },
      (error: unknown) => {
        setBusy(false);
        // A 409 says the role is still held. The server's sentence names the
        // remedy — withdraw it first — so it is shown as it was written.
        setRefusal(failure(error, 'the role was not deleted'));
      },
    );
  };

  return (
    <section className="role-catalogue" aria-label={title}>
      <div className="role-catalogue-toolbar"><p className="muted">{explanation}</p>{writable && <Button variant="primary" onClick={() => { setRefusal(null); setCreating(true); }}>+ New role</Button>}</div>
      {notice !== null && <Message tone="success">{notice}</Message>}
      {refusal !== null && <Message tone="error">{refusal}</Message>}
      {load.kind === 'loading' && <Skeleton rows={3} label="Reading the catalogue." />}
      {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
      {load.kind === 'ready' && load.value.roles.length === 0 && (
        <div className="table-scroll"><table><thead><tr><th>Role name</th><th>Description</th></tr></thead><tbody><tr><td colSpan={2} className="empty-table">No roles defined yet. Create a role to start assigning access.</td></tr></tbody></table></div>
      )}
      {load.kind === 'ready' && load.value.roles.length > 0 && (
        <DataTable
          rows={load.value.roles}
          rowKey={(role) => role.name}
          search={{
            of: (role) => `${role.name} ${role.description ?? ''}`,
            placeholder: 'Filter the catalogue…',
            label: 'Filter these roles by name or description',
          }}
          columns={[
            {
              key: 'name',
              header: 'Role',
              sortBy: (role) => role.name,
              cell: (role) => <strong>{role.name}</strong>,
            },
            {
              key: 'description',
              header: 'Description',
              sortBy: (role) => role.description ?? '',
              cell: (role) => role.description ?? '',
            },
            ...(writable
              ? [
                  {
                    key: 'delete',
                    header: 'Delete',
                    actions: true,
                    cell: (role: AppRole) => (
                      <Button small disabled={busy} onClick={() => remove(role.name)}>
                        Delete <span className="visually-hidden">{role.name}</span>
                      </Button>
                    ),
                  },
                ]
              : []),
          ]}
        />
      )}
      {writable && (
        <Dialog open={creating} onOpenChange={(open) => { if (!busy) setCreating(open); }}><DialogContent>
        <DialogHeader><DialogTitle>New role</DialogTitle><DialogDescription>Define an access role that you can assign to users.</DialogDescription></DialogHeader>
        {refusal !== null && <Message tone="error">{refusal}</Message>}
        <form
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            create();
          }}
        >
          <fieldset className="role-dialog-fields" disabled={busy}>
            <Field
              label="Name"
              required
              // Said while it is being typed, and never instead of the
              // server's own refusal: `RoleName::parse` decides, this only
              // saves the round trip. See `validation.ts`.
              error={roleName(name)}
              hint={
                <>
                  Use lowercase letters, numbers or <code>-_.:</code>. Maximum 64 characters.
                </>
              }
            >
              {(props) => (
                <input
                  {...props}
                  name="name"
                  type="text"
                  value={name}
                  placeholder="payments.settlement:approve"
                  onChange={(event) => setName(event.target.value)}
                />
              )}
            </Field>
            <Field
              label="Description"
              hint="Help administrators understand when to assign this role."
              error={roleDescription(description)}
            >
              {(props) => (
                <input
                  {...props}
                  name="description"
                  type="text"
                  value={description}
                  onChange={(event) => setDescription(event.target.value)}
                />
              )}
            </Field>
            <Actions>
              <Button onClick={() => setCreating(false)} disabled={busy}>Cancel</Button>
              <Button type="submit" variant="primary" disabled={busy || name.trim() === ''}>
                Create role
              </Button>
            </Actions>
          </fieldset>
        </form></DialogContent></Dialog>
      )}
    </section>
  );
}

/**
 * What one account holds, with the two changes an operator makes: give a role,
 * take one back (`ast-mqt`).
 *
 * Beside `ast-3t8`'s administrative role editor and deliberately not merged
 * with it — see this module's header. The catalogues are read here so the
 * operator picks a name rather than typing one: a typed name that is not in
 * the catalogue is a 409, which is the right refusal and a poor form.
 */
export function UserAppRoles({
  session,
  userId,
  busy,
  onChanged,
}: Readonly<{
  session: Session;
  userId: string;
  busy: boolean;
  onChanged: (message: string) => void;
}>): JSX.Element {
  const [load, setLoad] = useState<Load<HeldRoles>>({ kind: 'loading' });
  const [catalogue, setCatalogue] = useState<readonly AppRole[]>([]);
  const [clients, setClients] = useState<readonly string[]>([]);
  /** Which catalogue the form is picking from: `''` is the tenant's. */
  const [owner, setOwner] = useState('');
  const [chosen, setChosen] = useState('');
  const [refusal, setRefusal] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [assigning, setAssigning] = useState(false);
  const [search, setSearch] = useState('');
  const writable = mayWrite(session);
  const path = heldPath(userId);

  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    read(path).then(
      (value) => setLoad({ kind: 'ready', value: value as HeldRoles }),
      (error: unknown) =>
        setLoad({
          kind: 'failed',
          message: failure(error, 'the application roles could not be read'),
        }),
    );
  }, [path]);

  useEffect(refresh, [refresh]);

  // The catalogue the form picks from, which follows the chosen owner. Read
  // rather than typed: a name that is not in the catalogue is a 409 — never a
  // silent creation — and a refusal is the wrong way to discover a spelling.
  useEffect(() => {
    read(owner === '' ? TENANT_CATALOGUE : clientCatalogue(owner)).then(
      (value) => setCatalogue((value as Catalogue).roles),
      () => setCatalogue([]),
    );
  }, [owner]);

  // The clients whose catalogues may be offered. A caller without
  // `admin.clients:read` gets the tenant's catalogue and no client list, which
  // is the same screen minus a picker rather than a broken one.
  useEffect(() => {
    if (!session.scopes.includes('admin.clients:read')) {
      return;
    }
    read('clients').then(
      (value) =>
        setClients(
          (value as { items: readonly { client_id: string }[] }).items.map(
            (client) => client.client_id,
          ),
        ),
      () => setClients([]),
    );
  }, [session.scopes]);

  const assign = (): void => {
    setSaving(true);
    setRefusal(null);
    const body: Record<string, unknown> = { name: chosen };
    if (owner !== '') {
      body.client_id = owner;
    }
    mutate(path, 'POST', session, body).then(
      () => {
        setSaving(false);
        setChosen('');
        setAssigning(false);
        onChanged(`${chosen} was assigned.`);
        refresh();
      },
      (error: unknown) => {
        setSaving(false);
        setRefusal(failure(error, 'the role was not assigned'));
      },
    );
  };

  const withdraw = (role: string, clientId: string | null): void => {
    setSaving(true);
    setRefusal(null);
    mutate(withdrawPath(userId, role, clientId), 'DELETE', session).then(
      () => {
        setSaving(false);
        onChanged(`${role} was withdrawn.`);
        refresh();
      },
      (error: unknown) => {
        setSaving(false);
        setRefusal(failure(error, 'the role was not withdrawn'));
      },
    );
  };

  const held = load.kind === 'ready' ? assignmentsOf(load.value) : [];
  // A role already held is not offered again: assigning it twice is harmless —
  // the server answers 200 rather than 201 — but a list that offers what is
  // already in the table above reads as though it were not.
  const offered = catalogue.filter(
    (role) =>
      !held.some(
        (each) => each.clientId === (owner === '' ? null : owner) && each.role === role.name,
      ),
  );

  return (
    <Panel className="flat-section"
      id="app-roles"
      title="Application roles"
      description="Access assigned to this user across the tenant and its applications."
      actions={writable ? <Button variant="primary" onClick={() => { setSearch(''); setAssigning(true); }}>Assign role</Button> : undefined}
    >
      {refusal !== null && <Message tone="error">{refusal}</Message>}
      {load.kind === 'loading' && <Skeleton rows={3} label="Reading the assignments." />}
      {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
      {load.kind === 'ready' && held.length === 0 && (
        <div className="table-wrap"><table><thead><tr><th>Role name</th><th>Application</th><th>Assignment</th></tr></thead><tbody><tr><td colSpan={3} className="table-empty">No application roles assigned to this user.</td></tr></tbody></table></div>
      )}
      {load.kind === 'ready' && held.length > 0 && (
        <DataTable
          rows={held}
          rowKey={(assignment) => `${assignment.clientId ?? ''}:${assignment.role}`}
          search={{
            of: (assignment) => `${assignment.role} ${assignment.clientId ?? 'the tenant'}`,
            placeholder: 'Filter these assignments…',
            label: 'Filter these assignments by role or catalogue',
          }}
          columns={[
            {
              key: 'role',
              header: 'Role',
              sortBy: (assignment) => assignment.role,
              cell: (assignment) => <code>{assignment.role}</code>,
            },
            {
              key: 'catalogue',
              header: 'Application',
              sortBy: (assignment) => assignment.clientId ?? '',
              cell: (assignment) =>
                assignment.clientId === null ? (
                  'the tenant'
                ) : (
                  <code>{assignment.clientId}</code>
                ),
            },
            { key: 'assignment', header: 'Assignment', cell: () => 'Direct' },
            ...(writable
              ? [
                  {
                    key: 'withdraw',
                    header: 'Withdraw',
                    actions: true,
                    cell: (assignment: { role: string; clientId: string | null }) => (
                      <Button
                        small
                        disabled={busy || saving}
                        onClick={() => withdraw(assignment.role, assignment.clientId)}
                      >
                        Withdraw <span className="visually-hidden">{assignment.role}</span>
                      </Button>
                    ),
                  },
                ]
              : []),
          ]}
        />
      )}
      <Dialog open={assigning} onOpenChange={setAssigning}>
        <DialogContent>
          <DialogHeader><DialogTitle>Assign application role</DialogTitle><DialogDescription>Choose a catalogue, then select the access to grant.</DialogDescription></DialogHeader>
          {refusal !== null && <Message tone="error">{refusal}</Message>}
          <form onSubmit={(event) => { event.preventDefault(); assign(); }}>
            <Field label="Catalogue">{(props) => <FormSelect {...props} name="client_id" value={owner}
              disabled={busy || saving} onValueChange={(value) => { setOwner(value); setChosen(''); }}
              options={[{ value: '', label: 'Tenant · every application' }, ...clients.map((id) => ({ value: id, label: id }))]} />}</Field>
            <Field label="Find a role">{(props) => <input {...props} type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search roles" />}</Field>
            <div className="role-picker" role="radiogroup" aria-label="Available roles">
              {offered.filter((role) => `${role.name} ${role.description ?? ''}`.toLowerCase().includes(search.toLowerCase())).map((role) => (
                <label className="role-choice" key={role.name}>
                  <input type="radio" name="role" value={role.name} checked={chosen === role.name} disabled={busy || saving} onChange={() => setChosen(role.name)} />
                  <span><strong>{role.name}</strong><small>{role.description ?? 'No description provided.'}</small></span>
                </label>
              ))}
              {offered.length === 0 && <p className="muted">No unassigned roles in this catalogue. Create roles in tenant or application settings.</p>}
            </div>
            <Actions end><Button onClick={() => setAssigning(false)}>Cancel</Button><Button type="submit" variant="primary" disabled={!writable || busy || saving || chosen === ''}>Assign role</Button></Actions>
          </form>
        </DialogContent>
      </Dialog>

    </Panel>
  );
}

/** Dedicated home for workspace and application role definitions. */
export function Roles({ session, client }: Readonly<{ session: Session; client?: string | null }>): JSX.Element {
  const [owner, setOwner] = useState(client ?? '');
  const [clients, setClients] = useState<readonly { client_id: string; client_name?: string }[]>([]);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { setOwner(client ?? ''); }, [client]);
  useEffect(() => {
    if (!session.scopes.includes('admin.clients:read')) return;
    let active = true;
    read('clients').then(value => { if (active) setClients((value as { items: typeof clients }).items); },
      reason => { if (active) setError(failure(reason, 'Applications could not be loaded')); });
    return () => { active = false; };
  }, [session.scopes]);
  const options = [{ value: '', label: 'Workspace · shared across applications' },
    ...clients.map(item => ({ value: item.client_id, label: item.client_name || item.client_id }))];
  if (owner !== '' && !options.some(option => option.value === owner)) options.push({ value: owner, label: owner });
  return <Screen title="Roles" description="Define access roles, then assign them to users from their profile.">
    {error !== null && <Message tone="error">{error}</Message>}
    <div className="role-scope"><Field label="Role scope" hint="Workspace roles are shared. Application roles apply to one application.">
      {props => <FormSelect {...props} value={owner} onValueChange={setOwner} options={options} />}
    </Field></div>
    <RoleCatalogue key={owner} session={session} path={owner === '' ? TENANT_CATALOGUE : clientCatalogue(owner)} title="Role definitions"
      explanation={owner === '' ? 'Roles available across this workspace.' : 'Roles available within the selected application.'} />
  </Screen>;
}
