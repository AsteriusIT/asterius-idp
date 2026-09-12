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
import {
  Actions,
  Button,
  EmptyState,
  Field,
  LoadFailure,
  Message,
  Panel,
  Skeleton,
} from './ui';

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
}: {
  session: Session;
  path: string;
  title: string;
  explanation: string;
}): JSX.Element {
  const [load, setLoad] = useState<Load<Catalogue>>({ kind: 'loading' });
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
        setName('');
        setDescription('');
        setNotice(`${body.name as string} is in the catalogue.`);
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
    <Panel id={`catalogue-${path}`} title={title} description={explanation}>
      {notice !== null && <Message tone="success">{notice}</Message>}
      {refusal !== null && <Message tone="error">{refusal}</Message>}
      {load.kind === 'loading' && <Skeleton rows={3} label="Reading the catalogue." />}
      {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
      {load.kind === 'ready' && load.value.roles.length === 0 && (
        <EmptyState
          title="No role has been defined here yet."
          body="A role defined here is a name this tenant's applications authorise against."
        />
      )}
      {load.kind === 'ready' && load.value.roles.length > 0 && (
        <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Role</th>
              <th scope="col">What it is for</th>
              {writable && <th scope="col">Delete</th>}
            </tr>
          </thead>
          <tbody>
            {load.value.roles.map((role) => (
              <tr key={role.name}>
                <td>
                  <code>{role.name}</code>
                </td>
                <td>{role.description ?? ''}</td>
                {writable && (
                  <td className="actions-cell">
                    <Button small disabled={busy} onClick={() => remove(role.name)}>
                      Delete
                    </Button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      )}
      {writable && (
        <form
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            create();
          }}
        >
          <fieldset disabled={busy}>
            <legend>Define a role</legend>
            <Field
              label="Name"
              hint={
                <>
                  Lower case, digits and <code>-_.:</code>, up to 64 characters. The name is
                  copied verbatim into tokens, so the server refuses anything a resource server
                  could read as two roles.
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
              label="What it is for"
              hint="For whoever assigns it. It is never issued in a token."
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
              <Button type="submit" variant="primary" disabled={busy || name.trim() === ''}>
                Define role
              </Button>
            </Actions>
          </fieldset>
        </form>
      )}
    </Panel>
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
}: {
  session: Session;
  userId: string;
  busy: boolean;
  onChanged: (message: string) => void;
}): JSX.Element {
  const [load, setLoad] = useState<Load<HeldRoles>>({ kind: 'loading' });
  const [catalogue, setCatalogue] = useState<readonly AppRole[]>([]);
  const [clients, setClients] = useState<readonly string[]>([]);
  /** Which catalogue the form is picking from: `''` is the tenant's. */
  const [owner, setOwner] = useState('');
  const [chosen, setChosen] = useState('');
  const [refusal, setRefusal] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
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
    <Panel
      id="app-roles"
      title="Application roles"
      description={
        <>
          What this account may do <em>in the tenant&rsquo;s applications</em>, issued in the{' '}
          <code>roles</code> and <code>resource_access</code> claims. Administering this server is
          the separate list above.
        </>
      }
    >
      {refusal !== null && <Message tone="error">{refusal}</Message>}
      {load.kind === 'loading' && <Skeleton rows={3} label="Reading the assignments." />}
      {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
      {load.kind === 'ready' && held.length === 0 && (
        <EmptyState title="This account holds no application role." />
      )}
      {load.kind === 'ready' && held.length > 0 && (
        <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Role</th>
              <th scope="col">Catalogue</th>
              {writable && <th scope="col">Withdraw</th>}
            </tr>
          </thead>
          <tbody>
            {held.map((assignment) => (
              <tr key={`${assignment.clientId ?? ''}:${assignment.role}`}>
                <td>
                  <code>{assignment.role}</code>
                </td>
                <td>
                  {assignment.clientId === null ? (
                    'the tenant'
                  ) : (
                    <code>{assignment.clientId}</code>
                  )}
                </td>
                {writable && (
                  <td className="actions-cell">
                    <Button
                      small
                      disabled={busy || saving}
                      onClick={() => withdraw(assignment.role, assignment.clientId)}
                    >
                      Withdraw
                    </Button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      )}
      {writable && (
        <form
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            assign();
          }}
        >
          <div className="toolbar">
            <Field label="Catalogue">
              {(props) => (
                <select
                  {...props}
                  name="client_id"
                  value={owner}
                  disabled={busy || saving}
                  onChange={(event) => {
                    setOwner(event.target.value);
                    setChosen('');
                  }}
                >
                  <option value="">the tenant (every application)</option>
                  {clients.map((clientId) => (
                    <option key={clientId} value={clientId}>
                      {clientId}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            <Field label="Role">
              {(props) => (
                <select
                  {...props}
                  name="name"
                  value={chosen}
                  disabled={busy || saving || offered.length === 0}
                  onChange={(event) => setChosen(event.target.value)}
                >
                  <option value="">Choose a role</option>
                  {offered.map((role) => (
                    <option key={role.name} value={role.name}>
                      {role.name}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            <Button type="submit" variant="primary" disabled={busy || saving || chosen === ''}>
              Assign
            </Button>
          </div>
          {offered.length === 0 && (
            <p className="muted">
              This catalogue has nothing left to give. A tenant role is defined on the tenant
              settings screen and a client&rsquo;s own roles on the client screen.
            </p>
          )}
        </form>
      )}
    </Panel>
  );
}
