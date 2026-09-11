/**
 * The account screen (`ast-f7m.6`).
 *
 * The directory, one account's claims and verification flags, what it can sign
 * in with, the sessions it has open and the authorizations it has granted —
 * with the four things an operator does about them: create, disable, revoke a
 * session, withdraw a grant.
 *
 * # Nothing here is a security control
 *
 * The same rule the key screen and the navigation state. A button this file
 * hides is a *usability* decision; the server refuses every one of these
 * operations independently against the authority the route declares
 * (`crates/admin-api/src/rbac.rs`), so this file being wrong would be a
 * confusing screen rather than an unauthorised change.
 *
 * # No credential can reach this file
 *
 * The API serves none. The port behind these routes answers with summaries
 * that carry no password hash, no public key, no signature counter and no
 * session lookup digest (`crates/domain/src/administration.rs`), so a session
 * is named here by the `sid` every participating relying party already holds
 * and a passkey by its credential row. There is nothing on this screen to be
 * careful with, which is a property of the port rather than of this file.
 *
 * # The confirmations are the destructive ones
 *
 * Disabling an account, forcing a password reset and withdrawing a grant all
 * sign somebody out of something, and two of them send a message. Each asks
 * once, in a `window.confirm`, because the alternative — a modal of our own —
 * is a focus trap to get right for no benefit an administrator would name.
 * Ending a *single* session does not ask: it is the reversible one, and the
 * person signs in again.
 */
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { mutate, read, type Session } from './api';
import { UserAppRoles, mayRead as mayReadAppRoles } from './appRoles';

/** Whether an account may authenticate, mirroring `UserStatus`. */
export type UserStatus = 'active' | 'disabled' | 'locked';

/** One account, as the directory lists it. */
export interface UserRow {
  readonly user_id: string;
  readonly username: string;
  readonly email: string | null;
  readonly email_verified: boolean;
  readonly status: UserStatus;
  readonly can_authenticate: boolean;
  readonly claims: number;
  readonly created_at: number;
  readonly updated_at: number;
}

/** One claim, with the provenance an operator judges it by. */
export interface ClaimRow {
  readonly value: unknown;
  readonly source: string;
  readonly verified_at: number | null;
}

/** One account, with its claims. */
export interface UserDocument extends Omit<UserRow, 'claims'> {
  readonly claims: Readonly<Record<string, ClaimRow>>;
}

/** One page of the directory. */
export interface Directory {
  readonly items: readonly UserRow[];
  readonly next_cursor: string | null;
}

/** One browser session. */
export interface SessionRow {
  readonly sid: string;
  readonly created_at: number;
  readonly authenticated_at: number;
  readonly last_seen_at: number;
  readonly expires_at: number;
  readonly amr: readonly string[];
  readonly acr: string | null;
  readonly live: boolean;
  readonly revoked_at: number | null;
  readonly revoked_reason: string | null;
}

/** One authorization. */
export interface GrantRow {
  readonly grant_id: string;
  readonly client_id: string;
  readonly scopes: readonly string[];
  readonly resources: readonly string[];
  readonly created_at: number;
  readonly updated_at: number;
  readonly expires_at: number | null;
  readonly revoked_at: number | null;
}

/** One passkey. */
export interface PasskeyRow {
  readonly credential_id: string;
  readonly label: string | null;
  readonly rp_id: string;
  readonly created_at: number;
  readonly last_used_at: number | null;
  readonly disabled_at: number | null;
}

/** What this account can sign in with. */
export interface Credentials {
  readonly password: boolean;
  readonly passkeys: readonly PasskeyRow[];
}

/** What a revocation reports. */
export interface Terminated {
  readonly sessions_revoked: number;
  readonly logout_tokens_queued: number;
}

/** What forcing a reset reports. */
export interface Reset extends Terminated {
  readonly password_invalidated: boolean;
  readonly recovery_sent: boolean;
}

/**
 * What one account administers (`ast-3t8`).
 *
 * `grantable` comes from the server and is not a constant here: a
 * deployment-scoped role may only be offered to a caller who already holds
 * authority over the deployment, and a console keeping its own copy of that
 * rule would draw a checkbox whose save is a 403.
 */
export interface RolesDocument {
  readonly roles: readonly string[];
  readonly grantable: readonly string[];
}

/** Everything one account's tabs need, read in one pass. */
interface Detail {
  readonly user: UserDocument;
  readonly credentials: Credentials;
  readonly sessions: readonly SessionRow[];
  readonly grants: readonly GrantRow[];
  /** `null` when the caller may not read who administers this tenant. */
  readonly roles: RolesDocument | null;
}

/**
 * A sentence describing what a revocation did.
 *
 * The logout tokens are reported as *queued* and never as delivered, because
 * that is what the number means: delivery is the outbox's, is retried, and may
 * end in a dead letter (which the dead-letter screen shows). An operator told
 * "3 relying parties notified" would believe a stronger statement than this
 * server can make.
 */
export function describeTermination(result: Terminated): string {
  const sessions =
    result.sessions_revoked === 1 ? '1 session ended' : `${result.sessions_revoked} sessions ended`;
  if (result.logout_tokens_queued === 0) {
    return `${sessions}. No relying party had registered a back-channel logout endpoint.`;
  }
  const tokens =
    result.logout_tokens_queued === 1
      ? '1 logout token queued'
      : `${result.logout_tokens_queued} logout tokens queued`;
  return `${sessions}; ${tokens} for delivery to the relying parties that took part.`;
}

/** A sentence describing what a forced reset did. */
export function describeReset(result: Reset): string {
  const password = result.password_invalidated
    ? 'The password no longer works'
    : 'This account had no password to invalidate';
  const mail = result.recovery_sent
    ? 'a recovery link has been sent'
    : 'no recovery link could be sent — this account has no email address';
  return `${password}; ${mail}. ${describeTermination(result)}`;
}

/** An instant, as a person reads it. */
export function moment(seconds: number | null): string {
  return seconds === null ? 'never' : new Date(seconds * 1000).toISOString();
}

/**
 * A claim value as text for the editor.
 *
 * A string claim is edited as itself and anything else as JSON: an operator
 * editing `name` should not have to type the quotes, and one editing an
 * `address` object must be able to see its shape. `parseClaimValue` is the
 * inverse and is deliberately forgiving in the same one direction.
 */
export function claimText(value: unknown): string {
  return typeof value === 'string' ? value : JSON.stringify(value);
}

/**
 * The inverse of {@link claimText}.
 *
 * Text that parses as JSON is sent as that JSON; anything else is sent as a
 * string. So `London` is a string, `42` is a number and `{"a":1}` is an
 * object — and a value the server refuses comes back as a 400 naming the
 * claim, which is the failure this function is allowed to have.
 */
export function parseClaimValue(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

/** What the screen is looking at. */
type View =
  | { readonly kind: 'directory' }
  | { readonly kind: 'account'; readonly id: string };

/** What a load is doing. */
type Load<T> =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly value: T }
  | { readonly kind: 'failed'; readonly message: string };

function failure(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

export function Users({ session }: { session: Session }): JSX.Element {
  const [view, setView] = useState<View>({ kind: 'directory' });

  if (view.kind === 'account') {
    return (
      <Account
        session={session}
        id={view.id}
        onBack={() => setView({ kind: 'directory' })}
      />
    );
  }
  return <DirectoryScreen session={session} onOpen={(id) => setView({ kind: 'account', id })} />;
}

/** The searchable list, and the form that adds to it. */
function DirectoryScreen({
  session,
  onOpen,
}: {
  session: Session;
  onOpen: (id: string) => void;
}): JSX.Element {
  const [load, setLoad] = useState<Load<Directory>>({ kind: 'loading' });
  const [term, setTerm] = useState('');
  const [cursor, setCursor] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = useCallback(
    (search: string, from: string | null) => {
      setLoad({ kind: 'loading' });
      const query = new URLSearchParams();
      if (search !== '') {
        query.set('q', search);
      }
      if (from !== null) {
        query.set('cursor', from);
      }
      const suffix = query.toString();
      read(suffix === '' ? 'users' : `users?${suffix}`).then(
        (value) => setLoad({ kind: 'ready', value: value as Directory }),
        (error: unknown) =>
          setLoad({ kind: 'failed', message: failure(error, 'the accounts could not be read') }),
      );
    },
    [],
  );

  useEffect(() => refresh(term, cursor), [refresh, term, cursor]);

  return (
    <>
      <h2>Users</h2>
      {notice !== null && (
        <p role="status" aria-live="polite">
          {notice}
        </p>
      )}
      <Search
        onSearch={(value) => {
          // A new search starts at the first page: keeping a cursor minted for
          // the previous term would resume in the middle of a different list.
          setCursor(null);
          setTerm(value);
        }}
      />
      {load.kind === 'loading' && <p>Reading the directory.</p>}
      {load.kind === 'failed' && (
        <>
          <p>{load.message}</p>
          <button type="button" onClick={() => refresh(term, cursor)}>
            Try again
          </button>
        </>
      )}
      {load.kind === 'ready' && (
        <>
          <UserTable rows={load.value.items} onOpen={onOpen} />
          <p>
            <button
              type="button"
              disabled={cursor === null}
              onClick={() => setCursor(null)}
            >
              First page
            </button>{' '}
            <button
              type="button"
              disabled={load.value.next_cursor === null}
              onClick={() => setCursor(load.value.next_cursor)}
            >
              Next page
            </button>
          </p>
        </>
      )}
      <NewAccount
        session={session}
        onCreated={(created) => {
          setNotice(`${created.username} was created.`);
          setCursor(null);
          refresh(term, null);
        }}
      />
    </>
  );
}

function Search({ onSearch }: { onSearch: (term: string) => void }): JSX.Element {
  const [typed, setTyped] = useState('');
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSearch(typed.trim());
      }}
    >
      <label htmlFor="user-search">Search</label>{' '}
      <input
        id="user-search"
        name="q"
        type="search"
        value={typed}
        placeholder="username or email"
        onChange={(event) => setTyped(event.target.value)}
      />{' '}
      <button type="submit">Search</button>
    </form>
  );
}

function UserTable({
  rows,
  onOpen,
}: {
  rows: readonly UserRow[];
  onOpen: (id: string) => void;
}): JSX.Element {
  if (rows.length === 0) {
    return <p>No account matches.</p>;
  }
  return (
    <table>
      <thead>
        <tr>
          <th scope="col">Username</th>
          <th scope="col">Email</th>
          <th scope="col">Verified</th>
          <th scope="col">Status</th>
          <th scope="col">Claims</th>
          <th scope="col">
            <span className="visually-hidden">Actions</span>
          </th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.user_id}>
            <td>{row.username}</td>
            <td>{row.email ?? '—'}</td>
            <td>{row.email_verified ? 'yes' : 'no'}</td>
            <td>{row.status}</td>
            <td>{row.claims}</td>
            <td>
              <button type="button" onClick={() => onOpen(row.user_id)}>
                Open
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/**
 * The creation form.
 *
 * The password field is optional and is the *only* place this console sends
 * one. It is checked against the deployment's own policy on the server — the
 * deny list included (`ast-895`) — and a refusal is rendered verbatim, because
 * an administrator creating an account should be told why a password was
 * refused: there is no account to enumerate, and "refused" with no reason is
 * how somebody ends up trying six variations of the same weak passphrase.
 *
 * `email_verified` is deliberately absent: OIDC Core §5.1 makes it a statement
 * that the provider took affirmative steps to check the address, which nobody
 * has taken at the moment an account is typed in. It is on the claims tab,
 * where an operator asserts it about an address that already exists.
 */
function NewAccount({
  session,
  onCreated,
}: {
  session: Session;
  onCreated: (created: UserRow) => void;
}): JSX.Element {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [refusal, setRefusal] = useState<string | null>(null);

  const submit = (event: React.FormEvent): void => {
    event.preventDefault();
    setBusy(true);
    setRefusal(null);
    const body: Record<string, unknown> = { username: username.trim() };
    if (email.trim() !== '') {
      body.email = email.trim();
    }
    if (password !== '') {
      body.password = password;
    }
    mutate('users', 'POST', session, body).then(
      (created) => {
        setBusy(false);
        setUsername('');
        setEmail('');
        setPassword('');
        onCreated(created as UserRow);
      },
      (error: unknown) => {
        setBusy(false);
        setRefusal(failure(error, 'the account was refused'));
      },
    );
  };

  return (
    <section aria-labelledby="new-account">
      <h3 id="new-account">Add an account</h3>
      {refusal !== null && (
        <p role="alert">{refusal}</p>
      )}
      <form onSubmit={submit}>
        <p>
          <label htmlFor="new-username">Username</label>{' '}
          <input
            id="new-username"
            name="username"
            required
            value={username}
            onChange={(event) => setUsername(event.target.value)}
          />
        </p>
        <p>
          <label htmlFor="new-email">Email</label>{' '}
          <input
            id="new-email"
            name="email"
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
        </p>
        <p>
          <label htmlFor="new-password">Password</label>{' '}
          <input
            id="new-password"
            name="password"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </p>
        <p className="muted">
          Leave the password empty for an account that will enrol a passkey. An account with no
          password cannot be signed into until it has a credential.
        </p>
        <p>
          <button type="submit" disabled={busy}>
            Create account
          </button>
        </p>
      </form>
    </section>
  );
}

/** One account: its claims, its credentials, its sessions and its grants. */
function Account({
  session,
  id,
  onBack,
}: {
  session: Session;
  id: string;
  onBack: () => void;
}): JSX.Element {
  const [load, setLoad] = useState<Load<Detail>>({ kind: 'loading' });
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const base = `users/${encodeURIComponent(id)}`;

  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    Promise.all([
      read(base),
      read(`${base}/credentials`),
      read(`${base}/sessions`),
      read(`${base}/grants`),
      // Asked for only when the caller holds the scope. A read that would be
      // refused is not made rather than made and swallowed: a 403 inside a
      // `Promise.all` would fail the whole screen, and catching it would hide
      // the refusals that do mean something.
      session.scopes.includes('admin.roles:read') ? read(`${base}/roles`) : Promise.resolve(null),
    ]).then(
      ([user, credentials, sessions, grants, roles]) =>
        setLoad({
          kind: 'ready',
          value: {
            user: user as UserDocument,
            credentials: credentials as Credentials,
            sessions: (sessions as { items: readonly SessionRow[] }).items,
            grants: (grants as { items: readonly GrantRow[] }).items,
            roles: roles as RolesDocument | null,
          },
        }),
      (error: unknown) =>
        setLoad({ kind: 'failed', message: failure(error, 'the account could not be read') }),
    );
  }, [base, session.scopes]);

  useEffect(refresh, [refresh]);

  /**
   * Runs one change, then re-reads.
   *
   * Always re-reads rather than patching state in place, for the reason the key
   * screen gives: the server is the only thing that knows what state the
   * account ended in, and a screen that guessed would show a session as live
   * after the revocation that ended it.
   */
  const run = (action: () => Promise<unknown>, describe: (value: unknown) => string): void => {
    setBusy(true);
    setNotice(null);
    action().then(
      (value) => {
        setNotice(describe(value));
        setBusy(false);
        refresh();
      },
      (error: unknown) => {
        setNotice(failure(error, 'the change was refused'));
        setBusy(false);
      },
    );
  };

  if (load.kind === 'loading') {
    return (
      <>
        <h2>Account</h2>
        <p>Reading the account.</p>
      </>
    );
  }
  if (load.kind === 'failed') {
    return (
      <>
        <h2>Account</h2>
        <p>{load.message}</p>
        <button type="button" onClick={onBack}>
          Back to users
        </button>
      </>
    );
  }

  const { user, credentials, sessions, grants, roles } = load.value;
  const disabled = user.status === 'disabled';

  return (
    <>
      <h2>{user.username}</h2>
      <p>
        <button type="button" onClick={onBack}>
          Back to users
        </button>
      </p>
      {notice !== null && (
        <p role="status" aria-live="polite">
          {notice}
        </p>
      )}

      <dl>
        <dt>Status</dt>
        <dd>{user.status}</dd>
        <dt>Created</dt>
        <dd>{moment(user.created_at)}</dd>
        <dt>Last changed</dt>
        <dd>{moment(user.updated_at)}</dd>
      </dl>

      <p>
        <button
          type="button"
          disabled={busy}
          onClick={() => {
            if (
              !disabled &&
              !window.confirm(
                'Disabling this account ends every session it has open and tells the relying parties that took part. Continue?',
              )
            ) {
              return;
            }
            run(
              () => mutate(`${base}/status`, 'PUT', session, { enabled: disabled }),
              (value) =>
                disabled
                  ? 'The account is active again. Nothing was signed out.'
                  : describeTermination(
                      (value as { terminated: Terminated }).terminated,
                    ),
            );
          }}
        >
          {disabled ? 'Enable account' : 'Disable account'}
        </button>
      </p>

      <ClaimsEditor
        session={session}
        base={base}
        user={user}
        busy={busy}
        onSaved={(message) => {
          setNotice(message);
          refresh();
        }}
      />

      {/*
        `ast-mqt`. Beside the administrative roles and never merged with them:
        `admin.app_roles:*` delegates the tenant's own vocabulary, and
        `admin.roles:*` delegates the authority to administer this server. The
        section is drawn only for a caller who may read it — a scope this
        console checks for courtesy and the server checks for real.
      */}
      {mayReadAppRoles(session) && (
        <UserAppRoles
          session={session}
          userId={user.user_id}
          busy={busy}
          onChanged={(message) => {
            setNotice(message);
          }}
        />
      )}

      {roles !== null && (
        <RoleEditor
          session={session}
          base={base}
          held={roles}
          isSelf={user.user_id === session.user}
          busy={busy}
          onSaved={(message) => {
            setNotice(message);
            refresh();
          }}
        />
      )}

      <section aria-labelledby="credentials">
        <h3 id="credentials">Credentials</h3>
        <p>Password: {credentials.password ? 'set' : 'none'}</p>
        <p>
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              if (
                !window.confirm(
                  'Forcing a reset invalidates the password, ends every session and emails a recovery link. Continue?',
                )
              ) {
                return;
              }
              run(
                () => mutate(`${base}/credentials/password/reset`, 'POST', session),
                (value) => describeReset(value as Reset),
              );
            }}
          >
            Force a password reset
          </button>
        </p>
        <PasskeyTable
          passkeys={credentials.passkeys}
          busy={busy}
          onRemove={(credential) =>
            run(
              () =>
                mutate(
                  `${base}/credentials/passkeys/${encodeURIComponent(credential)}`,
                  'DELETE',
                  session,
                ),
              () => 'The passkey can no longer be used to sign in.',
            )
          }
        />
      </section>

      <section aria-labelledby="sessions">
        <h3 id="sessions">Sessions</h3>
        <SessionTable
          sessions={sessions}
          busy={busy}
          onRevoke={(sid) =>
            run(
              () => mutate(`${base}/sessions/${encodeURIComponent(sid)}`, 'DELETE', session),
              (value) => describeTermination(value as Terminated),
            )
          }
        />
      </section>

      <section aria-labelledby="grants">
        <h3 id="grants">Authorizations</h3>
        <GrantTable
          grants={grants}
          busy={busy}
          onRevoke={(grant, client) => {
            if (
              !window.confirm(
                `Withdrawing this authorization revokes the refresh tokens ${client} holds and stops its access tokens being accepted. Continue?`,
              )
            ) {
              return;
            }
            run(
              () => mutate(`${base}/grants/${encodeURIComponent(grant)}`, 'DELETE', session),
              () => `The authorization ${client} held has been withdrawn.`,
            );
          }}
        />
      </section>
    </>
  );
}

/**
 * What this account administers, as a set of checkboxes (`ast-3t8`).
 *
 * Three things this screen does *not* decide, and each is the server's answer
 * arriving in the document or in the session:
 *
 * * which roles may be offered at all — `grantable`, which omits the
 *   deployment-wide role unless the caller already holds authority over the
 *   deployment;
 * * whether they may be changed — `admin.roles:write`, which a support agent
 *   does not hold, so the checkboxes are shown read-only rather than hidden:
 *   "who administers this tenant" is worth reading even when it is not yours
 *   to change;
 * * whether this is the caller's own account, which the server refuses to let
 *   anybody edit. Saying so here rather than letting the save 403 is the only
 *   part of that rule this file is allowed to know, and it is a label and not
 *   a control.
 */
function RoleEditor({
  session,
  base,
  held,
  isSelf,
  busy,
  onSaved,
}: {
  session: Session;
  base: string;
  held: RolesDocument;
  isSelf: boolean;
  busy: boolean;
  onSaved: (message: string) => void;
}): JSX.Element {
  const [chosen, setChosen] = useState<readonly string[]>(held.roles);
  const [saving, setSaving] = useState(false);
  const mayWrite = session.scopes.includes('admin.roles:write') && !isSelf;

  // The offered set is what the caller may grant, plus whatever this account
  // already holds: a role the caller cannot grant is still shown, ticked and
  // untouchable, because a screen that hid it would say this account holds
  // less authority than it does.
  const offered = [...new Set([...held.grantable, ...held.roles])];

  const save = (): void => {
    setSaving(true);
    mutate(`${base}/roles`, 'PUT', session, { roles: chosen }).then(
      () => {
        setSaving(false);
        onSaved('The roles this account holds have been replaced.');
      },
      (error: unknown) => {
        setSaving(false);
        onSaved(failure(error, 'the roles were not changed'));
      },
    );
  };

  return (
    <section aria-labelledby="roles">
      <h3 id="roles">Administrative roles</h3>
      {isSelf && <p>Nobody may change their own roles. Ask another administrator.</p>}
      {offered.length === 0 && <p>This account holds no administrative role.</p>}
      <ul>
        {offered.map((role) => (
          <li key={role}>
            <label>
              <input
                type="checkbox"
                checked={chosen.includes(role)}
                disabled={busy || saving || !mayWrite || !held.grantable.includes(role)}
                onChange={(event) =>
                  setChosen(
                    event.target.checked
                      ? [...chosen, role]
                      : chosen.filter((candidate) => candidate !== role),
                  )
                }
              />{' '}
              {role}
            </label>
          </li>
        ))}
      </ul>
      {mayWrite && (
        <p>
          <button type="button" disabled={busy || saving} onClick={save}>
            Save roles
          </button>
        </p>
      )}
    </section>
  );
}

/**
 * The claims and their verification flags, edited and saved as one document.
 *
 * A whole-document `PUT`, which is what the route takes: a merge would leave a
 * claim an administrator has just deleted in place, and the claim being
 * deleted is usually the one that was wrong.
 *
 * `verified` is a checkbox here and a *timestamp* in the row: the console
 * asserts "this is checked" and the server stamps when, because a verification
 * time a caller chose is not evidence of anything.
 */
function ClaimsEditor({
  session,
  base,
  user,
  busy,
  onSaved,
}: {
  session: Session;
  base: string;
  user: UserDocument;
  busy: boolean;
  onSaved: (message: string) => void;
}): JSX.Element {
  interface Editable {
    readonly name: string;
    readonly text: string;
    readonly verified: boolean;
  }

  const initial = (): readonly Editable[] =>
    Object.entries(user.claims).map(([name, claim]) => ({
      name,
      text: claimText(claim.value),
      verified: claim.verified_at !== null,
    }));

  const [email, setEmail] = useState(user.email ?? '');
  const [emailVerified, setEmailVerified] = useState(user.email_verified);
  const [claims, setClaims] = useState<readonly Editable[]>(initial);
  const [refusal, setRefusal] = useState<string | null>(null);

  const save = (event: React.FormEvent): void => {
    event.preventDefault();
    setRefusal(null);
    const body: Record<string, unknown> = {
      email_verified: emailVerified,
      claims: Object.fromEntries(
        claims
          .filter((claim) => claim.name.trim() !== '')
          .map((claim) => [
            claim.name.trim(),
            { value: parseClaimValue(claim.text), verified: claim.verified },
          ]),
      ),
    };
    if (email.trim() !== '') {
      body.email = email.trim();
    }
    mutate(`${base}/claims`, 'PUT', session, body).then(
      () => onSaved('The claims were saved.'),
      (error: unknown) => setRefusal(failure(error, 'the claims were refused')),
    );
  };

  return (
    <section aria-labelledby="claims">
      <h3 id="claims">Claims</h3>
      {refusal !== null && <p role="alert">{refusal}</p>}
      <form onSubmit={save}>
        <p>
          <label htmlFor="claim-email">Email</label>{' '}
          <input
            id="claim-email"
            name="email"
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
        </p>
        <p>
          <label htmlFor="claim-email-verified">
            <input
              id="claim-email-verified"
              name="email_verified"
              type="checkbox"
              checked={emailVerified}
              onChange={(event) => setEmailVerified(event.target.checked)}
            />{' '}
            Email verified
          </label>
        </p>
        <p className="muted">
          OIDC Core §5.1: this asserts that this deployment has taken affirmative steps to check
          that the address belongs to this person. Relying parties are entitled to act on it.
        </p>
        <table>
          <thead>
            <tr>
              <th scope="col">Claim</th>
              <th scope="col">Value</th>
              <th scope="col">Verified</th>
              <th scope="col">Asserted by</th>
              <th scope="col">
                <span className="visually-hidden">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {claims.map((claim, index) => (
              // The index is the key because the name is what an operator is
              // editing: keying on it would remount the field on every
              // keystroke and lose the caret.
              // eslint-disable-next-line react/no-array-index-key
              <tr key={index}>
                <td>
                  <label className="visually-hidden" htmlFor={`claim-name-${index}`}>
                    Claim name
                  </label>
                  <input
                    id={`claim-name-${index}`}
                    value={claim.name}
                    onChange={(event) =>
                      setClaims(
                        claims.map((held, at) =>
                          at === index ? { ...held, name: event.target.value } : held,
                        ),
                      )
                    }
                  />
                </td>
                <td>
                  <label className="visually-hidden" htmlFor={`claim-value-${index}`}>
                    Claim value
                  </label>
                  <input
                    id={`claim-value-${index}`}
                    value={claim.text}
                    onChange={(event) =>
                      setClaims(
                        claims.map((held, at) =>
                          at === index ? { ...held, text: event.target.value } : held,
                        ),
                      )
                    }
                  />
                </td>
                <td>
                  <label className="visually-hidden" htmlFor={`claim-verified-${index}`}>
                    Verified
                  </label>
                  <input
                    id={`claim-verified-${index}`}
                    type="checkbox"
                    checked={claim.verified}
                    onChange={(event) =>
                      setClaims(
                        claims.map((held, at) =>
                          at === index ? { ...held, verified: event.target.checked } : held,
                        ),
                      )
                    }
                  />
                </td>
                <td>{user.claims[claim.name]?.source ?? 'unsaved'}</td>
                <td>
                  <button
                    type="button"
                    onClick={() => setClaims(claims.filter((_, at) => at !== index))}
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p>
          <button
            type="button"
            onClick={() => setClaims([...claims, { name: '', text: '', verified: false }])}
          >
            Add a claim
          </button>{' '}
          <button type="submit" disabled={busy}>
            Save claims
          </button>
        </p>
        <p className="muted">
          A value that reads as JSON is stored as JSON; anything else is stored as a string. The
          claims this server mints for itself — <code>sub</code>, <code>iss</code>,{' '}
          <code>aud</code>, <code>acr</code>, <code>amr</code> — are refused, and so are{' '}
          <code>email</code> and <code>email_verified</code>, which have their own fields above.
        </p>
      </form>
    </section>
  );
}

function PasskeyTable({
  passkeys,
  busy,
  onRemove,
}: {
  passkeys: readonly PasskeyRow[];
  busy: boolean;
  onRemove: (credential: string) => void;
}): JSX.Element {
  if (passkeys.length === 0) {
    return <p>No passkey.</p>;
  }
  return (
    <table>
      <thead>
        <tr>
          <th scope="col">Label</th>
          <th scope="col">Relying party</th>
          <th scope="col">Enrolled</th>
          <th scope="col">Last used</th>
          <th scope="col">State</th>
          <th scope="col">
            <span className="visually-hidden">Actions</span>
          </th>
        </tr>
      </thead>
      <tbody>
        {passkeys.map((passkey) => (
          <tr key={passkey.credential_id}>
            <td>{passkey.label ?? '—'}</td>
            <td>{passkey.rp_id}</td>
            <td>{moment(passkey.created_at)}</td>
            <td>{moment(passkey.last_used_at)}</td>
            <td>{passkey.disabled_at === null ? 'usable' : 'blocked'}</td>
            <td>
              {passkey.disabled_at === null && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => onRemove(passkey.credential_id)}
                >
                  Remove
                </button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function SessionTable({
  sessions,
  busy,
  onRevoke,
}: {
  sessions: readonly SessionRow[];
  busy: boolean;
  onRevoke: (sid: string) => void;
}): JSX.Element {
  if (sessions.length === 0) {
    return <p>No session.</p>;
  }
  return (
    <table>
      <thead>
        <tr>
          <th scope="col">Session</th>
          <th scope="col">Signed in</th>
          <th scope="col">Last seen</th>
          <th scope="col">Expires</th>
          <th scope="col">How</th>
          <th scope="col">State</th>
          <th scope="col">
            <span className="visually-hidden">Actions</span>
          </th>
        </tr>
      </thead>
      <tbody>
        {sessions.map((row) => (
          <tr key={row.sid}>
            <td>
              <code>{row.sid}</code>
            </td>
            <td>{moment(row.authenticated_at)}</td>
            <td>{moment(row.last_seen_at)}</td>
            <td>{moment(row.expires_at)}</td>
            <td>{row.amr.length === 0 ? '—' : row.amr.join(', ')}</td>
            <td>{row.live ? 'live' : (row.revoked_reason ?? 'ended')}</td>
            <td>
              {row.live && (
                <button type="button" disabled={busy} onClick={() => onRevoke(row.sid)}>
                  End session
                </button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function GrantTable({
  grants,
  busy,
  onRevoke,
}: {
  grants: readonly GrantRow[];
  busy: boolean;
  onRevoke: (grant: string, client: string) => void;
}): JSX.Element {
  if (grants.length === 0) {
    return <p>No authorization.</p>;
  }
  return (
    <table>
      <thead>
        <tr>
          <th scope="col">Client</th>
          <th scope="col">Scopes</th>
          <th scope="col">Granted</th>
          <th scope="col">State</th>
          <th scope="col">
            <span className="visually-hidden">Actions</span>
          </th>
        </tr>
      </thead>
      <tbody>
        {grants.map((grant) => (
          <tr key={grant.grant_id}>
            <td>
              <code>{grant.client_id}</code>
            </td>
            <td>{grant.scopes.length === 0 ? '—' : grant.scopes.join(' ')}</td>
            <td>{moment(grant.created_at)}</td>
            <td>{grant.revoked_at === null ? 'active' : `withdrawn ${moment(grant.revoked_at)}`}</td>
            <td>
              {grant.revoked_at === null && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => onRevoke(grant.grant_id, grant.client_id)}
                >
                  Withdraw
                </button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
