import { DirectorySearch, DirectoryStatusFilter } from './directory-controls';
import { useViewState, useListScroll } from './view-memory';
import { useRouteParameters, setRouteParameters } from './route-state';
import { UserAccessSummary } from './user-access-summary';
import { useDialogDraft } from './dialog-draft';
import { useUnsavedChanges } from './navigation-guard';
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
 * session lookup digest (`crates/domain/src/administration.rs`). Session IDs
 * remain internal to row keys and revocation requests; operators identify a
 * session by when and how the user signed in. There is nothing on this screen to be
 * careful with, which is a property of the port rather than of this file.
 *
 * # The confirmations are the destructive ones
 *
 * Disabling an account, forcing a password reset and withdrawing a grant all
 * sign somebody out of something, and two of them send a message. Each asks
 * once, in the console's own dialog (`ui.tsx`) — which replaced `window.confirm`
 * in `ast-fe39`: the focus trap is got right once, in one component, and what is
 * about to happen can be said in the console's voice rather than in an unstyled
 * line the browser draws where the page cannot reach it. Ending a *single*
 * session does not ask: it is the reversible one, and the person signs in
 * again.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import type { JSX } from 'react';
import { mutate, read, type Session } from './api';
import { UserAppRoles, mayRead as mayReadAppRoles } from './appRoles';
import { Tabs, TabsList, TabsTrigger, TabsContent } from './components/ui/tabs';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from './components/ui/dialog';
import { toast } from './components/ui/toast';
import { JsonValue } from './components/json-view';
import {
  Actions,
  Badge,
  Button,
  ConfirmDialog,
  DataTable,
  EmptyState,
  Field,
  LoadFailure,
  Message,
  Panel,
  Screen,
  Skeleton,
  Timestamp,
  Truncate,
} from './ui';
import { emailAddress, username as usernameComplaint } from './validation';
import { UserGroups, mayReadMemberships } from './groups';
import { VerifiedClaims } from './verifiedClaims';
import { OidcBindings } from './oidc-bindings';

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
  /** Linked provider names; absent when an older server cannot report them. */
  readonly external_providers?: readonly string[];
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

/** What an administrator-assisted lost-TOTP reset did. */
export interface TotpReset extends Terminated {
  readonly factor_removed: boolean;
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

/** A sentence describing a lost-factor reset. */
export function describeTotpReset(result: TotpReset): string {
  const factor = result.factor_removed
    ? 'The authenticator was removed'
    : 'No authenticator was enrolled';
  return `${factor}. ${describeTermination(result)}`;
}

/** Whether this caller can change account claims and security settings. */
function mayManageAccount(session: Session): boolean {
  return session.scopes.includes('admin.users:write');
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

/** A live highlighted reading of a structured claim; plain strings need none. */
function ClaimJsonPreview({ text }: Readonly<{ text: string }>): JSX.Element | null {
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    return null;
  }
  if (typeof value === 'string') {
    return null;
  }
  return (
    <span className="claim-json-preview" aria-label="Structured claim preview">
      <JsonValue value={value} />
    </span>
  );
}

/** What the screen is looking at. */
type View =
  | { readonly kind: 'directory' }
  | { readonly kind: 'new' }
  | { readonly kind: 'account'; readonly id: string };

/** What a load is doing. */
type Load<T> =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly value: T }
  | { readonly kind: 'failed'; readonly message: string };

function failure(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

export function Users({ session }: Readonly<{ session: Session }>): JSX.Element {
  const parameters = useRouteParameters();
  const userId = parameters.get('id');
  const view: View = parameters.get('mode') === 'new' ? { kind: 'new' } : userId ? { kind: 'account', id: userId } : { kind: 'directory' };
  const setView = (next: View): void => setRouteParameters('users', { id: next.kind === 'account' ? next.id : null, mode: next.kind === 'new' ? 'new' : null, tab: null });
  const leave = useUnsavedChanges(false);

  if (view.kind === 'new') {
    return (
      <Screen
        title="Add a user"
        description="Create a username now. Set up sign-in methods and access from the new user's page."
        actions={<Button onClick={() => setView({ kind: 'directory' })}>Back to users</Button>}
      >
        <NewAccount
          session={session}
          onCreated={(created) => {
            toast.success('Account created', created.username);
            setView({ kind: 'account', id: created.user_id });
          }}
        />
      </Screen>
    );
  }

  if (view.kind === 'account') {
    return (
      <Account
        key={view.id}
        session={session}
        id={view.id}
        onBack={() => leave(() => setView({ kind: 'directory' }))}
      />
    );
  }
  return (
    <DirectoryScreen
      session={session}
      onNew={() => setView({ kind: 'new' })}
      onOpen={(id) => setView({ kind: 'account', id })}
    />
  );
}

/** The searchable account list. Creation has its own task-focused page. */
function DirectoryScreen({
  session,
  onNew,
  onOpen,
}: Readonly<{
  session: Session;
  onNew: () => void;
  onOpen: (id: string) => void;
}>): JSX.Element {
  const [load, setLoad] = useState<Load<Directory>>({ kind: 'loading' });
  const listRequest = useRef(0);
  useEffect(() => () => { listRequest.current++; }, []);
  const [term, setTerm] = useViewState('users:term', '');
  const [cursor, setCursor] = useViewState<string | null>('users:cursor', null);
  const [status, setStatus] = useViewState('users:status', '');
  useListScroll(`users:${term}:${status}:${cursor}`, load.kind === 'ready');

  const refresh = useCallback(
    (search: string, from: string | null) => {
      const request = ++listRequest.current;
      setLoad({ kind: 'loading' });
      const query = new URLSearchParams();
      if (status) query.set('status', status);
      if (search !== '') {
        query.set('q', search);
      }
      if (from !== null) {
        query.set('cursor', from);
      }
      const suffix = query.toString();
      read(suffix === '' ? 'users' : `users?${suffix}`).then(
        (value) => { if (request === listRequest.current) setLoad({ kind: 'ready', value: value as Directory }); },
        (error: unknown) => {
          if (request === listRequest.current) setLoad({ kind: 'failed', message: failure(error, 'the accounts could not be read') });
        },
      );
    },
    [status],
  );

  useEffect(() => refresh(term, cursor), [refresh, term, cursor]);

  return (
    <Screen
      title="Users"
      description="Find people in this tenant and manage how they sign in and what they can access."
      actions={session.scopes.includes('admin.users:write') ? (
        <Button variant="primary" onClick={onNew}>Add user</Button>
      ) : undefined}
    >
      <Panel
        className="directory-panel"
        title="Directory"
        description="Search by username or email. The list is one page at a time."
      >
        <div className="directory-toolbar"><Search initial={term}
          onSearch={(value) => {
            // A new search starts at the first page: keeping a cursor minted for
            // the previous term would resume in the middle of a different list.
            setCursor(null);
            setTerm(value);
          }}
        /><DirectoryStatusFilter value={status} options={[{ value: '', label: 'All statuses' }, { value: 'active', label: 'Active' }, { value: 'disabled', label: 'Disabled' }, { value: 'locked', label: 'Locked' }]} onChange={value => { setCursor(null); setStatus(value); }} /></div>
        {load.kind === 'loading' && <Skeleton rows={4} label="Reading the directory." />}
        {load.kind === 'failed' && (
          <LoadFailure message={load.message} onRetry={() => refresh(term, cursor)} />
        )}
        {load.kind === 'ready' && (
          <>
            <UserTable rows={load.value.items} onOpen={onOpen} />
            {(cursor !== null || load.value.next_cursor !== null) && <Actions>
              <Button variant="ghost" disabled={cursor === null} onClick={() => setCursor(null)}>
                First page
              </Button>
              <Button variant="ghost"
                disabled={load.value.next_cursor === null}
                onClick={() => setCursor(load.value.next_cursor)}
              >
                Next page
              </Button>
            </Actions>}
          </>
        )}
      </Panel>
    </Screen>
  );
}

function Search({ initial, onSearch }: Readonly<{ initial: string; onSearch: (term: string) => void }>): JSX.Element {
  const [typed, setTyped] = useState(initial);
  return <DirectorySearch label="Search" value={typed} placeholder="Search by username or email address" onChange={setTyped} onSubmit={() => onSearch(typed.trim())} />;
}

function UserTable({
  rows,
  onOpen,
}: Readonly<{
  rows: readonly UserRow[];
  onOpen: (id: string) => void;
}>): JSX.Element {
  return (
    <DataTable
      caption="Accounts"
      rows={rows}
      rowKey={(row) => row.user_id}
      empty={<EmptyState title="No account matches." body="Change the search or status filter to see more accounts." />}
      columns={[
        {
          key: 'username',
          header: 'Username',
          sortBy: (row) => row.username,
          // Truncated, with the whole of it in the `title` (`ast-f9j5`): a
          // username is often an address, an address has nowhere to break, and
          // one long row used to push "Verified" and everything after it off
          // the edge of the card.
          cell: (row) => <div className="user-identity"><span className="identity-avatar" aria-hidden="true">{row.username.slice(0, 2).toUpperCase()}</span><button className="identity-link" onClick={() => onOpen(row.user_id)}><Truncate text={row.username} className="max-w-[32ch]" /></button></div>,
        },
        {
          key: 'email',
          header: 'Email',
          sortBy: (row) => row.email ?? '',
          cell: (row) => <Truncate text={row.email ?? '—'} className="max-w-[32ch]" />,
        },
        {
          key: 'verified',
          header: 'Email status',
          cell: (row) => row.email === null ? 'Not set' : <Badge tone={row.email_verified ? 'ok' : 'warn'}>{row.email_verified ? 'Verified' : 'Not verified'}</Badge>,
        },
        {
          key: 'status',
          header: 'Status',
          sortBy: (row) => row.status,
          cell: (row) => <StatusBadge status={row.status} />,
        },
        {
          key: 'external',
          header: 'External',
          sortBy: (row) => row.external_providers?.join(', ') ?? '',
          cell: (row) => row.external_providers === undefined
            ? <span className="muted">Unknown</span>
            : row.external_providers.length === 0
              ? <span className="muted">No</span>
              : <span title={row.external_providers.join(', ')}>{row.external_providers.join(', ')}</span>,
        },
        { key: 'claims', header: 'Claims', numeric: true, sortBy: (row) => row.claims, cell: (row) => row.claims },

      ]}
    />
  );
}

/**
 * Whether an account may authenticate, as a word first and a tint second.
 *
 * The word is the same one the API uses, so an operator reading a screen and an
 * operator reading a response are reading the same vocabulary.
 */
function StatusBadge({ status }: Readonly<{ status: UserStatus }>): JSX.Element {
  let tone: 'ok' | 'warn' | 'bad' = 'bad';
  if (status === 'active') tone = 'ok';
  if (status === 'locked') tone = 'warn';
  return (
    <Badge tone={tone}>{status}</Badge>
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
 * `email_verified` is deliberately absent: the identity protocol makes it a statement
 * that the provider took affirmative steps to check the address, which nobody
 * has taken at the moment an account is typed in. It is on the claims tab,
 * where an operator asserts it about an address that already exists.
 */
function NewAccount({
  session,
  onCreated,
}: Readonly<{
  session: Session;
  onCreated: (created: UserRow) => void;
}>): JSX.Element {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  useUnsavedChanges(username !== '' || email !== '' || password !== '');
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
    <Panel id="new-account" title="New user" description="The username is their sign-in name. You can add an email address and initial password now or later.">
      {refusal !== null && <Message tone="error">{refusal}</Message>}
      <form onSubmit={submit}>
        {/* `accept_username` is what refuses one; this is the same rule said
            a round trip earlier (`ast-f9j5` (2), `validation.ts`). */}
        <Field label="Username" hint="The name this person will use to sign in." required error={usernameComplaint(username)}>
          {(props) => (
            <input
              {...props}
              name="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
            />
          )}
        </Field>
        <Field label="Email address" hint="Used for verification and recovery messages when provided." error={emailAddress(email)}>
          {(props) => (
            <input
              {...props}
              name="email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
          )}
        </Field>
        <Field
          label="Initial password (optional)"
          hint="Leave it empty for an account that will enrol a passkey. An account with no password cannot be signed into until it has a credential."
        >
          {(props) => (
            <input
              {...props}
              name="password"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          )}
        </Field>
        <Actions>
          <Button type="submit" variant="primary" disabled={busy}>
            Create user
          </Button>
        </Actions>
      </form>
    </Panel>
  );
}

/** One account: its claims, its credentials, its sessions and its grants. */
function Account({
  session,
  id,
  onBack,
}: Readonly<{
  session: Session;
  id: string;
  onBack: () => void;
}>): JSX.Element {
  const parameters = useRouteParameters();
  const tab = accountTab(parameters.get('tab'));
  const setTab = (value: string): void => setRouteParameters('users', { tab: value });
  const [load, setLoad] = useState<Load<Detail>>({ kind: 'loading' });
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // The question in front of an irreversible act, and what to do when it is
  // answered yes. One slot rather than one flag per button: two confirmations
  // are never open at once, and a component that could hold both would be a
  // second thing to close.
  const [confirming, setConfirming] = useState<Confirmation | null>(null);
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
      <Screen title="Account">
        <Panel title="Reading">
          <Skeleton rows={5} label="Reading the account." />
        </Panel>
      </Screen>
    );
  }
  if (load.kind === 'failed') {
    return (
      <Screen
        title="Account"
        actions={<Button onClick={onBack}>Back to users</Button>}
      >
        <Panel title="This account could not be read">
          <LoadFailure message={load.message} onRetry={refresh} />
        </Panel>
      </Screen>
    );
  }

  const { user, credentials, sessions, grants, roles } = load.value;
  const disabled = user.status === 'disabled';

  const toggleStatus = (): void =>
    run(
      () => mutate(`${base}/status`, 'PUT', session, { enabled: disabled }),
      (value) =>
        disabled
          ? 'The account is active again. Nothing was signed out.'
          : describeTermination((value as { terminated: Terminated }).terminated),
    );

  return (
    <Screen
      title={user.username}
      identity={user.username}
      back={{ label: 'Back to users', onClick: onBack }}
      description={<>{user.email ?? 'No email address'} · {user.status === 'active' ? 'Active account' : `${user.status[0]?.toUpperCase()}${user.status.slice(1)} account`}</>}
    >
      {notice !== null && <Message tone="success">{notice}</Message>}

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList aria-label="Account sections">
          <TabsTrigger value="details">Profile</TabsTrigger>
          <TabsTrigger value="claims">Identity data</TabsTrigger>
          <TabsTrigger value="credentials">Sign-in methods</TabsTrigger>
          <TabsTrigger value="sessions">Sessions</TabsTrigger>
          <TabsTrigger value="grants">Connected apps</TabsTrigger>
          {(mayReadAppRoles(session) || roles !== null) && <TabsTrigger value="roles">Access roles</TabsTrigger>}
          {mayReadMemberships(session) && <TabsTrigger value="groups">Groups</TabsTrigger>}
        </TabsList>
        <TabsContent value="details">
      <UserAccessSummary userId={user.user_id} grants={grants.length} session={session} />
      <Panel
        id="account-details"
        className="flat-section account-details-section"
        title="Profile"
        actions={
          mayManageAccount(session) ? (
          <>
          <Button
            variant={disabled ? 'secondary' : 'danger'}
            disabled={busy}
            onClick={() => {
              if (disabled) {
                toggleStatus();
                return;
              }
              setConfirming({
                title: 'Disable this account?',
                body: 'Disabling it ends every session it has open and tells the relying parties that took part.',
                confirmLabel: 'Disable the account',
                act: toggleStatus,
              });
            }}
          >
            {disabled ? 'Enable account' : 'Disable account'}
          </Button>
          </>
          ) : undefined
        }
      >
        <dl className="stats account-summary">
          <div className="stat"><dt>Username</dt><dd>{user.username}</dd></div>
          <div className="stat"><dt>Email address</dt><dd>{user.email ?? 'Not set'} {user.email !== null && <Badge tone={user.email_verified ? 'ok' : 'warn'}>{user.email_verified ? 'Verified' : 'Not verified'}</Badge>}</dd></div>
          <div className="stat"><dt>Signed up</dt><dd><Timestamp value={user.created_at} /></dd></div>
          <div className="stat">
            <dt>Status</dt>
            <dd>
              <StatusBadge status={user.status} />
            </dd>
          </div>
          <div className="stat">
            <dt>Last changed</dt>
            <dd><Timestamp value={user.updated_at} /></dd>
          </div>
        </dl>
      </Panel>

      {(disabled || user.email === null || !user.email_verified) && (
        <Panel className="flat-section" title="Sign-in and email diagnosis">
          {disabled && <p>This account is disabled and cannot sign in. A tenant security administrator can enable it.</p>}
          {user.email === null && <p>No email address is on the account, so verification and recovery links cannot be sent. A tenant security administrator must add an address.</p>}
          {user.email !== null && !user.email_verified && <p>This address is not verified. Verification links are single use and expire; an expired or already-used link must be replaced by a fresh verification request.</p>}
          {user.email !== null && <p>Mail status shows provider acceptance and failures without displaying message contents or tokens. An accepted message may still be filtered or undelivered by the recipient's mail service.</p>}
        </Panel>
      )}

        </TabsContent>
        <TabsContent value="claims">
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
      <VerifiedClaims session={session} userId={user.user_id} />

        </TabsContent>
        <TabsContent value="roles">
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

        </TabsContent>
        <TabsContent value="groups">
          {mayReadMemberships(session) && <UserGroups session={session} userId={user.user_id} />}
        </TabsContent>
        <TabsContent value="credentials">
      <OidcBindings session={session} userId={user.user_id} />
      <Panel className="flat-section"
        id="credentials"
        title="Sign-in methods"
        actions={
          mayManageAccount(session) ? (
          <>
          <Button
            variant="danger"
            disabled={busy}
            onClick={() =>
              setConfirming({
                title: 'Force a password reset?',
                body: 'The password stops working, every session ends, and a recovery link is emailed to this account.',
                confirmLabel: 'Force the reset',
                act: () =>
                  run(
                    () => mutate(`${base}/credentials/password/reset`, 'POST', session),
                    (value) => describeReset(value as Reset),
                  ),
              })
            }
          >
            Force a password reset
          </Button>
          <Button
            variant="danger"
            disabled={busy}
            onClick={() =>
              setConfirming({
                title: 'Reset this authenticator?',
                body: 'This requires a fresh sign-in with a user-verified passkey. The TOTP factor will be removed and every active session for this account will end. The user must set up a new authenticator after signing in.',
                confirmLabel: 'Reset authenticator',
                act: () =>
                  run(
                    () => mutate(`${base}/credentials/totp/reset`, 'POST', session),
                    (value) => describeTotpReset(value as TotpReset),
                  ),
              })
            }
          >
            Reset authenticator
          </Button>
          </>
          ) : undefined
        }
      >
        <p className="row">
          Password: <Badge tone={credentials.password ? 'ok' : 'neutral'}>
            {credentials.password ? 'set' : 'none'}
          </Badge>
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
      </Panel>

        </TabsContent>
        <TabsContent value="sessions">
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
        </TabsContent>
        <TabsContent value="grants">
        <GrantTable
          grants={grants}
          busy={busy}
          onRevoke={(grant, application) =>
            setConfirming({
              title: 'Withdraw this authorization?',
              body: `The refresh tokens for ${application} are revoked and its access tokens stop being accepted.`,
              confirmLabel: 'Withdraw it',
              act: () =>
                run(
                  () => mutate(`${base}/grants/${encodeURIComponent(grant)}`, 'DELETE', session),
                  () => `The authorization for ${application} has been withdrawn.`,
                ),
            })
          }
        />
        </TabsContent>
      </Tabs>

      {confirming !== null && (
        <ConfirmDialog
          title={confirming.title}
          body={confirming.body}
          confirmLabel={confirming.confirmLabel}
          busy={busy}
          onCancel={() => setConfirming(null)}
          onConfirm={() => {
            const act = confirming.act;
            setConfirming(null);
            act();
          }}
        />
      )}
    </Screen>
  );
}

/** A question asked before something irreversible, and the act behind it. */
interface Confirmation {
  readonly title: string;
  readonly body: string;
  readonly confirmLabel: string;
  readonly act: () => void;
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
}: Readonly<{
  session: Session;
  base: string;
  held: RolesDocument;
  isSelf: boolean;
  busy: boolean;
  onSaved: (message: string) => void;
}>): JSX.Element {
  const [editing, setEditing] = useState(false);
  const [chosen, setChosen] = useState<readonly string[]>(held.roles);
  const [saving, setSaving] = useState(false);
  const mayWrite = session.scopes.includes('admin.roles:write') && !isSelf;
  const roleDraft = useDialogDraft(editing && JSON.stringify([...chosen].sort()) !== JSON.stringify([...held.roles].sort()), busy || saving, () => setEditing(false));

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
        setEditing(false);
        onSaved('The roles this account holds have been replaced.');
      },
      (error: unknown) => {
        setSaving(false);
        onSaved(failure(error, 'the roles were not changed'));
      },
    );
  };

  return (
    <Panel
      className="flat-section"
      id="roles"
      title="Administrative roles"
      description="Permissions to administer Asterius. Managed separately from application access."
      actions={mayWrite ? <Button onClick={() => { setChosen(held.roles); setEditing(true); }}>Manage roles</Button> : undefined}
    >
      {isSelf && (
        <Message tone="info">Nobody may change their own roles. Ask another administrator.</Message>
      )}
      <div className="table-wrap"><table>
        <thead><tr><th>Role name</th><th>Assignment</th></tr></thead>
        <tbody>{held.roles.length === 0 ? <tr><td colSpan={2} className="table-empty">No administrative roles assigned.</td></tr> : held.roles.map((role) => <tr key={role}><td>{role}</td><td>Direct</td></tr>)}</tbody>
      </table></div>
      <Dialog open={editing} onOpenChange={open => { if (!open) roleDraft.requestClose(); }}>
        <DialogContent>
          {roleDraft.confirmation}
          <DialogHeader><DialogTitle>Manage administrative roles</DialogTitle><DialogDescription>Select the roles this account should hold.</DialogDescription></DialogHeader>
      <ul className="switches">
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
        <Actions>
          <Button variant="primary" disabled={busy || saving} onClick={save}>
            Save roles
          </Button>
        </Actions>
      )}
        </DialogContent>
      </Dialog>
    </Panel>
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
}: Readonly<{
  session: Session;
  base: string;
  user: UserDocument;
  busy: boolean;
  onSaved: (message: string) => void;
}>): JSX.Element {
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
  useUnsavedChanges(email !== (user.email ?? '') || emailVerified !== user.email_verified || JSON.stringify(claims) !== JSON.stringify(initial()));
  const [refusal, setRefusal] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);

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
      () => { setEditing(false); onSaved('The claims were saved.'); },
      (error: unknown) => setRefusal(failure(error, 'the claims were refused')),
    );
  };

  return (
    <Panel className="flat-section" id="claims" title="Claims" actions={session.scopes.includes('admin.users:write') && !editing ? <Button onClick={() => setEditing(true)}>Edit identity data</Button> : undefined}>
      {refusal !== null && <Message tone="error">{refusal}</Message>}
      {!editing ? <div className="read-summary"><dl className="stats"><div><dt>Email</dt><dd>{user.email ?? 'Not set'}</dd></div><div><dt>Email verified</dt><dd>{user.email_verified ? 'Yes' : 'No'}</dd></div></dl>
        <h4>Saved claims</h4>{Object.keys(user.claims).length === 0 ? <p className="muted">No additional claims.</p> : <dl className="stats">{Object.entries(user.claims).map(([name, claim]) => <div key={name}><dt>{name}</dt><dd><code>{claimText(claim.value)}</code></dd></div>)}</dl>}</div> : <form onSubmit={save}>
        <Field label="Email" error={emailAddress(email)}>
          {(props) => (
            <input
              {...props}
              name="email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
          )}
        </Field>
        <ul className="switches">
          <li>
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
            <p className="muted">
              This asserts that someone here has taken active steps to check that the address
              belongs to this person. Applications that sign people in through this server are
              entitled to act on it.
            </p>
          </li>
        </ul>
        <div className="table-wrap">
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
                  <ClaimJsonPreview text={claim.text} />
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
                <td className="actions-cell">
                  <Button small onClick={() => setClaims(claims.filter((_, at) => at !== index))}>
                    Remove
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
        <Actions>
          <Button
            onClick={() => setClaims([...claims, { name: '', text: '', verified: false }])}
          >
            Add a claim
          </Button>
          <Button type="submit" variant="primary" disabled={busy}>
            Save claims
          </Button>
        </Actions>
        <p className="muted">
          A value that reads as JSON is stored as JSON; anything else is stored as a string. The
          claims this server mints for itself — <code>sub</code>, <code>iss</code>,{' '}
          <code>aud</code>, <code>acr</code>, <code>amr</code> — are refused, and so are{' '}
          <code>email</code> and <code>email_verified</code>, which have their own fields above.
        </p>
        <Button onClick={() => { setEmail(user.email ?? ''); setEmailVerified(user.email_verified); setClaims(initial()); setEditing(false); }} disabled={busy}>Cancel editing</Button>
      </form>}
    </Panel>
  );
}

function PasskeyTable({
  passkeys,
  busy,
  onRemove,
}: Readonly<{
  passkeys: readonly PasskeyRow[];
  busy: boolean;
  onRemove: (credential: string) => void;
}>): JSX.Element {
  return (
    <div className="table-wrap">
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
        {passkeys.length === 0 && <tr><td colSpan={6} className="table-empty">This user has no passkeys.</td></tr>}
        {passkeys.map((passkey) => (
          <tr key={passkey.credential_id}>
            <td>{passkey.label ?? '—'}</td>
            <td>{passkey.rp_id}</td>
            <td><Timestamp value={passkey.created_at} /></td>
            <td><Timestamp value={passkey.last_used_at} /></td>
            <td>
              <Badge tone={passkey.disabled_at === null ? 'ok' : 'bad'}>
                {passkey.disabled_at === null ? 'usable' : 'blocked'}
              </Badge>
            </td>
            <td className="actions-cell">
              {passkey.disabled_at === null && (
                <Button small disabled={busy} onClick={() => onRemove(passkey.credential_id)}>
                  Remove
                </Button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
    </div>
  );
}

function SessionTable({
  sessions,
  busy,
  onRevoke,
}: Readonly<{
  sessions: readonly SessionRow[];
  busy: boolean;
  onRevoke: (sid: string) => void;
}>): JSX.Element {
  return (
    <div className="table-wrap">
    <table>
      <thead>
        <tr>
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
        {sessions.length === 0 && <tr><td colSpan={6} className="table-empty">This user has no sessions.</td></tr>}
        {sessions.map((row) => (
          <tr key={row.sid}>
            <td><Timestamp value={row.authenticated_at} /></td>
            <td><Timestamp value={row.last_seen_at} /></td>
            <td><Timestamp value={row.expires_at} /></td>
            <td>{row.amr.length === 0 ? '—' : row.amr.join(', ')}</td>
            <td>
              <Badge tone={row.live ? 'ok' : 'neutral'}>
                {row.live ? 'live' : (row.revoked_reason ?? 'ended')}
              </Badge>
            </td>
            <td className="actions-cell">
              {row.live && (
                <Button small disabled={busy} onClick={() => onRevoke(row.sid)}>
                  End session
                </Button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
    </div>
  );
}

function GrantTable({
  grants,
  busy,
  onRevoke,
}: Readonly<{
  grants: readonly GrantRow[];
  busy: boolean;
  onRevoke: (grant: string, application: string) => void;
}>): JSX.Element {
  return (
    <div className="table-wrap">
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
        {grants.length === 0 && <tr><td colSpan={5} className="table-empty">This user has no authorizations.</td></tr>}
        {grants.map((grant, index) => (
          <tr key={grant.grant_id}>
            <td>
              Application {index + 1}
            </td>
            <td>{grant.scopes.length === 0 ? '—' : grant.scopes.join(' ')}</td>
            <td><Timestamp value={grant.created_at} /></td>
            <td>
              {grant.revoked_at === null ? (
                <Badge tone="ok">active</Badge>
              ) : (
                <span className="muted">withdrawn <Timestamp value={grant.revoked_at} /></span>
              )}
            </td>
            <td className="actions-cell">
              {grant.revoked_at === null && (
                <Button
                  small
                  disabled={busy}
                  onClick={() => onRevoke(grant.grant_id, `Application ${index + 1}`)}
                >
                  Withdraw
                </Button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
    </div>
  );
}

function accountTab(value: string | null): string {
  return value !== null && ['details', 'claims', 'credentials', 'sessions', 'grants', 'roles', 'groups'].includes(value) ? value : 'details';
}
