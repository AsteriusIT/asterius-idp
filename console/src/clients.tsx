import { hrefOf } from './routes';
/**
 * The clients screen (`ast-f7m.5`).
 *
 * What a tenant's administrators can do to the clients registered against
 * them: find one, read its registration, register a new one, edit an existing
 * one, and take one out of service. That is the whole of what the admin API
 * serves (`GET`/`POST /clients`, `GET`/`PUT /clients/{client_id}`), and this
 * screen is deliberately no wider than that.
 *
 * # This form has no rules of its own
 *
 * Every constraint on a client — https callbacks, the closed algorithm list,
 * `jwks` xor `jwks_uri`, which grant types this deployment implements, the
 * auth methods FAPI 2.0 permits — lives in
 * `asterius_domain::ClientMetadata::validate`, below the API, and is applied to
 * a document posted from this form exactly as it is applied to one posted to
 * `/register` by a client. So the fields below are a *convenience for typing*
 * and nothing else, and when the server refuses, what is shown is the server's
 * own sentence, which names the field and the clause.
 *
 * That is why the form submits with `noValidate` and why the grant-type list is
 * a display list rather than a claim: a console that pre-empted the validator
 * would eventually disagree with it, and the version that is wrong is always
 * the one nobody re-reads.
 *
 * # What is deliberately absent
 *
 * * **A DCR policy editor.** The per-tenant registration policy model is
 *   `ast-m9c.6` and is not built; there is nothing to edit and nothing to
 *   dry-run against.
 * * **An agent profile editor.** `ast-lh3.1`; same reason.
 * * **Issuing initial access tokens.** Today an initial access token is a
 *   string in `asterius.toml`, hashed at boot. There is no row, so there is no
 *   expiry, no quota and nothing to show once. What this screen does instead is
 *   report the gate — see {@link RegistrationGate} — because "can anybody
 *   register, and on how many credentials" is a question an operator has to be
 *   able to answer.
 * * **`resources` and RAR types.** Not settable from a registration document
 *   (the per-client audience allow-list is policy, `ast-m9c.6`), so they are
 *   shown read-only where the server sends them and never posted back.
 *
 * # No third-party anything
 *
 * The console runs under a strict nonce CSP with `connect-src 'self'`
 * (ADR-0009). Every control is an ordinary form element, every handler is
 * attached by React, and nothing is fetched from anywhere but this origin.
 */
import { Tabs, TabsList, TabsTrigger, TabsContent } from './components/ui/tabs';
import { FormSelect } from './components/ui/select';
import { ArrowRightLeftIcon, KeyRoundIcon, MonitorSmartphoneIcon, RefreshCwIcon, ServerIcon, SmartphoneIcon } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { ApiError, mutate, read, type Session } from './api';
import { mayRead as mayReadAppRoles } from './appRoles';
import { toast } from './components/ui/toast';
import { JsonView } from './components/json-view';
import {
  Actions,
  Badge,
  Button,
  DataTable,
  EmptyState,
  Field,
  LoadFailure,
  Message,
  Panel,
  Screen,
  Skeleton,
} from './ui';
import { jsonDocument, redirectUris } from './validation';
import {
  documentFrom,
  draftOf,
  emptyDraft,
  type ClientDocument,
  type Draft,
} from './client-draft';

export { documentFrom, draftOf, emptyDraft, linesOf, listFrom } from './client-draft';
export type { ClientDocument, Draft } from './client-draft';

/** Where the client collection lives, relative to the API base. */
export const CLIENTS_PATH = 'clients';

/** Where the registration gate is reported. */
export const REGISTRATION_PATH = 'registration';

/**
 * The grant types this console draws a checkbox for, mirroring
 * `asterius_domain::GrantType::ALL`.
 *
 * A display list, like the feature list on the settings screen: a grant this
 * build does not implement is refused by the validator whatever this array
 * says, and a grant the server knows about that is missing here still arrives
 * in a client's document and is still rendered (see {@link grantRows}) — so
 * editing a client cannot silently drop one.
 *
 * The identifier is the value the API takes and is shown as it is typed;
 * the description beside it is the product's own words rather than a
 * citation (`ast-k7az.4`). The two `urn:ietf:…` grants are RFC 8628's and
 * RFC 8693's, and `urn:openid:…` is CIBA's.
 */
const KNOWN_GRANTS: readonly (readonly [string, string])[] = [
  ['authorization_code', 'The code flow. Almost every client wants this one.'],
  ['refresh_token', 'Refresh tokens, rotated on every use.'],
  ['client_credentials', 'Machine-to-machine, with no end user.'],
  [
    'urn:ietf:params:oauth:grant-type:device_code',
    'Sign-in on a device with no keyboard; the code is entered on another screen.',
  ],
  ['urn:openid:params:grant-type:ciba', 'CIBA backchannel authentication.'],
  [
    'urn:ietf:params:oauth:grant-type:token-exchange',
    'This client swaps one token for another to act on someone’s behalf.',
  ],
];

const GRANT_PRESENTATION: Record<string, { label: string; icon: typeof KeyRoundIcon }> = {
  authorization_code: { label: 'Authorization code', icon: KeyRoundIcon },
  refresh_token: { label: 'Refresh tokens', icon: RefreshCwIcon },
  client_credentials: { label: 'Machine to machine', icon: ServerIcon },
  'urn:ietf:params:oauth:grant-type:device_code': { label: 'Device authorization', icon: MonitorSmartphoneIcon },
  'urn:openid:params:grant-type:ciba': { label: 'Backchannel authentication', icon: SmartphoneIcon },
  'urn:ietf:params:oauth:grant-type:token-exchange': { label: 'Token exchange', icon: ArrowRightLeftIcon },
};

/** The signing algorithms this profile permits (ADR-0003, FAPI 2.0 SP §5.4.1). */
const ALGORITHMS: readonly string[] = ['EdDSA', 'ES256', 'PS256'];

/** Optional algorithm choices, including a value introduced by a newer server. */
function algorithmOptions(value: string): readonly { value: string; label: string }[] {
  const options = [
    { value: '', label: 'Not configured' },
    ...ALGORITHMS.map((algorithm) => ({ value: algorithm, label: algorithm })),
  ];
  return value === '' || ALGORITHMS.includes(value)
    ? options
    : [...options, { value, label: `${value} (unrecognized; preserved)` }];
}

/** One row of the inventory, as `GET /clients` renders it. */
export interface ClientRow {
  readonly client_id: string;
  readonly client_name: string;
  readonly application_type: string;
  readonly status: string;
  readonly token_endpoint_auth_method: string;
  readonly grant_types: readonly string[];
  readonly redirect_uris: readonly string[];
  readonly subject_type: string;
  readonly jwks_source: string;
}

/** A page of them. */
interface Page {
  readonly items: readonly ClientRow[];
  readonly next_cursor: string | null;
}

/** The registration gate, as `GET /registration` reports it. */
export interface RegistrationGate {
  readonly mode: string;
  readonly configured_tokens: number;
  readonly tokens_stored_hashed: boolean;
  readonly console_issuance: boolean;
}

/** The path of one client, relative to the API base. */
export function clientPath(clientId: string): string {
  return `${CLIENTS_PATH}/${encodeURIComponent(clientId)}`;
}

/** The list path, with a search term when there is one. */
export function listPath(query: string): string {
  const trimmed = query.trim();
  return trimmed === '' ? CLIENTS_PATH : `${CLIENTS_PATH}?q=${encodeURIComponent(trimmed)}`;
}

/**
 * Every grant checkbox to draw: the ones this build knows, plus any the client
 * already holds that it does not.
 *
 * The second half is what keeps an edit from dropping a grant somebody else's
 * release added — the `PUT` is a whole-document replacement (RFC 7592 §2.2), so
 * a checkbox that was never drawn would be a grant silently removed.
 */
export function grantRows(
  granted: readonly string[],
): readonly (readonly [string, string])[] {
  const known = new Set(KNOWN_GRANTS.map(([name]) => name));
  const unknown = granted.filter((name) => !known.has(name));
  return [
    ...KNOWN_GRANTS,
    ...unknown.map((name) => [name, 'A grant type this console does not know about.'] as const),
  ];
}

/** What the screen is doing. */
type Load =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly rows: readonly ClientRow[] }
  | { readonly kind: 'failed'; readonly message: string };

/** Which client the editor is on, if any. */
type Editing =
  | { readonly kind: 'none' }
  | { readonly kind: 'new' }
  | { readonly kind: 'existing'; readonly document: ClientDocument };

export function Clients({ session }: Readonly<{ session: Session }>): JSX.Element {
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [query, setQuery] = useState('');
  const [tab, setTab] = useState('settings');
  const [editing, setEditing] = useState<Editing>({ kind: 'none' });
  const [draft, setDraft] = useState<Draft | null>(null);
  const [gate, setGate] = useState<RegistrationGate | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(
    (term: string) => {
      setLoad({ kind: 'loading' });
      read(listPath(term)).then(
        (document) => setLoad({ kind: 'ready', rows: (document as Page).items }),
        (error: unknown) =>
          setLoad({
            kind: 'failed',
            message: error instanceof Error ? error.message : 'the clients could not be read',
          }),
      );
    },
    [],
  );

  useEffect(() => refresh(''), [refresh]);

  useEffect(() => {
    // The gate is deployment-scoped, so a tenant administrator is answered 403.
    // That is not an error to show: it is a section they do not get, and the
    // screen simply does not draw it.
    read(REGISTRATION_PATH).then(
      (document) => setGate(document as RegistrationGate),
      (error: unknown) => {
        if (!(error instanceof ApiError)) {
          setGate(null);
        }
      },
    );
  }, []);

  const openNew = useCallback(() => {
    setNotice(null);
    setRefusal(null);
    setTab('settings');
    setEditing({ kind: 'new' });
    setDraft(emptyDraft());
  }, []);

  const openExisting = useCallback((clientId: string) => {
    setNotice(null);
    setRefusal(null);
    setBusy(true);
    read(clientPath(clientId)).then(
      (body) => {
        const document = body as ClientDocument;
        setTab('settings');
        setEditing({ kind: 'existing', document });
        setDraft(draftOf(document));
        setBusy(false);
      },
      (error: unknown) => {
        setRefusal(error instanceof Error ? error.message : 'the client could not be read');
        setBusy(false);
      },
    );
  }, []);

  const close = useCallback(() => {
    setTab('settings');
    setEditing({ kind: 'none' });
    setDraft(null);
  }, []);

  const save = useCallback(
    (current: Draft, where: Editing) => {
      let document: Record<string, unknown>;
      try {
        document = documentFrom(current);
      } catch {
        const said =
          'The JWK Set box does not hold JSON. Paste the whole document, braces and all.';
        setRefusal(said);
        toast.error('The client was not sent', said);
        return;
      }

      setBusy(true);
      setNotice(null);
      setRefusal(null);
      const request =
        where.kind === 'existing'
          ? mutate(clientPath(where.document.client_id), 'PUT', session, document)
          : mutate(CLIENTS_PATH, 'POST', session, document);

      request.then(
        (body) => {
          // Re-read from the answer rather than from the form: the server's
          // document is the client that exists, including the members it
          // provisioned itself.
          const stored = body as ClientDocument;
          setEditing({ kind: 'existing', document: stored });
          setDraft(draftOf(stored));
          const said =
            where.kind === 'existing' ? 'Saved.' : `Registered as ${stored.client_id}.`;
          setNotice(said);
          // The toast announces and the `Message` at the top records
          // (`ast-f9j5` (3)). The editor is longer than a window, so an
          // operator pressing "Save client" at the bottom of it was told at
          // the top, where they were not looking.
          toast.success(
            where.kind === 'existing' ? 'Client saved' : 'Client registered',
            stored.client_id,
          );
          setBusy(false);
          refresh(query);
        },
        (error: unknown) => {
          const said = error instanceof Error ? error.message : 'the change was refused';
          setRefusal(said);
          // The refusal names a field and a clause, which is the part an
          // operator has to act on: the toast says that it happened, the
          // `Message` keeps what it said.
          toast.error('The client was not saved', said);
          setBusy(false);
        },
      );
    },
    [query, refresh, session],
  );

  if (draft !== null && editing.kind !== 'none') {
    const title = editing.kind === 'existing'
      ? `Edit ${editing.document.client_name}`
      : 'Register an application';
    return (
      <Screen
        title={title}
        identity={editing.kind === 'existing' ? editing.document.client_name : undefined}
        description={editing.kind === 'existing' ? <>Client ID: <code>{editing.document.client_id}</code></> : 'Configure authentication, callbacks, and access for your application.'}
        back={{ label: 'Back to applications', onClick: close }}
      >
        {editing.kind === 'existing' && mayReadAppRoles(session) && <a className="application-roles-link" href={hrefOf('roles', { client: editing.document.client_id })}>Manage application roles →</a>}
        {notice !== null && <Message tone="success">{notice}</Message>}
        {refusal !== null && <Message tone="error">{refusal}</Message>}
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList aria-label="Application sections">
            <TabsTrigger value="settings">Settings</TabsTrigger>
            <TabsTrigger value="callbacks">Callbacks</TabsTrigger>
            <TabsTrigger value="grants">Grant types</TabsTrigger>
            <TabsTrigger value="credentials">Credentials</TabsTrigger>
            <TabsTrigger value="tokens">Token claims</TabsTrigger>

          </TabsList>
        <div><Editor
          draft={draft}
          editing={editing}
          busy={busy}
          onChange={setDraft}
          onSubmit={() => save(draft, editing)}
          onClose={close}
        /></div>
        </Tabs>
      </Screen>
    );
  }

  return (
    <Screen
      title="Applications"
      description={
        <>
          Manage applications, authentication methods, and callback URLs for <strong>{session.workspace}</strong>.
        </>
      }
      actions={
        <Button variant="primary" onClick={openNew}>
          Register a client
        </Button>
      }
    >
      {notice !== null && <Message tone="success">{notice}</Message>}
      {refusal !== null && <Message tone="error">{refusal}</Message>}

      <Panel className="directory-panel" title="Registered clients">
        <form
          className="toolbar"
          role="search"
          onSubmit={(event) => {
            event.preventDefault();
            refresh(query);
          }}
        >
          <Field label="Search clients">
            {(props) => (
              <input
                {...props}
                name="q"
                type="search"
                value={query}
                placeholder="name, client_id or a callback"
                onChange={(event) => setQuery(event.target.value)}
              />
            )}
          </Field>
          <Button type="submit">Search</Button>
        </form>

        <Inventory load={load} onOpen={openExisting} onRetry={() => refresh(query)} busy={busy} />
      </Panel>

      {gate !== null && <Gate gate={gate} />}

      <Panel id="clients-not-here" title="Not editable yet">
        <p className="muted">
          The per-tenant registration policy (<code>ast-m9c.6</code>), the agent profile{' '}
          (<code>ast-lh3.1</code>) and the per-client resource allow-list are not served by this
          release&rsquo;s admin API, so this screen does not offer them. A control that saved
          nowhere would be worse than none.
        </p>
      </Panel>
    </Screen>
  );
}

function Inventory({
  load,
  onOpen,
  onRetry,
  busy,
}: Readonly<{
  load: Load;
  onOpen: (clientId: string) => void;
  onRetry: () => void;
  busy: boolean;
}>): JSX.Element {
  if (load.kind === 'loading') {
    return <Skeleton rows={4} label="Reading the clients." />;
  }
  if (load.kind === 'failed') {
    return <LoadFailure message={load.message} onRetry={onRetry} />;
  }

  return (
    <DataTable
      caption="Registered clients"
      rows={load.rows}
      rowKey={(row) => row.client_id}
      empty={
        <EmptyState
          title="No client matches."
          body="Clear the search to see every client registered against this tenant."
        />
      }
      columns={[
        {
          key: 'name',
          header: 'Name',
          sortBy: (row) => row.client_name,
          cell: (row) => row.client_name,
        },
        {
          key: 'client_id',
          header: 'client_id',
          sortBy: (row) => row.client_id,
          cell: (row) => <code>{row.client_id}</code>,
        },
        {
          key: 'status',
          header: 'Status',
          sortBy: (row) => row.status,
          cell: (row) => (
            <Badge tone={row.status === 'active' ? 'ok' : 'bad'}>{row.status}</Badge>
          ),
        },
        {
          key: 'auth',
          header: 'Authentication',
          cell: (row) => <code>{row.token_endpoint_auth_method}</code>,
        },
        { key: 'keys', header: 'Keys', cell: (row) => <code>{row.jwks_source}</code> },
        { key: 'grants', header: 'Grants', cell: (row) => row.grant_types.join(', ') },
        {
          key: 'edit',
          header: 'Actions',
          actions: true,
          cell: (row) => (
            <Button small disabled={busy} onClick={() => onOpen(row.client_id)}>
              Edit <span className="visually-hidden">{row.client_name}</span>
            </Button>
          ),
        },
      ]}
    />
  );
}

function Editor({
  draft,
  editing,
  busy,
  onChange,
  onSubmit,
  onClose,
}: Readonly<{
  draft: Draft;
  editing: Editing;
  busy: boolean;
  onChange: (draft: Draft) => void;
  onSubmit: () => void;
  onClose: () => void;
}>): JSX.Element {
  const heading =
    editing.kind === 'existing' ? `Editing ${editing.document.client_id}` : 'New client';
  const toggleGrant = (name: string, on: boolean): void =>
    onChange({
      ...draft,
      grant_types: on
        ? [...draft.grant_types, name]
        : draft.grant_types.filter((each) => each !== name),
    });

  return (
    <Panel className="application-editor" id="client-editor" title={heading}>
      {/*
        `noValidate`, for the reason the settings screen gives: the browser's
        own constraint validation would block a submission and show a tooltip
        that names no clause, leaving the server's sentence — the one that says
        which field and which specification — unreachable from this screen.
      */}
      <form
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit();
        }}
      >
        <TabsContent value="settings"><fieldset disabled={busy}>
          <legend id="client-identity">Identity</legend>
          <Field label="Client name" required>
            {(props) => (
              <input
                {...props}
                name="client_name"
                type="text"
                value={draft.client_name}
                onChange={(event) => onChange({ ...draft, client_name: event.target.value })}
              />
            )}
          </Field>
          <p>
            <label htmlFor="application-type">Application type</label>
            <FormSelect
              id="application-type"
              name="application_type"
              value={draft.application_type}
              onValueChange={(value) => onChange({ ...draft, application_type: value })}
             disabled={busy} options={[{"value": "web", "label": "Web application"}, {"value": "native", "label": "Native application"}]} />
          </p>
          <p>
            <label htmlFor="client-status">Status</label>
            <FormSelect
              id="client-status"
              name="status"
              value={draft.status}
              onValueChange={(value) => onChange({ ...draft, status: value })}
             disabled={busy} options={[{"value": "active", "label": "Active"}, {"value": "disabled", "label": "Disabled"}]} />
          </p>
          <p className="muted">
            A disabled client fails client authentication. Its grants and its audit trail stay.
          </p>
        </fieldset></TabsContent>

        <TabsContent value="callbacks"><fieldset disabled={busy}>
          <legend id="client-callbacks">Callbacks</legend>
          {/*
            The complaint is an echo of `RedirectUri::parse` and never a rule of
            this form's own (`ast-f9j5` (2), `validation.ts`): the submission is
            not blocked, the server still decides, and what it says is what is
            shown at the top of this screen.
          */}
          <Field
            label="Redirect URIs (one per line)"
            hint="Compared byte for byte at the authorization endpoint (ADR-0005), so a trailing slash is a different URI."
            error={redirectUris(draft.redirect_uris, draft.application_type)}
          >
            {(props) => (
              <textarea
                {...props}
                name="redirect_uris"
                rows={4}
                value={draft.redirect_uris}
                onChange={(event) => onChange({ ...draft, redirect_uris: event.target.value })}
              />
            )}
          </Field>
          <Field
            label="Post-logout redirect URIs (one per line)"
            error={redirectUris(draft.post_logout_redirect_uris, draft.application_type)}
          >
            {(props) => (
              <textarea
                {...props}
                name="post_logout_redirect_uris"
                rows={3}
                value={draft.post_logout_redirect_uris}
                onChange={(event) =>
                  onChange({ ...draft, post_logout_redirect_uris: event.target.value })
                }
              />
            )}
          </Field>
        </fieldset></TabsContent>

        <TabsContent value="grants"><fieldset disabled={busy}>
          <legend id="client-grant-types">Grant types</legend>
          <ul className="grant-options">
            {grantRows(draft.grant_types).map(([name, description]) => {
              const display = GRANT_PRESENTATION[name];
              const Icon = display?.icon ?? KeyRoundIcon;
              return <li key={name}>
                <label className={draft.grant_types.includes(name) ? 'grant-option selected' : 'grant-option'}>
                  <Icon aria-hidden="true" />
                  <span><strong>{display?.label ?? name}</strong><small>{description}</small><code>{name}</code></span>
                  <input type="checkbox" name={name} checked={draft.grant_types.includes(name)} onChange={(event) => toggleGrant(name, event.target.checked)} />
                </label>
              </li>;
            })}
          </ul>
          <p>
            <label htmlFor="client-scope">Scope</label>
            <input
              id="client-scope"
              name="scope"
              type="text"
              value={draft.scope}
              onChange={(event) => onChange({ ...draft, scope: event.target.value })}
            />
          </p>
          <p className="muted">The scope names this client may ask for, separated by spaces.</p>
        </fieldset></TabsContent>

        <TabsContent value="credentials"><fieldset disabled={busy}>
          <legend id="client-keys-subjects">Keys and subjects</legend>
          {editing.kind === 'existing' && editing.document.jwks !== undefined && (
            <JsonView value={editing.document.jwks} label="Registered inline JWK Set JSON" />
          )}
          <p>
            <label htmlFor="jwks-uri">JWK Set URL</label>
            <input
              id="jwks-uri"
              name="jwks_uri"
              type="url"
              value={draft.jwks_uri}
              onChange={(event) => onChange({ ...draft, jwks_uri: event.target.value })}
            />
          </p>
          <Field label="Inline JWK Set" error={jsonDocument(draft.jwks, 'The JWK Set')}>
            {(props) => (
              <textarea
                {...props}
                name="jwks"
                rows={6}
                value={draft.jwks}
                onChange={(event) => onChange({ ...draft, jwks: event.target.value })}
              />
            )}
          </Field>
          <p className="muted">
            One or the other, never both. A URL is re-fetched when the client rotates its keys;
            an inline set is changed here.
          </p>
          <p>
            <label htmlFor="id-token-alg">ID token signing algorithm</label>
            <FormSelect
              id="id-token-alg"
              name="id_token_signed_response_alg"
              value={draft.id_token_signed_response_alg}
              onValueChange={(value) => onChange({ ...draft, id_token_signed_response_alg: value })} disabled={busy} options={ALGORITHMS.map((alg) => ({ value: alg, label: alg }))} />
          </p>
          <p className="muted">
            This tenant must hold an active key for it, or the client could never be issued an ID
            token — the server refuses the registration in that case.
          </p>
          <p>
            <label htmlFor="userinfo-response-alg">UserInfo response signing algorithm</label>
            <FormSelect
              id="userinfo-response-alg"
              name="userinfo_signed_response_alg"
              value={draft.userinfo_signed_response_alg}
              onValueChange={(value) =>
                onChange({ ...draft, userinfo_signed_response_alg: value })
              }
              disabled={busy}
              options={algorithmOptions(draft.userinfo_signed_response_alg)}
            />
          </p>
          <p className="muted">
            When configured, <code>/userinfo</code> returns a signed JWT instead of a plain JSON
            object. The client must verify its signature and audience.
          </p>
          <p>
            <label htmlFor="request-object-alg">Request object signing algorithm</label>
            <FormSelect
              id="request-object-alg"
              name="request_object_signing_alg"
              value={draft.request_object_signing_alg}
              onValueChange={(value) =>
                onChange({ ...draft, request_object_signing_alg: value })
              }
              disabled={busy}
              options={algorithmOptions(draft.request_object_signing_alg)}
            />
          </p>
          <p className="muted">
            Configuring this opts the client into signed authorization request objects. Every
            request object must use this algorithm and a registered client key.
          </p>
          <p>
            <label>
              <input
                type="checkbox"
                name="tls_client_certificate_bound_access_tokens"
                checked={draft.tls_client_certificate_bound_access_tokens === true}
                onChange={(event) =>
                  onChange({
                    ...draft,
                    tls_client_certificate_bound_access_tokens: event.target.checked,
                  })
                }
              />{' '}
              Bind access tokens to this client&rsquo;s TLS certificate
            </label>
          </p>
          <p className="muted">
            Access and refresh tokens can then be used only with the certificate presented at the
            token endpoint. Leave this off for DPoP-bound tokens; enabling it requires the
            deployment&rsquo;s mutual-TLS endpoints and a registered client certificate identity.
          </p>
          <p>
            <label htmlFor="subject-type">Subject type</label>
            <FormSelect
              id="subject-type"
              name="subject_type"
              value={draft.subject_type}
              onValueChange={(value) => onChange({ ...draft, subject_type: value })}
             disabled={busy} options={[{"value": "public", "label": "Public"}, {"value": "pairwise", "label": "Pairwise"}]} />
          </p>
          <p>
            <label htmlFor="sector-identifier-uri">Sector identifier URL</label>
            <input
              id="sector-identifier-uri"
              name="sector_identifier_uri"
              type="url"
              value={draft.sector_identifier_uri}
              onChange={(event) =>
                onChange({ ...draft, sector_identifier_uri: event.target.value })
              }
            />
          </p>
          <p className="muted">
            Fetched and checked when the client is saved: every redirect URI above has to appear
            in the document it serves.
          </p>
        </fieldset></TabsContent>

        <TabsContent value="tokens"><fieldset disabled={busy}>
          <legend id="client-token-roles">Application roles in tokens</legend>
          <p>
            <label>
              <input
                type="checkbox"
                name="roles_in_id_token"
                checked={draft.roles_in_id_token}
                onChange={(event) =>
                  onChange({ ...draft, roles_in_id_token: event.target.checked })
                }
              />{' '}
              Also put <code>roles</code> and <code>resource_access</code> in this
              client&rsquo;s ID tokens
            </label>
          </p>
          <p className="muted">
            Off by default (<code>ast-mqt</code>). The claims are always in the access token and
            at <code>/userinfo</code>; an ID token travels through the browser and is kept by the
            client, so the authority it carries is the client&rsquo;s decision for its own users.
            A client can also ask for them one sign-in at a time, with the <code>claims</code>{' '}
            parameter. Either way a token names only this client in{' '}
            <code>resource_access</code>.
          </p>
        </fieldset></TabsContent>

        <Actions>
          <Button type="button" disabled={busy} onClick={onClose}>
            Close
          </Button>
          <Button type="submit" variant="primary" disabled={busy}>
            {editing.kind === 'existing' ? 'Save client' : 'Register client'}
          </Button>
        </Actions>
      </form>
    </Panel>
  );
}

/**
 * The dynamic registration gate, reported rather than edited.
 *
 * The sentence about issuance is on the screen rather than only in a bead,
 * because an operator looking for the button has to be told why there is none.
 */
function Gate({ gate }: Readonly<{ gate: RegistrationGate }>): JSX.Element {
  return (
    <Panel id="registration-gate" title="Dynamic client registration">
      <dl className="stats">
        <div className="stat">
          <dt>Mode</dt>
          <dd>
            <code>{gate.mode}</code>
          </dd>
        </div>
        <div className="stat">
          <dt>Initial access tokens configured</dt>
          <dd>{gate.configured_tokens}</dd>
        </div>
        <div className="stat">
          <dt>Stored as</dt>
          <dd>{gate.tokens_stored_hashed ? 'SHA-256 digests' : 'plain text'}</dd>
        </div>
      </dl>
      {!gate.console_issuance && (
        <p className="muted">
          Initial access tokens are provisioned in this deployment&rsquo;s configuration file and
          hashed when it is read, so there is no row to give an expiry, a quota or a revocation —
          and nothing for this console to mint. Issuing them from here needs the per-tenant
          registration policy (<code>ast-m9c.6</code>).
        </p>
      )}
    </Panel>
  );
}
