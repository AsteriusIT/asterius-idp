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
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { ApiError, mutate, read, type Session } from './api';
import { RoleCatalogue, clientCatalogue, mayRead as mayReadAppRoles } from './appRoles';
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
 */
const KNOWN_GRANTS: readonly (readonly [string, string])[] = [
  ['authorization_code', 'The code flow. Almost every client wants this one.'],
  ['refresh_token', 'Refresh tokens, rotated on every use.'],
  ['client_credentials', 'Machine-to-machine, with no end user.'],
  ['urn:ietf:params:oauth:grant-type:device_code', 'Device authorization grant (RFC 8628).'],
  ['urn:openid:params:grant-type:ciba', 'CIBA backchannel authentication.'],
  ['urn:ietf:params:oauth:grant-type:token-exchange', 'Token exchange (RFC 8693).'],
];

/** The signing algorithms this profile permits (ADR-0003, FAPI 2.0 SP §5.4.1). */
const ALGORITHMS: readonly string[] = ['EdDSA', 'ES256', 'PS256'];

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

/** One client's registration, as `GET /clients/{client_id}` renders it. */
export interface ClientDocument {
  readonly client_id: string;
  readonly status: string;
  readonly client_name: string;
  readonly application_type: string;
  readonly token_endpoint_auth_method: string;
  readonly redirect_uris: readonly string[];
  readonly post_logout_redirect_uris: readonly string[];
  readonly grant_types: readonly string[];
  readonly scope: string;
  readonly id_token_signed_response_alg: string;
  readonly subject_type: string;
  readonly resources: readonly string[];
  readonly authorization_details_types: readonly string[];
  /** `ast-mqt`: whether this client's ID tokens carry the role claims. */
  readonly roles_in_id_token: boolean;
  readonly jwks?: unknown;
  readonly jwks_uri?: string;
  readonly sector_identifier_uri?: string;
}

/** The registration gate, as `GET /registration` reports it. */
export interface RegistrationGate {
  readonly mode: string;
  readonly configured_tokens: number;
  readonly tokens_stored_hashed: boolean;
  readonly console_issuance: boolean;
}

/** What the form holds while it is being edited. */
export interface Draft {
  readonly client_name: string;
  readonly application_type: string;
  readonly redirect_uris: string;
  readonly post_logout_redirect_uris: string;
  readonly grant_types: readonly string[];
  readonly scope: string;
  readonly id_token_signed_response_alg: string;
  readonly subject_type: string;
  readonly sector_identifier_uri: string;
  readonly jwks_uri: string;
  readonly jwks: string;
  readonly status: string;
  readonly roles_in_id_token: boolean;
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

/** One URI per line, which is how the textareas hold a list. */
export function linesOf(value: readonly string[]): string {
  return value.join('\n');
}

/**
 * A textarea back into a list.
 *
 * Blank lines are dropped, because an operator ends a list with a newline and
 * an empty `redirect_uris` entry is refused by the validator with a message
 * about entry three that they did not type.
 */
export function listFrom(value: string): string[] {
  return value
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '');
}

/** The draft a freshly read document starts as. */
export function draftOf(document: ClientDocument): Draft {
  return {
    client_name: document.client_name,
    application_type: document.application_type,
    redirect_uris: linesOf(document.redirect_uris),
    post_logout_redirect_uris: linesOf(document.post_logout_redirect_uris ?? []),
    grant_types: [...document.grant_types],
    scope: document.scope,
    id_token_signed_response_alg: document.id_token_signed_response_alg,
    subject_type: document.subject_type,
    sector_identifier_uri: document.sector_identifier_uri ?? '',
    jwks_uri: document.jwks_uri ?? '',
    // Pretty-printed, because an operator who has to paste a JWK Set in has to
    // be able to read the one that is there.
    jwks: document.jwks === undefined ? '' : JSON.stringify(document.jwks, null, 2),
    status: document.status,
    // Absent in a document from an older release reads as off, which is the
    // default the server applies to the same client.
    roles_in_id_token: document.roles_in_id_token === true,
  };
}

/** The draft a new client starts as: this profile's defaults, spelled out. */
export function emptyDraft(): Draft {
  return {
    client_name: '',
    application_type: 'web',
    redirect_uris: '',
    post_logout_redirect_uris: '',
    grant_types: ['authorization_code'],
    scope: 'openid',
    id_token_signed_response_alg: 'EdDSA',
    subject_type: 'public',
    sector_identifier_uri: '',
    jwks_uri: '',
    jwks: '',
    status: 'active',
    roles_in_id_token: false,
  };
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
  const known = KNOWN_GRANTS.map(([name]) => name);
  const unknown = granted.filter((name) => !known.includes(name));
  return [
    ...KNOWN_GRANTS,
    ...unknown.map((name) => [name, 'A grant type this console does not know about.'] as const),
  ];
}

/**
 * The registration document a draft posts.
 *
 * `jwks` is parsed here rather than sent as a string, because RFC 7591 §2 makes
 * it a JSON object: sending the text would be refused by the validator with a
 * type error naming a line number, and "that is not JSON" is something this
 * form can say about the box the operator is looking at. Everything else is
 * passed through as typed — no normalising, no lower-casing, no trimming of a
 * redirect URI, because ADR-0005 compares them byte for byte and a console that
 * quietly repaired one would register a callback nobody typed.
 *
 * @throws SyntaxError if the JWK Set box does not hold JSON.
 */
export function documentFrom(draft: Draft): Record<string, unknown> {
  const document: Record<string, unknown> = {
    client_name: draft.client_name,
    application_type: draft.application_type,
    redirect_uris: listFrom(draft.redirect_uris),
    post_logout_redirect_uris: listFrom(draft.post_logout_redirect_uris),
    grant_types: [...draft.grant_types],
    scope: draft.scope,
    id_token_signed_response_alg: draft.id_token_signed_response_alg,
    subject_type: draft.subject_type,
    status: draft.status,
    roles_in_id_token: draft.roles_in_id_token,
  };
  if (draft.sector_identifier_uri.trim() !== '') {
    document.sector_identifier_uri = draft.sector_identifier_uri.trim();
  }
  // RFC 7591 §2: never both. The form offers both boxes because a client has
  // one or the other and an operator switching between them needs to see both;
  // only the filled one is sent, and a document carrying both is refused by the
  // server anyway.
  if (draft.jwks.trim() !== '') {
    document.jwks = JSON.parse(draft.jwks) as unknown;
  } else if (draft.jwks_uri.trim() !== '') {
    document.jwks_uri = draft.jwks_uri.trim();
  }
  return document;
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

export function Clients({ session }: { session: Session }): JSX.Element {
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [query, setQuery] = useState('');
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
    setEditing({ kind: 'none' });
    setDraft(null);
  }, []);

  const save = useCallback(
    (current: Draft, where: Editing) => {
      let document: Record<string, unknown>;
      try {
        document = documentFrom(current);
      } catch {
        setRefusal('The JWK Set box does not hold JSON. Paste the whole document, braces and all.');
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
          setNotice(
            where.kind === 'existing' ? 'Saved.' : `Registered as ${stored.client_id}.`,
          );
          setBusy(false);
          refresh(query);
        },
        (error: unknown) => {
          setRefusal(error instanceof Error ? error.message : 'the change was refused');
          setBusy(false);
        },
      );
    },
    [query, refresh, session],
  );

  return (
    <Screen
      title="Clients"
      description={
        <>
          Every client registered against <strong>{session.tenant}</strong>. A client created here
          goes through the same validator as one that registers itself, so anything this
          deployment would refuse at <code>/register</code> is refused here too.
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

      <Panel title="Registered clients">
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

      {draft !== null && editing.kind !== 'none' && (
        <Editor
          draft={draft}
          editing={editing}
          busy={busy}
          onChange={setDraft}
          onSubmit={() => save(draft, editing)}
          onClose={close}
        />
      )}

      {/*
        This client's own role catalogue (`ast-095`), under the editor and only
        for an existing client: a role belongs to a client that exists, and the
        catalogue of one being registered would have nowhere to be written.
      */}
      {editing.kind === 'existing' && mayReadAppRoles(session) && (
        <RoleCatalogue
          session={session}
          path={clientCatalogue(editing.document.client_id)}
          title={`Application roles of ${editing.document.client_id}`}
          explanation="Issued to this client alone, under resource_access.{client_id}.roles. A token issued to another client never names them. Deleting one is refused while any account still holds it."
        />
      )}

      {gate !== null && <Gate gate={gate} />}

      <Panel id="clients-not-here" title="Not editable yet">
        <p className="muted">
          The per-tenant registration policy (<code>ast-m9c.6</code>), the agent profile (
          <code>ast-lh3.1</code>) and the per-client resource allow-list are not served by this
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
}: {
  load: Load;
  onOpen: (clientId: string) => void;
  onRetry: () => void;
  busy: boolean;
}): JSX.Element {
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
}: {
  draft: Draft;
  editing: Editing;
  busy: boolean;
  onChange: (draft: Draft) => void;
  onSubmit: () => void;
  onClose: () => void;
}): JSX.Element {
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
    <Panel id="client-editor" title={heading}>
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
        <fieldset disabled={busy}>
          <legend>Identity</legend>
          <p>
            <label htmlFor="client-name">Client name</label>
            <input
              id="client-name"
              name="client_name"
              type="text"
              value={draft.client_name}
              onChange={(event) => onChange({ ...draft, client_name: event.target.value })}
            />
          </p>
          <p>
            <label htmlFor="application-type">Application type</label>
            <select
              id="application-type"
              name="application_type"
              value={draft.application_type}
              onChange={(event) => onChange({ ...draft, application_type: event.target.value })}
            >
              <option value="web">web</option>
              <option value="native">native</option>
            </select>
          </p>
          <p>
            <label htmlFor="client-status">Status</label>
            <select
              id="client-status"
              name="status"
              value={draft.status}
              onChange={(event) => onChange({ ...draft, status: event.target.value })}
            >
              <option value="active">active</option>
              <option value="disabled">disabled</option>
            </select>
          </p>
          <p className="muted">
            A disabled client fails client authentication. Its grants and its audit trail stay.
          </p>
        </fieldset>

        <fieldset disabled={busy}>
          <legend>Callbacks</legend>
          <p>
            <label htmlFor="redirect-uris">Redirect URIs (one per line)</label>
            <textarea
              id="redirect-uris"
              name="redirect_uris"
              rows={4}
              value={draft.redirect_uris}
              onChange={(event) => onChange({ ...draft, redirect_uris: event.target.value })}
            />
          </p>
          <p className="muted">
            Compared byte for byte at the authorization endpoint (ADR-0005), so a trailing slash
            is a different URI.
          </p>
          <p>
            <label htmlFor="post-logout-redirect-uris">
              Post-logout redirect URIs (one per line)
            </label>
            <textarea
              id="post-logout-redirect-uris"
              name="post_logout_redirect_uris"
              rows={3}
              value={draft.post_logout_redirect_uris}
              onChange={(event) =>
                onChange({ ...draft, post_logout_redirect_uris: event.target.value })
              }
            />
          </p>
        </fieldset>

        <fieldset disabled={busy}>
          <legend>Grant types</legend>
          <ul className="switches">
            {grantRows(draft.grant_types).map(([name, description]) => (
              <li key={name}>
                <label>
                  <input
                    type="checkbox"
                    name={name}
                    checked={draft.grant_types.includes(name)}
                    onChange={(event) => toggleGrant(name, event.target.checked)}
                  />{' '}
                  <code>{name}</code>
                </label>
                <p className="muted">{description}</p>
              </li>
            ))}
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
          <p className="muted">Space-delimited, as RFC 6749 §3.3 defines it.</p>
        </fieldset>

        <fieldset disabled={busy}>
          <legend>Keys and subjects</legend>
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
          <p>
            <label htmlFor="jwks">Inline JWK Set</label>
            <textarea
              id="jwks"
              name="jwks"
              rows={6}
              value={draft.jwks}
              onChange={(event) => onChange({ ...draft, jwks: event.target.value })}
            />
          </p>
          <p className="muted">
            One or the other, never both (RFC 7591 §2). A URL is re-fetched when the client
            rotates its keys; an inline set is changed here.
          </p>
          <p>
            <label htmlFor="id-token-alg">ID token signing algorithm</label>
            <select
              id="id-token-alg"
              name="id_token_signed_response_alg"
              value={draft.id_token_signed_response_alg}
              onChange={(event) =>
                onChange({ ...draft, id_token_signed_response_alg: event.target.value })
              }
            >
              {ALGORITHMS.map((alg) => (
                <option key={alg} value={alg}>
                  {alg}
                </option>
              ))}
            </select>
          </p>
          <p className="muted">
            This tenant must hold an active key for it, or the client could never be issued an ID
            token — the server refuses the registration in that case.
          </p>
          <p>
            <label htmlFor="subject-type">Subject type</label>
            <select
              id="subject-type"
              name="subject_type"
              value={draft.subject_type}
              onChange={(event) => onChange({ ...draft, subject_type: event.target.value })}
            >
              <option value="public">public</option>
              <option value="pairwise">pairwise</option>
            </select>
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
            Fetched and checked when the client is saved (OIDC Registration §5): every redirect
            URI above has to appear in the document it serves.
          </p>
        </fieldset>

        <fieldset disabled={busy}>
          <legend>Application roles in tokens</legend>
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
            A client can also ask per authorization with the <code>claims</code> parameter (OIDC
            Core §5.5). Either way a token names only this client in{' '}
            <code>resource_access</code>.
          </p>
        </fieldset>

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
function Gate({ gate }: { gate: RegistrationGate }): JSX.Element {
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
