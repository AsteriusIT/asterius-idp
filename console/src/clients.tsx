import { WorkflowSteps } from './components/workflow-steps';
import { Field as FormField, FieldLabel, FieldGroup, FieldSet, FieldLegend } from '@/components/ui/field';
import { SettingSwitch } from './form-controls';
import { Textarea } from '@/components/ui/textarea';
import { Input } from '@/components/ui/input';
import { DirectorySearch, DirectoryStatusFilter, DirectoryFilterSummary } from './directory-controls';
import { AuthorizationTypePicker } from './authorization-type-picker';
import { useViewState, useListScroll } from './view-memory';
import { CopyValue } from './components/copy-value';
import { useRouteParameters, setRouteParameters, replaceSavedRoute } from './route-state';
import { useUnsavedChanges } from './navigation-guard';
import { hrefOf } from './routes';
import { FlowOrigin } from './flow-origin';
/**
 * The clients screen (`ast-f7m.5`).
 *
 * What a tenant's administrators can do to the clients registered against
 * them: find one, read its registration, register a new one, edit an existing
 * one, take one out of service, and replace its administrator-owned resource
 * allow-list.
 *
 * # The API validates metadata; private keys are stopped before upload
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
 * A pre-submit public-key check also prevents uploading private or symmetric
 * key material: a disclosure must be stopped before asking the API to refuse it.
 *
 * That is why the form otherwise submits with `noValidate` and why the grant-type list is
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
 * * **`resources` in registration metadata.** They are never posted in the
 *   registration document. The dedicated policy operation below replaces
 *   them only from resource servers already registered in this tenant.
 *
 * # No third-party anything
 *
 * The console runs under a strict nonce CSP with `connect-src 'self'`
 * (ADR-0009). Every control is an ordinary form element, every handler is
 * attached by React, and nothing is fetched from anywhere but this origin.
 */
import { ClientConditionalAccess } from './client-conditional-access';
import { OneTimeSecret } from './components/one-time-secret';
import { Tabs, TabsList, TabsTrigger, TabsContent } from './components/ui/tabs';
import { FormSelect } from './components/ui/select';
import { ArrowRightLeftIcon, KeyRoundIcon, MonitorSmartphoneIcon, PencilIcon, RefreshCwIcon, ServerIcon, SmartphoneIcon } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { JSX } from 'react';
import { ApiError, mutate, read, type Session } from './api';
import { mayRead as mayReadAppRoles } from './appRoles';
import { toast } from './components/ui/toast';
import { JsonView } from './components/json-view';
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
} from './ui';
import { redirectUris } from './validation';
import { ClientSecurity } from './client-setup';
import { KubernetesProfileSetup } from './kubernetes-profile';
import { clientConfiguration, clientFieldError, publicKeyError, readClientDiscovery, type ClientDiscovery } from './client-onboarding';
import { resourceChoices, type ResourceServerSummary } from './client-resources';
import {
  documentFrom,
  draftOf,
  emptyDraft,
  profilePresentation,
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
const RESPONSE_MODES = ['query', 'form_post', 'query.jwt', 'jwt', 'form_post.jwt'] as const;

function responseModeRows(modes: readonly string[] | null): readonly string[] {
  return [...RESPONSE_MODES, ...(modes ?? []).filter((mode) => !RESPONSE_MODES.includes(mode as typeof RESPONSE_MODES[number]))];
}

function encryptionEnabled(alg: string, enc: string): boolean {
  return alg !== '' || enc !== '';
}

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
  readonly compliance_profile: 'fapi' | 'oidc' | 'public';
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

type ResourceLoad =
  | { readonly kind: 'idle' }
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly rows: readonly ResourceServerSummary[] }
  | { readonly kind: 'failed'; readonly message: string };

type HealthReport = {
  readonly request_id: string;
  readonly audit_event: string;
  readonly checks: readonly { readonly name: string; readonly status: 'pass' | 'fail'; readonly message: string }[];
};

/** Which client the editor is on, if any. */
type Editing =
  | { readonly kind: 'none' }
  | { readonly kind: 'new' }
  | { readonly kind: 'existing'; readonly document: ClientDocument };

export function Clients({ session }: Readonly<{ session: Session }>): JSX.Element {
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [query, setQuery] = useViewState('clients:query', '');
  const [appliedQuery, setAppliedQuery] = useViewState('clients:applied', '');
  const [status, setStatus] = useViewState('clients:status', '');
  const [cursor, setCursor] = useViewState<string | null>('clients:cursor', null);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const parameters = useRouteParameters();
  const wantedId = parameters.get('id');
  const wantedMode = parameters.get('mode');
  const { tab, guided } = clientEditorRoute(parameters);
  const setTab = useCallback((value: string) => setRouteParameters('clients', { tab: value }), []);
  useListScroll(`clients:${appliedQuery}:${status}:${cursor}`, wantedId === null && wantedMode !== 'new' && load.kind === 'ready');
  const [editing, setEditing] = useState<Editing>({ kind: 'none' });
  const [draft, setDraft] = useState<Draft | null>(null);
  const [gate, setGate] = useState<RegistrationGate | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const openedClient = useRef<string | null>(null);
  const requestNumber = useRef(0);
  const listRequest = useRef(0);
  useEffect(() => () => { listRequest.current++; }, []);
  useEffect(() => () => { requestNumber.current++; }, []);
  const [secretCopied, setSecretCopied] = useState(false);
  const [issuedSecret, setIssuedSecret] = useState<string | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [discovery, setDiscovery] = useState<ClientDiscovery | null>(null);
  const [discoveryError, setDiscoveryError] = useState<string | null>(null);
  const [resourceLoad, setResourceLoad] = useState<ResourceLoad>({ kind: 'idle' });
  const [selectedResources, setSelectedResources] = useState<readonly string[]>([]);
  const [health, setHealth] = useState<HealthReport | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [healthBusy, setHealthBusy] = useState(false);
  const leave = useUnsavedChanges(hasUnsavedClient(draft, editing, selectedResources, issuedSecret, secretCopied));
  const canWrite = session.scopes.includes('admin.clients:write');
  const canReadResources = session.scopes.includes('admin.resource_servers:read');
  useEffect(() => {
    let active = true;
    readClientDiscovery().then(
      (value) => { if (active) setDiscovery(value); },
      (error: unknown) => { if (active) setDiscoveryError(error instanceof Error ? error.message : 'Discovery could not be read.'); },
    );
    return () => { active = false; };
  }, []);

  const refresh = useCallback(
    (term: string) => {
      const request = ++listRequest.current;
      setLoad({ kind: 'loading' });
      const params = new URLSearchParams();
      if (status) params.set('status', status);
      if (term.trim()) params.set('q', term.trim());
      if (cursor) params.set('cursor', cursor);
      read(`clients?${params}`).then(
        (document) => { if (request !== listRequest.current) return; setLoad({ kind: 'ready', rows: (document as Page).items }); setNextCursor((document as Page).next_cursor); },
        (error: unknown) => {
          if (request !== listRequest.current) return;
          setLoad({
            kind: 'failed',
            message: error instanceof Error ? error.message : 'the clients could not be read',
          });
        },
      );
    },
    [cursor, status],
  );

  useEffect(() => refresh(appliedQuery), [refresh, appliedQuery]);

  const loadResourceServers = useCallback(() => {
    if (!canReadResources) {
      setResourceLoad({
        kind: 'failed',
        message: 'Reading registered resource servers requires admin.resource_servers:read.',
      });
      return;
    }
    setResourceLoad({ kind: 'loading' });
    read('resource-servers').then(
      (body) => setResourceLoad({
        kind: 'ready',
        rows: (body as { items: readonly ResourceServerSummary[] }).items,
      }),
      (error: unknown) => setResourceLoad({
        kind: 'failed',
        message: error instanceof Error ? error.message : 'The resource servers could not be read.',
      }),
    );
  }, [canReadResources]);

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
    requestNumber.current++; openedClient.current = null;
    setNotice(null);
    setRefusal(null);
    setIssuedSecret(null);
    setBusy(false);
    setEditing({ kind: 'new' });
    setDraft(emptyDraft());
  }, []);

  const openExisting = useCallback((clientId: string) => {
    const number = ++requestNumber.current;
    openedClient.current = clientId;
    setNotice(null);
    setRefusal(null);
    setIssuedSecret(null);
    setBusy(true);
    read(clientPath(clientId)).then(
      (body) => {
        if (number !== requestNumber.current) return;
        const document = body as ClientDocument;
        setEditing({ kind: 'existing', document });
        setDraft(draftOf(document));
        setSelectedResources(document.resources);
        loadResourceServers();
        setBusy(false);
      },
      (error: unknown) => {
        if (number !== requestNumber.current) return;
        setRefusal(error instanceof Error ? error.message : 'the client could not be read');
        setBusy(false);
      },
    );
  }, [loadResourceServers]);

  const close = useCallback(() => {
    requestNumber.current++; openedClient.current = null;
    setBusy(false);
    setEditing({ kind: 'none' });
    setDraft(null);
    setResourceLoad({ kind: 'idle' });
    setSelectedResources([]);
    setIssuedSecret(null);
    setHealth(null);
    setHealthError(null);
  }, []);

  useEffect(() => {
    if (wantedId) { if (openedClient.current !== wantedId) openExisting(wantedId); }
    else if (wantedMode === 'new') openNew();
    else close();
  }, [wantedId, wantedMode, openExisting, openNew, close]);

  const checkHealth = useCallback((clientId: string) => {
    const requestId = crypto.randomUUID();
    setHealthBusy(true);
    setHealthError(null);
    setHealth(null);
    read(`${clientPath(clientId)}/health`, { 'X-Request-ID': requestId }).then(
      (body) => setHealth(body as HealthReport),
      (error: unknown) => setHealthError(error instanceof Error ? error.message : 'The integration check could not be completed.'),
    ).finally(() => setHealthBusy(false));
  }, []);

  const saveResources = useCallback(
    (clientId: string) => {
      if (!canWrite) return;
      setBusy(true);
      setNotice(null);
      setRefusal(null);
      mutate(`${clientPath(clientId)}/resources`, 'PUT', session, {
        resources: [...selectedResources],
      }).then(
        (body) => {
          const stored = body as ClientDocument;
          setEditing({ kind: 'existing', document: stored });
          setSelectedResources(stored.resources);
          setNotice('Authorized resources saved.');
          toast.success('Resource access saved', stored.client_id);
          setBusy(false);
        },
        (error: unknown) => {
          const said = error instanceof Error ? error.message : 'the resource policy was refused';
          setRefusal(said);
          toast.error('Resource access was not saved', said);
          setBusy(false);
        },
      );
    },
    [canWrite, selectedResources, session],
  );

  const save = useCallback(
    (current: Draft, where: Editing, secretCommand?: 'rotate' | 'revoke') => {
      if (!canWrite) return;
      const keyComplaint = publicKeyError(current);
      if (keyComplaint !== null) {
        // Public key setup is also a confidentiality boundary: never send a
        // pasted private key to registration, even to ask the API to refuse it.
        setRefusal(`jwks: ${keyComplaint}`);
        setNotice(null);
        toast.error('The client was not sent', keyComplaint);
        return;
      }
      let document: Record<string, unknown>;
      try {
        document = documentFrom(current);
        if (secretCommand === 'rotate') document.rotate_client_secret = true;
        if (secretCommand === 'revoke') document.revoke_client_secret = true;
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
      const number = requestNumber.current;
      const request =
        where.kind === 'existing'
          ? mutate(clientPath(where.document.client_id), 'PUT', session, document)
          : mutate(CLIENTS_PATH, 'POST', session, document);

      request.then(
        (body) => {
          if (number !== requestNumber.current) return;
          // Re-read from the answer rather than from the form: the server's
          // document is the client that exists, including the members it
          // provisioned itself.
          const response = body as ClientDocument;
          const { client_secret: issuedSecret, ...stored } = response;
          setIssuedSecret(previous => issuedSecret ?? (secretCommand === 'revoke' ? null : previous));
          if (issuedSecret !== undefined) setSecretCopied(false);
          openedClient.current = stored.client_id;
          replaceSavedRoute('clients', { id: stored.client_id, tab: issuedSecret !== undefined ? 'credentials' : tab });
          // Keep the one-time plaintext only in the dedicated panel state. The
          // editable registration and saved-configuration state never need it.
          setEditing({ kind: 'existing', document: stored });
          setDraft(draftOf(stored));
          setSelectedResources(stored.resources);
          if (where.kind === 'new') loadResourceServers();
          const said = issuedSecret !== undefined
            ? 'Saved. Copy the new client secret now; it will not be shown again.'
            : secretCommand === 'revoke'
              ? 'Saved. The client secret was revoked.'
              : where.kind === 'existing' ? 'Saved.' : `Registered as ${stored.client_id}.`;
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
    [canWrite, loadResourceServers, query, refresh, session, tab],
  );

  if (draft !== null && editing.kind !== 'none') {
    const title = editing.kind === 'existing'
      ? editing.document.client_name
      : 'Register an application';
    const profile = profilePresentation(draft.compliance_profile);
    const discoveryUrl = issuerDiscoveryUrl(discovery);
    return (
      <Screen
        title={title}
        identity={editing.kind === 'existing' ? editing.document.client_name : undefined}
        description={editing.kind === 'existing' ? 'Connection information and configuration for this application.' : 'Configure authentication, callbacks, and access for your application.'}
        actions={<Badge tone={profile.fapiBadge ? 'ok' : 'warn'}>{profile.label}</Badge>}
        back={{ label: 'Back to applications', onClick: () => leave(() => setRouteParameters('clients', { id: null, mode: null, tab: null })) }}
      >
        {editing.kind === 'existing' && mayReadAppRoles(session) && <a className="application-roles-link" href={hrefOf('roles', { client: editing.document.client_id })}>Manage application roles →</a>}
        {editing.kind === 'existing' && <FlowOrigin session={session} kind="application" resource={editing.document.client_id} />}
        {notice !== null && <Message tone="success">{notice}</Message>}
        {refusal !== null && <Message tone="error">{refusal}</Message>}
        {editing.kind === 'existing' && discovery !== null && discoveryUrl !== null && <ConnectionCard document={editing.document} draft={draft} discovery={discovery} discoveryUrl={discoveryUrl} session={session} busy={busy} healthBusy={healthBusy} healthError={healthError} health={health} checkHealth={checkHealth} />}
        {discoveryError !== null && <Message tone="error">{discoveryError}</Message>}
        {!canWrite && <Message tone="info">Read-only access. Registering and saving applications requires admin.clients:write.</Message>}
        {guided && <Panel className="guided-setup-summary" title="Guided application setup"
          description={`Step ${Math.max(0, ['settings', 'callbacks', 'credentials', 'grants', 'tokens', 'review'].indexOf(tab)) + 1} of 6. Review before registering; no application is created until you choose Register client.`}
          actions={<Button onClick={() => setRouteParameters('clients', { guided: null })}>Switch to full editor</Button>}>
          {null}
        </Panel>}
        <Tabs value={tab} onValueChange={setTab}>
          <ApplicationTabs existing={editing.kind === 'existing'} guided={guided} />
        {!['resources', 'policy', 'configuration', 'kubernetes'].includes(tab) && <Editor
          draft={draft}
          session={session}
          guided={guided}
          tab={tab}
          onTab={setTab}
          editing={editing}
          busy={busy}
          canWrite={canWrite}
          discovery={discovery}
          refusal={refusal}
          issuedSecret={issuedSecret}
          onSecretCopied={() => setSecretCopied(true)}
          onChange={setDraft}
          onSubmit={() => save(draft, editing)}
          onRotateSecret={() => save(draft, editing, 'rotate')}
          onRevokeSecret={() => save(draft, editing, 'revoke')}
          onClose={() => leave(() => setRouteParameters('clients', { id: null, mode: null, tab: null }))}
        />}
        {editing.kind === 'existing' && <TabsContent value="resources"><ResourceAllowList
          load={resourceLoad}
          selected={selectedResources}
          busy={busy}
          canWrite={canWrite}
          onRetry={loadResourceServers}
          onChange={setSelectedResources}
          onSave={() => saveResources(editing.document.client_id)}
        /></TabsContent>}
        {editing.kind === 'existing' && <TabsContent value="policy"><ClientConditionalAccess session={session} clientID={editing.document.client_id} /></TabsContent>}
        {editing.kind === 'existing' && <TabsContent value="configuration">
          <Panel title="Saved configuration">
            <p>This reflects the last saved registration. Save edits before copying it. Private signing keys, proof keys, and client secrets are never included.</p>
            {discovery !== null ? <JsonView value={clientConfiguration(editing.document, discovery)} label="Saved client configuration" />
              : <p>Discovery must load before a connection configuration can be exported.</p>}
          </Panel>
        </TabsContent>}
        {editing.kind === 'existing' && <TabsContent value="kubernetes"><KubernetesProfileSetup clientId={editing.document.client_id} session={session} canWrite={canWrite} /></TabsContent>}
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
        canWrite ? <Actions><Button variant="ghost" onClick={() => setRouteParameters('clients', { mode: 'new', id: null, tab: null, guided: '1' })}>Guided setup</Button><Button variant="primary" onClick={() => setRouteParameters('clients', { mode: 'new', id: null, tab: null, guided: null })}>
          Register a client
        </Button></Actions> : undefined
      }
    >
      {notice !== null && <Message tone="success">{notice}</Message>}
      {refusal !== null && <Message tone="error">{refusal}</Message>}

      <section className="directory-panel" aria-label="Registered applications">
        <div className="directory-toolbar"><DirectorySearch label="Search clients" value={query} placeholder="Name, client ID or callback" onChange={setQuery} onSubmit={() => {
          if (cursor === null && appliedQuery === query) refresh(query);
          else { setCursor(null); setAppliedQuery(query); }
        }} /><DirectoryStatusFilter value={status} options={[{ value: '', label: 'All statuses' }, { value: 'active', label: 'Active' }, { value: 'disabled', label: 'Disabled' }]} onChange={value => { setCursor(null); setStatus(value); }} /></div>
        <DirectoryFilterSummary query={appliedQuery} status={status} onClearQuery={() => { setQuery(''); setAppliedQuery(''); setCursor(null); }} onClearStatus={() => { setStatus(''); setCursor(null); }} onClearAll={() => { setQuery(''); setAppliedQuery(''); setStatus(''); setCursor(null); }} />
        <Inventory load={load} onOpen={(id) => setRouteParameters('clients', { id, mode: null, tab: null })} onRetry={() => refresh(appliedQuery)} busy={busy} onClearFilters={appliedQuery || status ? () => { setQuery(''); setAppliedQuery(''); setStatus(''); setCursor(null); } : undefined} />
        {(cursor !== null || nextCursor) && <Actions><Button variant="ghost" disabled={cursor === null || load.kind === 'loading'} onClick={() => setCursor(null)}>First page</Button><Button variant="ghost" disabled={!nextCursor || load.kind === 'loading'} onClick={() => setCursor(nextCursor)}>Next page</Button></Actions>}
      </section>

      {gate !== null && <Gate gate={gate} />}
    </Screen>
  );
}

function issuerDiscoveryUrl(discovery: ClientDiscovery | null): string | null {
  return discovery === null ? null : `${discovery.issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;
}

function clientEditorRoute(parameters: URLSearchParams): { tab: string; guided: boolean } {
  const wantedTab = parameters.get('tab') ?? 'settings';
  return {
    guided: parameters.get('mode') === 'new' && parameters.get('guided') === '1',
    tab: ['settings', 'callbacks', 'credentials', 'grants', 'resources', 'tokens', 'policy', 'configuration', 'kubernetes', 'review'].includes(wantedTab) ? wantedTab : 'settings',
  };
}

function ApplicationTabs({ existing, guided }: Readonly<{ existing: boolean; guided: boolean }>): JSX.Element {
  if (guided) return <WorkflowSteps label="Application sections" steps={[
    { value: 'settings', title: 'General', description: 'Name and profile' },
    { value: 'callbacks', title: 'Callbacks', description: 'Redirect destinations' },
    { value: 'credentials', title: 'Credentials', description: 'Client authentication' },
    { value: 'grants', title: 'Access & grants', description: 'Allowed access' },
    { value: 'tokens', title: 'Token claims', description: 'Identity output' },
    { value: 'review', title: 'Review', description: 'Check and register' },
  ]} />;
  return <TabsList className={guided ? "application-tabs guided-application-steps" : "application-tabs"} aria-label="Application sections">
            <TabsTrigger value="settings">{guided && <span className="setup-step-number" aria-hidden="true">1</span>}General</TabsTrigger>
            <TabsTrigger value="callbacks">{guided && <span className="setup-step-number" aria-hidden="true">2</span>}Callbacks</TabsTrigger>
            <TabsTrigger value="credentials">{guided && <span className="setup-step-number" aria-hidden="true">3</span>}Credentials</TabsTrigger>
            <TabsTrigger value="grants">{guided && <span className="setup-step-number" aria-hidden="true">4</span>}Access &amp; grants</TabsTrigger>
            {existing && <TabsTrigger value="resources">Resources</TabsTrigger>}
            {existing && <TabsTrigger value="kubernetes">Kubernetes</TabsTrigger>}
            <TabsTrigger value="tokens">{guided && <span className="setup-step-number" aria-hidden="true">5</span>}Token claims</TabsTrigger>
            {existing && <TabsTrigger value="policy">Access policy</TabsTrigger>}
            {existing && <TabsTrigger value="configuration">Export</TabsTrigger>}
            {guided && <TabsTrigger value="review">{guided && <span className="setup-step-number" aria-hidden="true">6</span>}Review</TabsTrigger>}

          </TabsList>;
}

function hasUnsavedClient(draft: Draft | null, editing: Editing, resources: readonly string[], secret: string | null, copied: boolean): boolean {
  if (draft === null) return false;
  const original = editing.kind === 'existing' ? draftOf(editing.document) : emptyDraft();
  return JSON.stringify(draft) !== JSON.stringify(original)
    || (editing.kind === 'existing' && JSON.stringify(resources) !== JSON.stringify(editing.document.resources))
    || (secret !== null && !copied);
}

function ConnectionCard({ document, draft, discovery, discoveryUrl, session, busy, healthBusy, healthError, health, checkHealth }: Readonly<{
  document: ClientDocument; draft: Draft; discovery: ClientDiscovery; discoveryUrl: string;
  session: Session; busy: boolean; healthBusy: boolean; healthError: string | null;
  health: HealthReport | null; checkHealth: (id: string) => void;
}>): JSX.Element {
  const profile = profilePresentation(draft.compliance_profile);
  return <Panel
          className="application-connection-card"
          title="Connect to this application"
          description="Use these values in the application’s authentication library or deployment configuration."
          actions={<Badge tone={document.status === 'active' ? 'ok' : 'bad'}>{document.status}</Badge>}
        >
          <dl className="application-connection-grid">
            <div><dt>Client ID</dt><dd><code>{document.client_id}</code><CopyValue value={document.client_id} label="Copy client ID" iconOnly /></dd></div>
            <div><dt>Authentication</dt><dd><code>{draft.token_endpoint_auth_method}</code><CopyValue value={draft.token_endpoint_auth_method} label="Copy authentication method" iconOnly /></dd></div>
            <div className="application-connection-wide"><dt>Issuer</dt><dd><code>{discovery.issuer}</code><CopyValue value={discovery.issuer} label="Copy issuer" iconOnly /></dd></div>
            <div className="application-connection-wide"><dt>Discovery document</dt><dd><code>{discoveryUrl}</code><CopyValue value={discoveryUrl} label="Copy discovery URL" iconOnly /></dd></div>
          </dl>
          {draft.token_endpoint_auth_method === 'private_key_jwt' && <p className="muted">Use the issuer as the assertion audience, the client ID as <code>iss</code> and <code>sub</code>, and a fresh <code>jti</code> for every request.</p>}
          {!profile.fapiBadge && <Message tone="info">This application is a non-FAPI compatibility exception. Review its authentication and sender constraints before production use.</Message>}
          <div className="application-health">
            <Button disabled={healthBusy || busy} onClick={() => checkHealth(document.client_id)}>{healthBusy ? 'Checking…' : 'Run integration check'}</Button>
            <p className="muted">Read-only checks. No token is issued and no private credential is requested. The registered JWKS URL is fetched through the server’s guarded outbound path.</p>
            {healthError !== null && <Message tone="error">{healthError}</Message>}
            {health !== null && <>
              <ul className="application-health-checks">
                {health.checks.map((check) => <li key={check.name}>
                  <Badge tone={check.status === 'pass' ? 'ok' : 'bad'}>{check.status}</Badge>
                  <span><strong>{check.name.replaceAll('_', ' ')}</strong><small>{check.message}</small></span>
                </li>)}
              </ul>
              <p>Request ID <code>{health.request_id}</code> <CopyValue value={health.request_id} label="Copy ID" /> · audit event <code>{health.audit_event}</code>{session.scopes.includes('admin.audit:read') ? <> in <a href={hrefOf('audit')}>Audit</a>.</> : ' (viewing the event requires admin.audit:read).'}</p>
            </>}
          </div>
        </Panel>;
}

function ResourceAllowList({
  load,
  selected,
  busy,
  canWrite,
  onRetry,
  onChange,
  onSave,
}: Readonly<{
  load: ResourceLoad;
  selected: readonly string[];
  busy: boolean;
  canWrite: boolean;
  onRetry: () => void;
  onChange: (resources: readonly string[]) => void;
  onSave: () => void;
}>): JSX.Element {
  const toggle = (identifier: string, checked: boolean): void => {
    const next = checked
      ? [...new Set([...selected, identifier])]
      : selected.filter((resource) => resource !== identifier);
    onChange(next.sort((left, right) => left.localeCompare(right)));
  };

  return <Panel title="Authorized resources">
    <p>
      Registering a resource server makes its audience known to the tenant. Selecting it here is
      the separate authorization that lets this client request tokens for that audience.
    </p>
    {load.kind === 'idle' || load.kind === 'loading'
      ? <Skeleton rows={2} label="Reading registered resource servers." />
      : load.kind === 'failed'
        ? <LoadFailure message={load.message} onRetry={onRetry} />
        : resourceChoices(load.rows, selected).length === 0
          ? <EmptyState title="No resource servers are available." body="Register an audience on the Resource servers screen before authorizing this client." />
          : <ul className="grant-options">
            {resourceChoices(load.rows, selected).map((choice) => <li key={choice.identifier}>
              <label className={selected.includes(choice.identifier) ? 'grant-option selected' : 'grant-option'}>
                <ServerIcon aria-hidden="true" />
                <span>
                  <strong>{choice.identifier}</strong>
                  <small>{choice.registered ? 'Registered in this tenant' : 'No longer registered; remove this stale assignment'}</small>
                </span>
                <input
                  type="checkbox"
                  checked={selected.includes(choice.identifier)}
                  disabled={busy || !canWrite || (!choice.registered && !selected.includes(choice.identifier))}
                  onChange={(event) => toggle(choice.identifier, event.target.checked)}
                />
              </label>
            </li>)}
          </ul>}
    <p className="muted">An empty selection authorizes no resource. Dynamic registration cannot change this list.</p>
    {canWrite && <Button type="button" variant="primary" disabled={busy || load.kind !== 'ready'} onClick={onSave}>
      {busy ? 'Saving…' : 'Save authorized resources'}
    </Button>}
  </Panel>;
}

function Inventory({
  load,
  onOpen,
  onRetry,
  busy,
  onClearFilters,
}: Readonly<{
  load: Load;
  onOpen: (clientId: string) => void;
  onRetry: () => void;
  busy: boolean;
  onClearFilters?: (() => void) | undefined;
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
      columnPreferences={{ key: 'clients', required: ['name', 'client_id', 'status'] }}
      rows={load.rows}
      rowKey={(row) => row.client_id}
      empty={
        <EmptyState
          title="No client matches."
          body="Change the search or status filter to see more applications."
          action={onClearFilters && <Button onClick={onClearFilters}>Reset application filters</Button>}
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
          key: 'profile',
          header: 'Profile',
          sortBy: (row) => row.compliance_profile,
          cell: (row) => {
            const profile = profilePresentation(row.compliance_profile);
            return <Badge tone={profile.fapiBadge ? 'ok' : 'warn'}>{profile.label}</Badge>;
          },
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
            <Button small className="size-8 p-0" disabled={busy} aria-label={`Edit ${row.client_name}`} title="Edit" onClick={() => onOpen(row.client_id)}>
              <PencilIcon aria-hidden="true" />
            </Button>
          ),
        },
      ]}
    />
  );
}

function Editor({
  draft,
  session,
  guided,
  tab,
  onTab,
  editing,
  busy,
  canWrite,
  discovery,
  refusal,
  issuedSecret,
  onSecretCopied,
  onChange,
  onSubmit,
  onRotateSecret,
  onRevokeSecret,
  onClose,
}: Readonly<{
  draft: Draft;
  session: Session;
  guided: boolean;
  tab: string;
  onTab: (tab: string) => void;
  editing: Editing;
  busy: boolean;
  canWrite: boolean;
  discovery: ClientDiscovery | null;
  refusal: string | null;
  issuedSecret: string | null;
  onSecretCopied: () => void;
  onChange: (draft: Draft) => void;
  onSubmit: () => void;
  onRotateSecret: () => void;
  onRevokeSecret: () => void;
  onClose: () => void;
}>): JSX.Element {
  const [confirmingRevoke, setConfirmingRevoke] = useState(false);
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
          if (!guided || tab === 'review') onSubmit();
        }}
      >
        <TabsContent value="settings"><FieldSet disabled={busy || !canWrite}>
          <FieldLegend id="client-identity">Identity</FieldLegend>
          <FieldGroup>
          <Field label="Client name" required>
            {(props) => (
              <Input
                {...props}
                name="client_name"
                type="text"
                value={draft.client_name}
                onChange={(event) => onChange({ ...draft, client_name: event.target.value })}
              />
            )}
          </Field>
          <FormField>
            <FieldLabel htmlFor="application-type">Application type</FieldLabel>
            <FormSelect
              id="application-type"
              name="application_type"
              value={draft.application_type}
              onValueChange={(value) => onChange({ ...draft, application_type: value })}
             disabled={busy || !canWrite} options={[{"value": "web", "label": "Web application"}, {"value": "native", "label": "Native application"}]} />
          </FormField>
          <FormField>
            <FieldLabel htmlFor="client-status">Status</FieldLabel>
            <FormSelect
              id="client-status"
              name="status"
              value={draft.status}
              onValueChange={(value) => onChange({ ...draft, status: value })}
             disabled={busy || !canWrite} options={[{"value": "active", "label": "Active"}, {"value": "disabled", "label": "Disabled"}]} />
          </FormField>
          <p className="muted">
            A disabled client fails client authentication. Its grants and its audit trail stay.
          </p>
          <SettingSwitch label="Release stable managed group IDs to this client"
            description="Off by default. New ID tokens and UserInfo responses resolve at most 100 current memberships for this client and return stable, opaque group references. Names and directory membership for other clients are never disclosed."
            name="managed_groups_claim" checked={draft.managed_groups_claim} disabled={busy || !canWrite}
            onCheckedChange={(checked) => onChange({ ...draft, managed_groups_claim: checked })} />
        </FieldGroup></FieldSet></TabsContent>

        <TabsContent value="callbacks"><FieldSet disabled={busy || !canWrite}>
          <FieldLegend id="client-callbacks">Callbacks</FieldLegend>
          <FieldGroup>
          {/*
            The complaint is an echo of `RedirectUri::parse` and never a rule of
            this form's own (`ast-f9j5` (2), `validation.ts`): the submission is
            not blocked, the server still decides, and what it says is what is
            shown at the top of this screen.
          */}
          <Field
            label="Redirect URIs (one per line)"
            hint="Compared byte for byte at the authorization endpoint (ADR-0005), so a trailing slash is a different URI."
            error={clientFieldError(refusal, 'redirect_uris') ?? redirectUris(draft.redirect_uris, draft.application_type)}
          >
            {(props) => (
              <Textarea
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
            error={clientFieldError(refusal, 'post_logout_redirect_uris') ?? redirectUris(draft.post_logout_redirect_uris, draft.application_type)}
          >
            {(props) => (
              <Textarea
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
          <Field label="Provider Commands endpoint" hint="HTTPS endpoint that accepts signed account invalidate and delete commands." error={clientFieldError(refusal, 'command_endpoint')}>
            {(props) => (
              <Input
                {...props}
                name="command_endpoint"
                type="url"
                value={draft.command_endpoint}
                onChange={(event) => onChange({ ...draft, command_endpoint: event.target.value })}
              />
            )}
          </Field>
        </FieldGroup></FieldSet></TabsContent>

        <TabsContent value="grants"><AuthorizationTypePicker session={session} selected={draft.authorization_details_types} disabled={busy || !canWrite} onChange={values => onChange({ ...draft, authorization_details_types: values })} /><FieldSet disabled={busy || !canWrite}>
          <FieldLegend id="client-grant-types">Grant types</FieldLegend>
          <FieldGroup>
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
          <FormField>
            <FieldLabel htmlFor="client-scope">Scope</FieldLabel>
            <Input
              id="client-scope"
              name="scope"
              type="text"
              value={draft.scope}
              onChange={(event) => onChange({ ...draft, scope: event.target.value })}
            />
          </FormField>
          <p className="muted">The scope names this client may ask for, separated by spaces.</p>
        </FieldGroup></FieldSet></TabsContent>

        <TabsContent value="credentials">
          {(issuedSecret !== null || (draft.token_endpoint_auth_method === 'client_secret_basic' && editing.kind === 'existing')) && <section className="credential-secret-panel" aria-label="Client secret">
            <h3>Client secret</h3>
            {issuedSecret !== null && <OneTimeSecret key={issuedSecret} value={issuedSecret} onStored={onSecretCopied} />}
            {draft.token_endpoint_auth_method === 'client_secret_basic' && editing.kind === 'existing' && canWrite && <div className="credential-secret-actions">
              <p className="muted">Rotate to issue a replacement once, or revoke to stop shared-secret authentication until a new secret is issued.</p>
              <Actions>
                <Button type="button" disabled={busy} onClick={onRotateSecret}><RefreshCwIcon aria-hidden="true" />Rotate secret</Button>
                <Button type="button" variant="danger" disabled={busy} onClick={() => setConfirmingRevoke(true)}>Revoke secret</Button>
              </Actions>
            </div>}
          </section>}
          <FieldSet disabled={busy || !canWrite}>
          <FieldLegend id="client-keys-subjects">Keys and subjects</FieldLegend>
          <FieldGroup>
          <ClientSecurity draft={draft} discovery={discovery} refusal={refusal} busy={busy || !canWrite} onChange={onChange} />
          {draft.token_endpoint_auth_method !== 'none' && editing.kind === 'existing' && editing.document.jwks !== undefined && (
            <JsonView value={editing.document.jwks} label="Registered inline JWK Set JSON" />
          )}
          {draft.token_endpoint_auth_method === 'none' && <p className="muted">Public clients do not authenticate with a JWK Set.</p>}
          {draft.token_endpoint_auth_method !== 'none' && <><FormField>
            <FieldLabel htmlFor="jwks-uri">JWK Set URL</FieldLabel>
            <Input
              id="jwks-uri"
              name="jwks_uri"
              type="url"
              value={draft.jwks_uri}
              onChange={(event) => onChange({ ...draft, jwks_uri: event.target.value })}
            />
          </FormField>
          <Field label="Inline JWK Set" error={clientFieldError(refusal, 'jwks') ?? publicKeyError(draft)}>
            {(props) => (
              <Textarea
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
          </p></>}
          <FormField>
            <FieldLabel htmlFor="id-token-alg">ID token signing algorithm</FieldLabel>
            <FormSelect
              id="id-token-alg"
              name="id_token_signed_response_alg"
              value={draft.id_token_signed_response_alg}
              onValueChange={(value) => onChange({ ...draft, id_token_signed_response_alg: value })} disabled={busy || !canWrite} options={ALGORITHMS.map((alg) => ({ value: alg, label: alg }))} />
          </FormField>
          <p className="muted">
            This tenant must hold an active key for it, or the client could never be issued an ID
            token — the server refuses the registration in that case.
          </p>
          <FormField>
            <FieldLabel htmlFor="userinfo-response-alg">UserInfo response signing algorithm</FieldLabel>
            <FormSelect
              id="userinfo-response-alg"
              name="userinfo_signed_response_alg"
              value={draft.userinfo_signed_response_alg}
              onValueChange={(value) =>
                onChange({ ...draft, userinfo_signed_response_alg: value })
              }
              disabled={busy || !canWrite}
              options={algorithmOptions(draft.userinfo_signed_response_alg)}
            />
          </FormField>
          <p className="muted">
            When configured, <code>/userinfo</code> returns a signed JWT instead of a plain JSON
            object. The client must verify its signature and audience.
          </p>
          <FormField>
            <FieldLabel htmlFor="request-object-alg">Request object signing algorithm</FieldLabel>
            <FormSelect
              id="request-object-alg"
              name="request_object_signing_alg"
              value={draft.request_object_signing_alg}
              onValueChange={(value) =>
                onChange({ ...draft, request_object_signing_alg: value })
              }
              disabled={busy || !canWrite}
              options={algorithmOptions(draft.request_object_signing_alg)}
            />
          </FormField>
          <p className="muted">
            Configuring this opts the client into signed authorization request objects. Every
            request object must use this algorithm and a registered client key.
          </p>
          <FormField>
            <FieldLabel htmlFor="authorization-response-alg">JARM authorization response signing algorithm</FieldLabel>
            <FormSelect
              id="authorization-response-alg"
              name="authorization_signed_response_alg"
              value={draft.authorization_signed_response_alg}
              onValueChange={(value) => onChange({ ...draft, authorization_signed_response_alg: value })}
              disabled={busy || !canWrite}
              options={algorithmOptions(draft.authorization_signed_response_alg)}
            />
          </FormField>
          <p className="muted">Required when this client uses <code>jwt</code>, <code>query.jwt</code>, or <code>form_post.jwt</code>.</p>
          <fieldset>
            <legend>Allowed authorization response modes</legend>
            <p className="muted">No selection means the server permits every supported mode. Select modes to restrict this client.</p>
            <div className="response-mode-options">{responseModeRows(draft.response_modes).map((mode) => <label key={mode} className={draft.response_modes?.includes(mode) ? 'response-mode selected' : 'response-mode'}>
              <input
                type="checkbox"
                name="response_modes"
                value={mode}
                checked={draft.response_modes?.includes(mode) ?? false}
                onChange={(event) => {
                  const next = event.target.checked
                    ? [...(draft.response_modes ?? []), mode]
                    : (draft.response_modes ?? []).filter((item) => item !== mode);
                  onChange({ ...draft, response_modes: next.length === 0 ? null : next });
                }}
              /><span>{mode === 'form_post' ? 'Form post' : mode === 'query' ? 'Query' : mode}{!RESPONSE_MODES.includes(mode as typeof RESPONSE_MODES[number]) && ' (unrecognized; preserved)'}</span>
            </label>)}</div>
          </fieldset>
          <p>
            <label>
              <input
                type="checkbox"
                name="id_token_encrypted_response_alg"
                checked={encryptionEnabled(draft.id_token_encrypted_response_alg, draft.id_token_encrypted_response_enc)}
                onChange={(event) => onChange({ ...draft,
                  id_token_encrypted_response_alg: event.target.checked ? 'RSA-OAEP-256' : '',
                  id_token_encrypted_response_enc: event.target.checked ? 'A256GCM' : '',
                })}
              />{' '}Encrypt ID token responses (RSA-OAEP-256 / A256GCM)
            </label>
          </p>
          {encryptionEnabled(draft.id_token_encrypted_response_alg, draft.id_token_encrypted_response_enc)
            && (draft.id_token_encrypted_response_alg !== 'RSA-OAEP-256' || draft.id_token_encrypted_response_enc !== 'A256GCM')
            && <p className="muted">Existing ID token encryption pair: <code>{draft.id_token_encrypted_response_alg}</code> / <code>{draft.id_token_encrypted_response_enc}</code>. It will be preserved until changed.</p>}
          <p>
            <label>
              <input
                type="checkbox"
                name="userinfo_encrypted_response_alg"
                checked={encryptionEnabled(draft.userinfo_encrypted_response_alg, draft.userinfo_encrypted_response_enc)}
                onChange={(event) => onChange({ ...draft,
                  userinfo_encrypted_response_alg: event.target.checked ? 'RSA-OAEP-256' : '',
                  userinfo_encrypted_response_enc: event.target.checked ? 'A256GCM' : '',
                })}
              />{' '}Encrypt UserInfo responses (RSA-OAEP-256 / A256GCM)
            </label>
          </p>
          {encryptionEnabled(draft.userinfo_encrypted_response_alg, draft.userinfo_encrypted_response_enc)
            && (draft.userinfo_encrypted_response_alg !== 'RSA-OAEP-256' || draft.userinfo_encrypted_response_enc !== 'A256GCM')
            && <p className="muted">Existing UserInfo encryption pair: <code>{draft.userinfo_encrypted_response_alg}</code> / <code>{draft.userinfo_encrypted_response_enc}</code>. It will be preserved until changed.</p>}
          <p className="muted">Response encryption requires an inline JWK Set with an encryption key. UserInfo encryption also requires a UserInfo signing algorithm.</p>
          <FormField>
            <FieldLabel htmlFor="subject-type">Subject type</FieldLabel>
            <FormSelect
              id="subject-type"
              name="subject_type"
              value={draft.subject_type}
              onValueChange={(value) => onChange({ ...draft, subject_type: value })}
             disabled={busy || !canWrite} options={[{"value": "public", "label": "Public"}, {"value": "pairwise", "label": "Pairwise"}]} />
          </FormField>
          <FormField>
            <FieldLabel htmlFor="sector-identifier-uri">Sector identifier URL</FieldLabel>
            <Input
              id="sector-identifier-uri"
              name="sector_identifier_uri"
              type="url"
              value={draft.sector_identifier_uri}
              onChange={(event) =>
                onChange({ ...draft, sector_identifier_uri: event.target.value })
              }
            />
          </FormField>
          <p className="muted">
            Fetched and checked when the client is saved: every redirect URI above has to appear
            in the document it serves.
          </p>
        </FieldGroup></FieldSet></TabsContent>

        <TabsContent value="tokens"><FieldSet disabled={busy || !canWrite}>
          <FieldLegend id="client-token-roles">Application roles in tokens</FieldLegend>
          <FieldGroup>
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
        </FieldGroup></FieldSet></TabsContent>

        {guided && <TabsContent value="review"><Panel title="Review application">
          <dl className="detail">
            <div><dt>Name</dt><dd>{draft.client_name || 'Missing name'}</dd></div>
            <div><dt>Security profile</dt><dd>{draft.compliance_profile}</dd></div>
            <div><dt>Client authentication</dt><dd>{draft.token_endpoint_auth_method}</dd></div>
            <div><dt>Callback URLs</dt><dd><pre>{draft.redirect_uris || 'No callbacks'}</pre></dd></div>
            <div><dt>Grant types</dt><dd>{draft.grant_types.join(', ') || 'None'}</dd></div>
          </dl>
          <p>The server validates the full configuration when you register. Registration does not prove an application can sign in; use its integration check and perform a real sign-in afterward.</p>
        </Panel></TabsContent>}
        <Actions>
          {guided && tab !== 'settings' && <Button disabled={busy} onClick={() => onTab(['settings', 'callbacks', 'credentials', 'grants', 'tokens', 'review'][Math.max(0, ['settings', 'callbacks', 'credentials', 'grants', 'tokens', 'review'].indexOf(tab) - 1)]!)}>Previous step</Button>}
          {guided && tab !== 'review' && <Button variant="primary" disabled={busy} onClick={() => onTab(['settings', 'callbacks', 'credentials', 'grants', 'tokens', 'review'][['settings', 'callbacks', 'credentials', 'grants', 'tokens', 'review'].indexOf(tab) + 1] ?? 'review')}>Continue</Button>}
          <Button type="button" disabled={busy} onClick={onClose}>
            Close
          </Button>
          {canWrite && (!guided || tab === 'review') && <Button type="submit" variant="primary" disabled={busy}>
            {editing.kind === 'existing' ? 'Save client' : 'Register client'}
          </Button>}
        </Actions>
      </form>
      {confirmingRevoke && editing.kind === 'existing' && <ConfirmDialog
        title={`Revoke ${editing.document.client_id}'s secret?`}
        body="Clients using this shared secret will be unable to authenticate until a new secret is issued and deployed."
        confirmLabel="Revoke secret"
        busy={busy}
        onCancel={() => setConfirmingRevoke(false)}
        onConfirm={() => { setConfirmingRevoke(false); onRevokeSecret(); }}
      />}
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
    <details className="registration-settings">
      <summary>Dynamic client registration<span className="muted">Deployment configuration</span></summary>
      <div className="registration-settings-body">
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
            Initial access tokens are managed in your deployment’s configuration file.
            This console cannot issue, expire or revoke them. Contact your deployment administrator to change registration access.
          </p>
        )}
      </div>
    </details>
  );
}
