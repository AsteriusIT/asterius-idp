/**
 * The audit explorer (`ast-f7m.8`, over the query API of `ast-lh3.9`).
 *
 * The trail, filtered by agent, owner, user, grant, event type and time
 * window, one page at a time, with the RFC 8693 `act` chain of each record
 * drawn as the chain it is: the person, then each agent that delegated,
 * then the agent that acted. And the export: the same records as NDJSON,
 * downloaded through the browser with the same filters.
 *
 * # Why the export is a link and not a fetch
 *
 * `GET /audit/events/export` streams up to a hundred thousand lines. A
 * `fetch` that buffered them into a `Blob` would hold the whole export in
 * the tab's memory before the download dialog appeared; an anchor with
 * `download` hands the stream to the browser's downloader, which writes it
 * to disk as it arrives. The request is same-origin and carries the session
 * cookie like every other; the server decides the RBAC
 * (`admin.audit:read`), and this screen is only reachable by a caller that
 * holds it, so the link is not an offer the server will refuse.
 *
 * # Nothing here is a security control
 *
 * The filters are sent to the server, which parses them into a closed set
 * (`crates/admin-api/src/audit.rs`, fuzzed) and matches them below the API.
 * Nothing in this bundle decides which rows an operator sees.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { AuditFilterBar } from './components/audit-filter-bar';
import { AgentTaskViewer } from './agent-task-viewer';
import type { JSX } from 'react';
import { useRouteParameters, setRouteParameters } from './route-state';
import { hrefOf } from './routes';
import { CopyValue } from './components/copy-value';
import { read, type Session } from './api';
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from './components/ui/sheet';
import { JsonValue } from './components/json-view';
import {
  Actions,
  Badge,
  Button,
  EmptyState,
  LoadFailure,
  Panel,
  Screen,
  Skeleton,
  Timestamp,
  Truncate,
} from './ui';

/** One party to a record, as `actor` and each `actor_chain` entry render. */
export interface ActorDocument {
  readonly type: 'user' | 'client' | 'agent' | 'admin' | 'system';
  readonly id: string;
  readonly on_behalf_of?: string;
}

/** One record, as `GET /audit/events` renders it. */
export interface AuditRow {
  readonly id: number;
  readonly hash: string;
  /** Present on a row this build could not read; every other member is absent. */
  readonly opaque?: string;
  readonly occurred_at?: string;
  readonly type?: string;
  readonly outcome?: string;
  readonly actor?: ActorDocument;
  readonly actor_chain?: readonly ActorDocument[];
  readonly agent_id?: string;
  readonly agent_owner?: string;
  readonly subject?: string;
  readonly client_id?: string;
  readonly session_id?: string;
  readonly grant_id?: string;
  readonly request_id?: string;
  readonly detail?: Readonly<Record<string, unknown>>;
  readonly diagnostic?: { readonly status: 'recorded' | 'expired' | 'unavailable' | 'not_recorded' | 'opaque'; readonly expires_at?: string; readonly snapshot?: unknown; readonly reason?: 'integrity_mismatch' };
}

interface Page {
  readonly items: readonly AuditRow[];
  readonly next_cursor: string | null;
}

/** The filters, in the names the API takes (`audit::PARAMETERS`). */
export interface Filters {
  readonly agent: string;
  readonly owner: string;
  readonly user: string;
  readonly grant: string;
  readonly task?: string;
  readonly request_id?: string;
  readonly session?: string;
  readonly type: string;
  readonly from: string;
  readonly until: string;
}

export const EMPTY_FILTERS: Filters = {
  agent: '',
  owner: '',
  user: '',
  grant: '',
  task: '',
  request_id: '',
  session: '',
  type: '',
  from: '',
  until: '',
};

/**
 * The query string for `filters`, with blanks left out.
 *
 * Blank rather than absent would be a 400: the server refuses an empty
 * value on purpose, so that `owner=` cannot be read as "every owner".
 */
export function queryOf(filters: Filters, cursor?: string): string {
  const query = new URLSearchParams();
  for (const [name, value] of Object.entries(filters)) {
    const trimmed = (value ?? "").trim();
    if (trimmed !== '') {
      query.set(name, trimmed);
    }
  }
  if (cursor !== undefined) {
    query.set('cursor', cursor);
  }
  const rendered = query.toString();
  return rendered === '' ? '' : `?${rendered}`;
}

/**
 * One link of a chain, as a person reads it.
 *
 * An agent is named by its client id and the person it acts for, because
 * that pairing is the whole point of the `act` claim: a client id alone
 * says which software, not on whose authority.
 */
export function describeActor(actor: ActorDocument): string {
  if (actor.type === 'agent' && actor.on_behalf_of !== undefined) {
    return `agent ${actor.id} for ${actor.on_behalf_of}`;
  }
  return `${actor.type} ${actor.id}`;
}

/**
 * The delegation chain of a record, outermost first: the person, each
 * `act` link, then the actor.
 *
 * The person is the record's `subject` when it has one and the acting
 * agent's owner otherwise; a record with neither starts at its first link.
 * The order is the `act` claim's (RFC 8693 §4.1): the outermost entry is
 * the party that delegated first.
 */
export function chainOf(row: AuditRow): readonly string[] {
  const links: string[] = [];
  const person = row.subject ?? row.agent_owner;
  if (person !== undefined) {
    links.push(`user ${person}`);
  }
  for (const link of row.actor_chain ?? []) {
    links.push(describeActor(link));
  }
  if (row.actor !== undefined) {
    links.push(describeActor(row.actor));
  }
  return links;
}

type Load =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly rows: readonly AuditRow[]; readonly next: string | null }
  | { readonly kind: 'failed'; readonly message: string };

export function AuditExplorer({ session }: Readonly<{ session: Session }>): JSX.Element {
  const parameters = useRouteParameters();
  const correlation = ['request_id', 'session', 'grant'].map(key => parameters.get(key) ?? '').join('|');
  const [draft, setDraft] = useState<Filters>(EMPTY_FILTERS);
  const [applied, setApplied] = useState<Filters>(EMPTY_FILTERS);
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [more, setMore] = useState(false);
  const requestGeneration = useRef(0);
  const mayExport = session.scopes.includes('admin.audit:read');

  const fetchPage = useCallback((filters: Filters, cursor?: string): Promise<Page> => {
    return read(`audit/events${queryOf(filters, cursor)}`) as Promise<Page>;
  }, []);

  const refresh = useCallback(
    (filters: Filters) => {
      const generation = ++requestGeneration.current;
      setMore(false); setLoad({ kind: 'loading' });
      fetchPage(filters).then(
        (page) => { if (generation === requestGeneration.current) setLoad({ kind: 'ready', rows: page.items, next: page.next_cursor }); },
        (error: unknown) => {
          if (generation !== requestGeneration.current) return;
          setLoad({
            kind: 'failed',
            message: error instanceof Error ? error.message : 'the trail could not be read',
          });
        },
      );
    },
    [fetchPage],
  );

  useEffect(() => refresh(applied), [applied, refresh]);
  useEffect(() => {
    const [request_id = '', session = '', grant = ''] = correlation.split('|');
    const linked = { ...EMPTY_FILTERS, request_id, session, grant };
    setDraft(linked); setApplied(linked);
  }, [correlation]);

  const loadMore = (): void => {
    if (more || load.kind !== 'ready' || load.next === null) {
      return;
    }
    const cursor = load.next;
    const generation = requestGeneration.current;
    setMore(true);
    fetchPage(applied, cursor).then(
      (page) => {
        if (generation !== requestGeneration.current) return;
        setLoad({ kind: 'ready', rows: [...load.rows, ...page.items], next: page.next_cursor });
        setMore(false);
      },
      (error: unknown) => {
        if (generation !== requestGeneration.current) return;
        setLoad({
          kind: 'failed',
          message: error instanceof Error ? error.message : 'the next page could not be read',
        });
        setMore(false);
      },
    );
  };

  return (
    <Screen
      title="Audit trail"
      description={
        <>
          Review recorded events in <strong>{session.workspace}</strong>, newest first. Filter by identity,
          authorization, event type or UTC time; inspect the delegation chain each record carries.
        </>
      }
      actions={
        /*
          The export needs `admin.audit:read`, which is also what this screen
          opens with — so the link is shown to whoever got here, and hidden
          for a session whose scopes say otherwise. The server answers 403
          regardless; see the module documentation.
        */
        mayExport ? (
          <a
            className="button"
            href={`api/v1/audit/events/export${queryOf(applied)}`}
            download="audit-events.ndjson"
          >
            Export as NDJSON
          </a>
        ) : undefined
      }
    >
      <AgentTaskViewer session={session} onAudit={task => { const next = { ...EMPTY_FILTERS, task }; setDraft(next); setApplied(next); }} />
      <p className="muted">Times use UTC. The export includes records matching the applied filters, up to the server’s export limit.</p>
      <Actions>{[1, 24, 168].map(hours => <Button key={hours} small onClick={() => {
        const next = { ...draft, from: new Date(Date.now() - hours * 3600000).toISOString(), until: new Date().toISOString() };
        setDraft(next); setApplied(next);
      }}>{hours === 1 ? 'Last hour' : hours === 24 ? 'Last 24 hours' : 'Last 7 days'}</Button>)}</Actions>
      <AuditFilterBar draft={draft} applied={applied} onDraft={setDraft} onApply={setApplied} empty={EMPTY_FILTERS} />

      <AuditEventDrawer />
      <Panel title="Records">
        <Trail load={load} more={more} onMore={loadMore} onRetry={() => refresh(applied)} />
      </Panel>
    </Screen>
  );
}

function Trail({
  load,
  more,
  onMore,
  onRetry,
}: Readonly<{
  load: Load;
  more: boolean;
  onMore: () => void;
  onRetry: () => void;
}>): JSX.Element {
  if (load.kind === 'loading') {
    return <Skeleton rows={5} label="Reading the trail." />;
  }
  if (load.kind === 'failed') {
    return <LoadFailure message={load.message} onRetry={onRetry} />;
  }
  if (load.rows.length === 0) {
    return <EmptyState title="No record matches." body="Widen the filters, or clear them." />;
  }
  return (
    <>
      {/*
        A scrolling box has to be reachable by keyboard (WCAG 2.2 §2.1.1), and
        this one really scrolls: a record's detail is a list of opaque
        identifiers and there is a width past which they cannot all be shown.
        `tabIndex` makes it a stop and the region carries a name, which is what
        axe asks for and what a screen reader announces on arrival
        (`ast-f9j5`).
      */}
      <section className="table-wrap" tabIndex={0} aria-label="Audit records">
      <table>
        <thead>
          <tr>
            <th scope="col">When</th>
            <th scope="col">Event</th>
            <th scope="col">Outcome</th>
            <th scope="col">Chain</th>
            <th scope="col">Detail</th>
          </tr>
        </thead>
        <tbody>
          {load.rows.map((row) => (
            <tr key={row.id}>
              {row.opaque !== undefined ? (
                <>
                  <td>#{row.id}</td>
                  <td colSpan={4} className="muted">
                    A record this console cannot read ({row.opaque}); hash{' '}
                    <code>{row.hash.slice(0, 16)}…</code>
                  </td>
                </>
              ) : (
                <>
                  <td>
                    {row.occurred_at === undefined ? (
                      <span className="muted">—</span>
                    ) : (
                      <Timestamp value={row.occurred_at} />
                    )}
                  </td>
                  <td>
                    {/* One token, never broken across two lines (`ast-f9j5`):
                        `auth.login` printed as "auth.l / ogin" is what a
                        column with no floor of its own does when the table
                        runs out of room. */}
                    <code className="whitespace-nowrap">{row.type}</code>
                  </td>
                  <td>
                    {/* `outcome` is optional in the record, and an empty badge
                        would be a state nobody recorded. */}
                    {row.outcome === undefined ? (
                      <span className="muted">—</span>
                    ) : (
                      <Badge tone={row.outcome === 'success' ? 'ok' : 'bad'}>{row.outcome}</Badge>
                    )}
                  </td>
                  <td>
                    <Chain links={chainOf(row)} />
                  </td>
                  <td>
                    <Button small onClick={() => setRouteParameters('audit', { id: String(row.id) })}>Inspect event #{row.id}</Button>
                  </td>
                </>
              )}
            </tr>
          ))}
        </tbody>
      </table>
      </section>
      {load.next !== null && (
        <Actions>
          <Button disabled={more} onClick={onMore}>
            Load more
          </Button>
        </Actions>
      )}
    </>
  );
}

/**
 * The chain, as an ordered list: `user alice → agent c.a for alice → agent
 * c.b for alice`. An `<ol>` rather than a string, so that a screen reader
 * announces the order the arrows only draw.
 */
function Chain({ links }: Readonly<{ links: readonly string[] }>): JSX.Element {
  if (links.length === 0) {
    return <span className="muted">none</span>;
  }
  return (
    <ol className="chain" aria-label="Delegation chain">
      {links.map((link, index) => (
        <li key={`${index}-${link}`}>
          {/* Bounded, with the whole link in the `title` (`ast-f9j5`): a chain
              of subjects is made of identifiers that have no width of their
              own, and this is the column that used to push the detail beside
              it off the edge of the card. */}
          <Truncate text={link} className="max-w-[28ch]" />
        </li>
      ))}
    </ol>
  );
}

function DetailList({ row }: Readonly<{ row: AuditRow }>): JSX.Element {
  const entries: [string, unknown][] = [];
  if (row.client_id !== undefined) {
    entries.push(['client', row.client_id]);
  }
  if (row.request_id !== undefined) { entries.push(['support reference', row.request_id]); }
  if (row.grant_id !== undefined) {
    entries.push(['grant', row.grant_id]);
  }
  if (row.session_id !== undefined) {
    entries.push(['session', row.session_id]);
  }
  for (const [key, value] of Object.entries(row.detail ?? {})) {
    entries.push([key, value]);
  }
  if (entries.length === 0) {
    return <span className="muted">none</span>;
  }
  return (
    <details className="audit-detail">
      <summary>
        {entries.length} {entries.length === 1 ? 'field' : 'fields'}
      </summary>
      <dl className="detail">
        {entries.map(([key, value]) => (
          <div key={key}>
            <dt>{key}</dt>
            <dd>
              {typeof value === 'string' ? (
                /* Elided rather than wrapped one character at a time, and whole
                   in the `title` (`ast-f9j5`): a session id is opaque, and a
                   column of six-character fragments is not a reading of it. */
                <code>
                  <Truncate text={value} className="max-w-[20ch]" />
                </code>
              ) : (
                <JsonValue value={value} />
              )}
            </dd>
          </div>
        ))}
      </dl>
    </details>
  );
}


function AuditEventDrawer() {
  const id = useRouteParameters().get('id');
  const [record, setRecord] = useState<AuditRow | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    let active = true;
    setRecord(null); setError(null);
    if (id !== null) {
      if (!/^[1-9][0-9]{0,18}$/.test(id)) setError('The event ID is invalid.');
      else read(`audit/events/${encodeURIComponent(id)}`).then(
        value => { if (active) setRecord(value as AuditRow); },
        reason => { if (active) setError(reason instanceof Error ? reason.message : 'The event could not be read.'); },
      );
    }
    return () => { active = false; };
  }, [id, retry]);
  return <Sheet open={id !== null} onOpenChange={open => { if (!open) setRouteParameters('audit', { id: null }); }}>
    <SheetContent className="record-detail-sheet">
      <SheetHeader><SheetTitle>Event #{id}</SheetTitle><SheetDescription>Read-only event details. Times use UTC.</SheetDescription></SheetHeader>
      <div className="record-detail-body">
        {error && <LoadFailure message={error} onRetry={() => setRetry(retry + 1)} />}
        {!record && !error && <Skeleton rows={3} label="Reading event." />}
        {record && <><p><strong>{record.type ?? 'Unreadable record'}</strong> · {record.outcome}</p><p><Timestamp value={record.occurred_at ?? null} /></p><Chain links={chainOf(record)} /><DetailList row={record} />
          <Panel title="Authorization evidence">
            <p>{({ recorded: 'Evidence from the evaluated policy snapshot.', expired: 'The policy evidence has expired.', unavailable: 'The recorded evidence is currently unavailable.', not_recorded: 'No policy evidence was recorded for this event.', opaque: 'This event cannot be decoded by this server.' })[record.diagnostic?.status ?? 'not_recorded']}</p>
            {record.diagnostic?.reason === 'integrity_mismatch' && <p>The recorded evidence failed its integrity check and has been withheld.</p>}
            {record.diagnostic?.expires_at && <p>Available until <Timestamp value={record.diagnostic.expires_at} /></p>}
            {record.diagnostic?.snapshot !== undefined && <JsonValue value={record.diagnostic.snapshot} />}
            <p>Only events recorded by Asterius or an integrated policy enforcement point are visible here.</p>
          </Panel>
          <Actions>
            {record.request_id && <a href={hrefOf('audit', { request_id: record.request_id })}>Follow request</a>}
            {record.session_id && <a href={hrefOf('audit', { session: record.session_id })}>Follow session</a>}
            {record.grant_id && <a href={hrefOf('audit', { grant: record.grant_id })}>Follow grant</a>}
            {typeof record.detail?.parent_grant_id === 'string' && <a href={hrefOf('audit', { grant: record.detail.parent_grant_id })}>Follow parent grant</a>}
          </Actions>
          <CopyValue value={new URL(hrefOf('audit', { id: String(record.id) }), window.location.href).href} label="Copy event link" />
        </>}
      </div>
    </SheetContent>
  </Sheet>;
}
