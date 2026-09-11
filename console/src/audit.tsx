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
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { read, type Session } from './api';

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
  readonly type: string;
  readonly from: string;
  readonly until: string;
}

export const EMPTY_FILTERS: Filters = {
  agent: '',
  owner: '',
  user: '',
  grant: '',
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
    const trimmed = value.trim();
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

export function AuditExplorer({ session }: { session: Session }): JSX.Element {
  const [draft, setDraft] = useState<Filters>(EMPTY_FILTERS);
  const [applied, setApplied] = useState<Filters>(EMPTY_FILTERS);
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [more, setMore] = useState(false);
  const mayExport = session.scopes.includes('admin.audit:read');

  const fetchPage = useCallback((filters: Filters, cursor?: string): Promise<Page> => {
    return read(`audit/events${queryOf(filters, cursor)}`) as Promise<Page>;
  }, []);

  const refresh = useCallback(
    (filters: Filters) => {
      setLoad({ kind: 'loading' });
      fetchPage(filters).then(
        (page) => setLoad({ kind: 'ready', rows: page.items, next: page.next_cursor }),
        (error: unknown) =>
          setLoad({
            kind: 'failed',
            message: error instanceof Error ? error.message : 'the trail could not be read',
          }),
      );
    },
    [fetchPage],
  );

  useEffect(() => refresh(applied), [applied, refresh]);

  const loadMore = (): void => {
    if (load.kind !== 'ready' || load.next === null) {
      return;
    }
    const cursor = load.next;
    setMore(true);
    fetchPage(applied, cursor).then(
      (page) => {
        setLoad({ kind: 'ready', rows: [...load.rows, ...page.items], next: page.next_cursor });
        setMore(false);
      },
      (error: unknown) => {
        setLoad({
          kind: 'failed',
          message: error instanceof Error ? error.message : 'the next page could not be read',
        });
        setMore(false);
      },
    );
  };

  const field = (name: keyof Filters, label: string, placeholder: string): JSX.Element => (
    <span>
      <label htmlFor={`audit-${name}`}>{label}</label>{' '}
      <input
        id={`audit-${name}`}
        name={name}
        type="text"
        value={draft[name]}
        placeholder={placeholder}
        maxLength={256}
        onChange={(event) => setDraft({ ...draft, [name]: event.target.value })}
      />{' '}
    </span>
  );

  return (
    <>
      <h2>Audit trail</h2>
      <p className="muted">
        What happened in <strong>{session.tenant}</strong>, newest first. Filter by the agent
        that acted, the person it acted for, the person concerned, an authorization, an event
        type or a time window; each row shows the delegation chain the record carries.
      </p>

      <form
        role="search"
        onSubmit={(event) => {
          event.preventDefault();
          setApplied(draft);
        }}
      >
        {field('agent', 'Agent', 'client_id')}
        {field('owner', 'Owner', 'subject the agent acts for')}
        {field('user', 'User', 'subject')}
        {field('grant', 'Grant', 'grant id (UUID)')}
        {field('type', 'Event type', 'token.exchanged, session.revoked')}
        {field('from', 'From', '2026-01-01T00:00:00Z')}
        {field('until', 'Until', '2026-12-31T00:00:00Z')}
        <button type="submit">Apply filters</button>{' '}
        <button
          type="button"
          onClick={() => {
            setDraft(EMPTY_FILTERS);
            setApplied(EMPTY_FILTERS);
          }}
        >
          Clear
        </button>{' '}
        {/*
          The export needs `admin.audit:read`, which is also what this screen
          opens with — so the link is shown to whoever got here, and hidden
          for a session whose scopes say otherwise. The server answers 403
          regardless; see the module documentation.
        */}
        {mayExport && (
          <a href={`api/v1/audit/events/export${queryOf(applied)}`} download="audit-events.ndjson">
            Export as NDJSON
          </a>
        )}
      </form>

      <Trail load={load} more={more} onMore={loadMore} onRetry={() => refresh(applied)} />
    </>
  );
}

function Trail({
  load,
  more,
  onMore,
  onRetry,
}: {
  load: Load;
  more: boolean;
  onMore: () => void;
  onRetry: () => void;
}): JSX.Element {
  if (load.kind === 'loading') {
    return <p>Reading the trail.</p>;
  }
  if (load.kind === 'failed') {
    return (
      <>
        <p role="alert" className="refusal">
          {load.message}
        </p>
        <button type="button" onClick={onRetry}>
          Try again
        </button>
      </>
    );
  }
  if (load.rows.length === 0) {
    return <p>No record matches.</p>;
  }
  return (
    <>
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
                  <td>{row.occurred_at}</td>
                  <td>
                    <code>{row.type}</code>
                  </td>
                  <td>{row.outcome}</td>
                  <td>
                    <Chain links={chainOf(row)} />
                  </td>
                  <td>
                    <DetailList row={row} />
                  </td>
                </>
              )}
            </tr>
          ))}
        </tbody>
      </table>
      {load.next !== null && (
        <p>
          <button type="button" disabled={more} onClick={onMore}>
            Load more
          </button>
        </p>
      )}
    </>
  );
}

/**
 * The chain, as an ordered list: `user alice → agent c.a for alice → agent
 * c.b for alice`. An `<ol>` rather than a string, so that a screen reader
 * announces the order the arrows only draw.
 */
function Chain({ links }: { links: readonly string[] }): JSX.Element {
  if (links.length === 0) {
    return <span className="muted">none</span>;
  }
  return (
    <ol className="chain" aria-label="Delegation chain">
      {links.map((link, index) => (
        <li key={`${index}-${link}`}>{link}</li>
      ))}
    </ol>
  );
}

function DetailList({ row }: { row: AuditRow }): JSX.Element {
  const entries: [string, string][] = [];
  if (row.client_id !== undefined) {
    entries.push(['client', row.client_id]);
  }
  if (row.grant_id !== undefined) {
    entries.push(['grant', row.grant_id]);
  }
  if (row.session_id !== undefined) {
    entries.push(['session', row.session_id]);
  }
  for (const [key, value] of Object.entries(row.detail ?? {})) {
    entries.push([key, typeof value === 'string' ? value : JSON.stringify(value)]);
  }
  if (entries.length === 0) {
    return <span className="muted">none</span>;
  }
  return (
    <dl className="detail">
      {entries.map(([key, value]) => (
        <div key={key}>
          <dt>{key}</dt>
          <dd>
            <code>{value}</code>
          </dd>
        </div>
      ))}
    </dl>
  );
}
