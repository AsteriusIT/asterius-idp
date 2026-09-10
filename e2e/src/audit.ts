/**
 * Reading the audit trail from a browser test, because nothing else can.
 *
 * `ast-qwu` needs to assert what a refusal *recorded*, not only what it
 * answered — the whole point of the clone signal is that the browser is told
 * nothing and the operator is told everything. There is no read API for the
 * trail: `crates/admin-api` writes events and never lists them, and adding an
 * endpoint so that a test can read one would be a production surface invented
 * for a test. So this reads the table, the way `scripts/browser-tests.sh`
 * already reads and seeds the database around the sweep.
 *
 * `psql` when it is installed, the compose container when it is not: the same
 * two cases, in the same order, as `psql_run` in that script. The connection
 * string comes from the script (`E2E_DATABASE_URL`), so there is no second
 * source of truth for which database is under test — a helper that guessed
 * `postgres://…/asterius` would happily read a *different* database's trail
 * and pass while the one under test recorded nothing.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);

/** Where the trail is. Set by `scripts/browser-tests.sh`. */
const DATABASE_URL = process.env.E2E_DATABASE_URL ?? '';

/** One event, with only the columns an assertion here has any use for. */
export interface AuditEvent {
  readonly event_type: string;
  readonly outcome: string;
  readonly subject: string | null;
  readonly detail: Record<string, string | number | boolean>;
}

/** Runs one query and returns its rows, which the query itself makes JSON. */
async function query(sql: string): Promise<unknown[]> {
  if (DATABASE_URL === '') {
    throw new Error(
      'E2E_DATABASE_URL is unset: run this spec through scripts/browser-tests.sh, ' +
        'which knows which database the server under test is using.',
    );
  }
  // Deliberately not the compose-container fallback `scripts/browser-tests.sh`
  // keeps for seeding: that one connects to the container's own `asterius`
  // database and ignores the connection string, which is harmless for a seed
  // and not harmless here — reading a *different* database's trail would find
  // no clone signal and blame the server for it. A missing client is a
  // precondition with a sentence attached instead.
  const wrapped = `select coalesce(json_agg(row_to_json(q)), '[]'::json)::text from (${sql}) q`;
  const { stdout } = await run('psql', [
    DATABASE_URL,
    '--quiet',
    '--no-psqlrc',
    '--tuples-only',
    '--no-align',
    '-c',
    wrapped,
  ]).catch((error: NodeJS.ErrnoException) => {
    throw error.code === 'ENOENT'
      ? new Error('psql is required to read the audit trail from a browser test')
      : error;
  });
  return JSON.parse(stdout.trim() || '[]') as unknown[];
}

/**
 * The most recent events of one type for one tenant, newest first.
 *
 * `since` is an ISO timestamp taken before the act under test, so a trail left
 * by an earlier test — or an earlier run against a database that was not
 * dropped — cannot be mistaken for this one's.
 */
export async function eventsSince(
  tenant: string,
  eventType: string,
  since: string,
  limit = 10,
): Promise<AuditEvent[]> {
  const quote = (value: string) => `'${value.replace(/'/g, "''")}'`;
  const rows = await query(
    `select event_type, outcome, subject, detail
       from audit_events
      where tenant_id = ${quote(tenant)}
        and event_type = ${quote(eventType)}
        and occurred_at >= ${quote(since)}::timestamptz
      order by occurred_at desc, event_id desc
      limit ${Number(limit)}`,
  );
  return rows as AuditEvent[];
}
