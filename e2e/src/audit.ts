/**
 * Reading the audit trail from a browser test, because nothing else can.
 *
 * `ast-qwu` needs to assert what a refusal *recorded*, not only what it
 * answered — the whole point of the clone signal is that the browser is told
 * nothing and the operator is told everything. There is no read API for the
 * trail: `crates/admin-api` writes events and never lists them, and adding an
 * endpoint so that a test can read one would be a production surface invented
 * for a test.
 *
 * How the query gets to the database — and why the connection string comes
 * from `scripts/browser-tests.sh` rather than being guessed — is `database.ts`,
 * which `ast-ndk.4` split out when the recovery sweep needed the same access
 * for the outbox.
 */
import { query, quote } from './database.js';

/** One event, with only the columns an assertion here has any use for. */
export interface AuditEvent {
  readonly event_type: string;
  readonly outcome: string;
  readonly subject: string | null;
  readonly detail: Record<string, string | number | boolean>;
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
