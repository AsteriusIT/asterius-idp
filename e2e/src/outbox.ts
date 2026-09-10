/**
 * The mailbox this deployment does not have.
 *
 * `PgOutboxMailSender` is the only sender this repository ships: it writes
 * every message to the transactional `outbox` and delivers nothing, on purpose
 * (`crates/store-pg/src/notifications.rs`). So the recovery link a person would
 * have received exists in exactly one place — that row — because the token
 * itself is stored as a digest and cannot be read back from anywhere else.
 *
 * Which is what lets `tests/no-js-account.spec.ts` walk a password reset the
 * way a person walks it, link included, without a mail server in the sweep.
 * Treat what comes back as a credential: it is one.
 */
import { query, quote } from './database.js';

/** Reads the most recent recovery link queued for one address. */
export async function latestRecoveryLink(tenant: string, recipient: string): Promise<string> {
  const rows = (await query(
    `select payload ->> 'link' as link
       from outbox
      where tenant_id = ${quote(tenant)}
        and kind = 'notification.account_recovery'
        and destination = ${quote(recipient)}
      order by created_at desc, outbox_id desc
      limit 1`,
  )) as { link: string | null }[];
  const link = rows[0]?.link;
  if (!link) {
    throw new Error(
      `no recovery message was queued for ${recipient}: the "check your email" page is ` +
        'the same page for an address this server knows and one it does not, so a missing ' +
        'row is the only way to tell that nothing was sent.',
    );
  }
  return link;
}
