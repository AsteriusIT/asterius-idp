/** Account mail delivery metadata. The API never supplies recipient or body. */
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { mutate, read, type Session } from './api';
import { Badge, Button, ConfirmDialog, DataTable, EmptyState, LoadFailure, Message, Panel, Screen, Skeleton, Timestamp } from './ui';

interface MailRow {
  readonly id: number;
  readonly kind: string;
  readonly status: 'queued' | 'journalled' | 'sent' | 'failed' | 'abandoned' | 'expired';
  readonly attempts: number;
  readonly created_at: string;
  readonly delivered_at: string | null;
  readonly last_error: string | null;
}

interface MailResponse {
  readonly items: readonly MailRow[];
}

interface InvitationRow {
  readonly id: string;
  readonly email: string;
  readonly username: string;
  readonly created_at: number;
  readonly expires_at: number;
  readonly status: 'pending' | 'expired' | 'accepted' | 'revoked';
}

type Load =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly items: readonly MailRow[]; readonly invitations: readonly InvitationRow[] }
  | { readonly kind: 'failed'; readonly message: string };

export function MailStatus({ session }: Readonly<{ session: Session }>): JSX.Element {
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ tone: 'success' | 'error'; text: string } | null>(null);
  const [revoking, setRevoking] = useState<InvitationRow | null>(null);
  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    Promise.all([read('notifications/status'), read('invitations')]).then(
      ([mail, invitationData]) => setLoad({
        kind: 'ready',
        items: (mail as MailResponse).items,
        invitations: (invitationData as { readonly items: readonly InvitationRow[] }).items,
      }),
      (error: unknown) => setLoad({
        kind: 'failed',
        message: error instanceof Error ? error.message : 'Mail status could not be read',
      }),
    );
  }, []);
  useEffect(refresh, [refresh]);

  const canManageInvitations = session.scopes.includes('admin.lifecycle:write');
  const actOnInvitation = async (row: InvitationRow, action: 'resend' | 'revoke'): Promise<void> => {
    setBusy(true);
    setNotice(null);
    try {
      if (action === 'resend') {
        await mutate(`invitations/${row.id}/resend`, 'POST', session, {
          expires_at: Math.floor(Date.now() / 1000) + 24 * 60 * 60,
        });
        setNotice({ tone: 'success', text: `A fresh one-use invitation link was queued for ${row.email}. The previous link no longer works.` });
      } else {
        await mutate(`invitations/${row.id}`, 'DELETE', session);
        setNotice({ tone: 'success', text: `The invitation for ${row.email} was revoked.` });
      }
      refresh();
    } catch (error) {
      setNotice({ tone: 'error', text: error instanceof Error ? error.message : 'The invitation action failed' });
    } finally {
      setBusy(false);
      setRevoking(null);
    }
  };

  return (
    <Screen
      title="Mail delivery"
      description={`Recent account messages for ${session.workspace}. Sent means the provider accepted a message; inbox delivery is not confirmed.`}
      actions={<Button onClick={refresh}>Refresh</Button>}
    >
      {notice !== null && <Message tone={notice.tone}>{notice.text}</Message>}
      <Panel title="Recent invitations" description="Expired links cannot be used. Resending rotates the token and invalidates every earlier link. No token or message content is shown.">
        {load.kind === 'loading' && <Skeleton label="Loading invitation status" />}
        {load.kind === 'ready' && (
          <DataTable
            rows={load.invitations}
            rowKey={(row) => row.id}
            empty={<EmptyState title="No invitations yet" body="New invitations will appear here after an administrator creates them." />}
            columns={[
              { key: 'username', header: 'Username', cell: (row) => row.username },
              { key: 'email', header: 'Email', cell: (row) => row.email },
              { key: 'status', header: 'Status', cell: (row) => <Badge tone={row.status === 'pending' ? 'neutral' : row.status === 'accepted' ? 'ok' : 'warn'}>{row.status}</Badge> },
              { key: 'expires', header: 'Expires', cell: (row) => <Timestamp value={new Date(row.expires_at * 1000).toISOString()} /> },
              ...(canManageInvitations ? [{
                key: 'actions', header: 'Actions', cell: (row: InvitationRow) => row.status === 'pending' || row.status === 'expired' ? (
                  <span className="row">
                    <Button disabled={busy} onClick={() => void actOnInvitation(row, 'resend')}>Resend</Button>
                    <Button variant="danger" disabled={busy} onClick={() => setRevoking(row)}>Revoke</Button>
                  </span>
                ) : '—',
              }] : []),
            ]}
          />
        )}
        {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
      </Panel>
      <Panel title="Recent messages" description="Recipient addresses and message contents are never shown here.">
        {load.kind === 'loading' && <Skeleton label="Loading mail status" />}
        {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
        {load.kind === 'ready' && (
          <DataTable
            rows={load.items}
            rowKey={(row) => String(row.id)}
            empty={<EmptyState title="No account mail yet" body="Messages will appear here after they enter the outbox." />}
            search={{
              of: (row) => `${row.id} ${row.kind} ${row.status}`,
              placeholder: 'Filter by row, kind or status…',
              label: 'Filter recent mail by row, kind or status',
            }}
            columns={[
              { key: 'id', header: 'Row', numeric: true, sortBy: (row) => row.id, cell: (row) => row.id },
              { key: 'kind', header: 'Kind', sortBy: (row) => row.kind, cell: (row) => <code>{row.kind.replace(/^notification\./, '')}</code> },
              { key: 'status', header: 'Status', sortBy: (row) => row.status, cell: (row) => (
                <Badge tone={row.status === 'sent' ? 'ok' : row.status === 'failed' || row.status === 'abandoned' ? 'warn' : 'neutral'}>{row.status}</Badge>
              ) },
              { key: 'attempts', header: 'Attempts', numeric: true, sortBy: (row) => row.attempts, cell: (row) => row.attempts },
              { key: 'queued', header: 'Queued', sortBy: (row) => row.created_at, cell: (row) => <Timestamp value={row.created_at} /> },
              { key: 'accepted', header: 'Accepted', sortBy: (row) => row.delivered_at ?? '', cell: (row) => <Timestamp value={row.delivered_at} /> },
              { key: 'error', header: 'Last error', cell: (row) => row.last_error ?? '—' },
            ]}
          />
        )}
      </Panel>
      {revoking !== null && <ConfirmDialog
        title={`Revoke invitation for ${revoking.username}?`}
        body="The existing one-use link will stop working. The user will need a new invitation to finish setup."
        confirmLabel="Revoke invitation"
        busy={busy}
        onCancel={() => setRevoking(null)}
        onConfirm={() => void actOnInvitation(revoking, 'revoke')}
      />}
    </Screen>
  );
}
