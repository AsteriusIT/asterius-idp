/** Account mail delivery metadata. The API never supplies recipient or body. */
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { read, type Session } from './api';
import { Badge, Button, DataTable, EmptyState, LoadFailure, Panel, Screen, Skeleton, Timestamp } from './ui';

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

type Load =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly items: readonly MailRow[] }
  | { readonly kind: 'failed'; readonly message: string };

export function MailStatus({ session }: Readonly<{ session: Session }>): JSX.Element {
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    read('notifications/status').then(
      (data) => setLoad({ kind: 'ready', items: (data as MailResponse).items }),
      (error: unknown) => setLoad({
        kind: 'failed',
        message: error instanceof Error ? error.message : 'Mail status could not be read',
      }),
    );
  }, []);
  useEffect(refresh, [refresh]);

  return (
    <Screen
      title="Mail delivery"
      description={`Recent account messages for ${session.workspace}. Sent means the provider accepted a message; inbox delivery is not confirmed.`}
      actions={<Button onClick={refresh}>Refresh</Button>}
    >
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
    </Screen>
  );
}
