/** Operator controls for explicitly configured upstream SSF transmitters. */
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { mutate, read, type Session } from './api';
import { toast } from './components/ui/toast';
import { Actions, Badge, Button, DataTable, EmptyState, LoadFailure, Message, Panel, Skeleton, Timestamp } from './ui';

interface Peer {
  readonly peer_client_id: string;
  readonly state: 'not_started' | 'pending_review' | 'established';
  readonly pending_since?: string;
  readonly last_polled_at?: string;
}

interface PeerList {
  readonly items: readonly Peer[];
}

type Load =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly peers: readonly Peer[] }
  | { readonly kind: 'failed'; readonly message: string };

export function SsfUpstreamPeers({ session }: Readonly<{ session: Session }>): JSX.Element {
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [busyPeer, setBusyPeer] = useState<string | null>(null);
  const [message, setMessage] = useState<{ tone: 'success' | 'error'; text: string } | null>(null);
  const writable = session.scopes.includes('admin.ssf:write');

  const refresh = useCallback(() => {
    read('ssf/upstream/peers').then(
      (response) => setLoad({ kind: 'ready', peers: (response as PeerList).items }),
      (error: unknown) => setLoad({
        kind: 'failed',
        message: error instanceof Error ? error.message : 'Upstream peers could not be read.',
      }),
    );
  }, []);

  useEffect(refresh, [refresh]);

  const operate = (peer: Peer, action: 'setup' | 'poll'): void => {
    setBusyPeer(peer.peer_client_id);
    setMessage(null);
    mutate(`ssf/upstream/${action}`, 'POST', session, { peer_client_id: peer.peer_client_id }).then(
      (response) => {
        const applied = action === 'poll' && (response as { event_applied?: boolean }).event_applied === true;
        const text = action === 'setup'
          ? `A poll stream was established for ${peer.peer_client_id}.`
          : applied
            ? `One event from ${peer.peer_client_id} was applied and acknowledged.`
            : `No new event was applied from ${peer.peer_client_id}.`;
        setMessage({ tone: 'success', text });
        toast.success(action === 'setup' ? 'Upstream stream established' : 'Upstream poll completed', text);
        refresh();
      },
      (error: unknown) => {
        const text = error instanceof Error ? error.message : 'The upstream operation was refused.';
        setMessage({ tone: 'error', text });
        toast.error('Upstream operation refused', text);
        refresh();
      },
    ).finally(() => setBusyPeer(null));
  };

  return (
    <Panel
      id="ssf-upstream-peers"
      title="Upstream transmitters"
      description="Inspect configured senders, establish a poll stream, or poll once. A stream pending review needs operator reconciliation before setup can be retried."
    >
      {message !== null && <Message tone={message.tone}>{message.text}</Message>}
      {load.kind === 'loading' && <Skeleton rows={3} label="Reading upstream transmitters." />}
      {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
      {load.kind === 'ready' && (
        <DataTable
          rows={load.peers}
          rowKey={(peer) => peer.peer_client_id}
          empty={<EmptyState title="No upstream transmitter configured." body="Configure an upstream peer on the server before creating a stream." />}
          columns={[
            { key: 'peer', header: 'Peer', sortBy: (peer) => peer.peer_client_id, cell: (peer) => <code>{peer.peer_client_id}</code> },
            { key: 'state', header: 'State', sortBy: (peer) => peer.state, cell: (peer) => (
              <Badge tone={peer.state === 'established' ? 'ok' : peer.state === 'pending_review' ? 'warn' : 'neutral'}>
                {peer.state === 'pending_review' ? 'Pending review' : peer.state === 'not_started' ? 'Not started' : 'Established'}
              </Badge>
            ) },
            { key: 'pending', header: 'Pending since', cell: (peer) => <Timestamp value={peer.pending_since ?? null} /> },
            { key: 'last_poll', header: 'Last poll', cell: (peer) => <Timestamp value={peer.last_polled_at ?? null} /> },
            { key: 'actions', header: 'Actions', cell: (peer) => writable ? (
              <Actions>
                {peer.state === 'not_started' && <Button type="button" disabled={busyPeer !== null} onClick={() => operate(peer, 'setup')}>Set up</Button>}
                {peer.state === 'established' && <Button type="button" disabled={busyPeer !== null} onClick={() => operate(peer, 'poll')}>Poll once</Button>}
                {peer.state === 'pending_review' && <span className="muted">Review required</span>}
              </Actions>
            ) : <span className="muted">Read only</span> },
          ]}
        />
      )}
    </Panel>
  );
}
