import { FlowOrigin } from './flow-origin';
/** Operator controls for explicitly configured upstream SSF transmitters. */
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { ApiError, mutate, read, type Session } from './api';
import { toast } from './components/ui/toast';
import { Actions, Badge, Button, ConfirmDialog, DataTable, EmptyState, LoadFailure, Message, Panel, Skeleton, Timestamp } from './ui';

interface Peer {
  readonly peer_client_id: string;
  readonly state: 'not_started' | 'pending_review' | 'established' | 'deletion_pending';
  readonly expected_audience: string;
  readonly allow_all_subjects: boolean;
  readonly pending_since?: string;
  readonly last_polled_at?: string;
  readonly last_verified_at?: string;
  readonly last_challenge_verified_at?: string;
}

interface PeerList {
  readonly items: readonly Peer[];
}

type Load =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly peers: readonly Peer[] }
  | { readonly kind: 'failed'; readonly message: string };

function stateGuidance(peer: Peer): string | null {
  if (peer.state === 'pending_review') {
    return 'Setup may have reached the transmitter. Compare its stream list with the local pending record before retrying; setup will not create another stream.';
  }
  if (peer.state === 'deletion_pending') {
    return 'Deletion was interrupted. Keep this peer configured and retry deletion to reconcile the recorded stream.';
  }
  if (peer.state === 'not_started' && !peer.allow_all_subjects) {
    return 'A transmitter whose default subject policy is ALL needs explicit all-subject consent before setup.';
  }
  return null;
}

function operationGuidance(error: unknown): string {
  if (error instanceof ApiError && error.status === 409) {
    return 'Refresh the peer state and reconcile the recorded stream with the transmitter before trying again.';
  }
  if (error instanceof ApiError && error.status === 503) {
    return 'Check the configured bearer credential, transmitter metadata and connectivity, then inspect server logs for the failed exchange.';
  }
  return 'Refresh the peer state before trying again.';
}

export function SsfUpstreamPeers({ session }: Readonly<{ session: Session }>): JSX.Element {
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [busyPeer, setBusyPeer] = useState<string | null>(null);
  const [deletePeer, setDeletePeer] = useState<Peer | null>(null);
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

  const operate = (peer: Peer, action: 'setup' | 'poll' | 'verify' | 'request-verification' | 'delete'): void => {
    setBusyPeer(peer.peer_client_id);
    setMessage(null);
    mutate(`ssf/upstream/${action}`, 'POST', session, { peer_client_id: peer.peer_client_id }).then(
      (response) => {
        const applied = action === 'poll' && (response as { event_applied?: boolean }).event_applied === true;
        const text = action === 'setup'
          ? `A poll stream was established for ${peer.peer_client_id}.`
          : action === 'verify'
            ? `The recorded stream for ${peer.peer_client_id} matches its remote configuration and status.`
            : action === 'request-verification'
              ? `Verification was requested from ${peer.peer_client_id}. Poll later to confirm the signed SET arrived.`
              : action === 'delete'
                ? `The remote stream for ${peer.peer_client_id} was deleted and reconciled.`
                : applied
                  ? `One event from ${peer.peer_client_id} was applied and acknowledged.`
                  : `No user event was applied from ${peer.peer_client_id}. Check the verification timestamps for a stream control event.`;
        setMessage({ tone: 'success', text });
        toast.success('Upstream operation completed', text);
        refresh();
      },
      (error: unknown) => {
        const refusal = error instanceof Error ? error.message : 'The upstream operation was refused.';
        const text = `${refusal} ${operationGuidance(error)}`;
        setMessage({ tone: 'error', text });
        toast.error('Upstream operation refused', text);
        refresh();
      },
    ).finally(() => setBusyPeer(null));
  };

  return (
    <>
    <Panel
      id="ssf-upstream-peers"
      title="Upstream transmitters"
      description="Inspect configured senders and their subject policy, establish a poll stream, verify its configuration and delivery, or poll once. Inbound signed events must use EdDSA or ES256; an RS256-only transmitter cannot deliver to this receiver."
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
            { key: 'peer', header: 'Peer', sortBy: (peer) => peer.peer_client_id, cell: (peer) => <><code>{peer.peer_client_id}</code><FlowOrigin session={session} kind="stream" resource={peer.peer_client_id} /></> },
            { key: 'state', header: 'State', sortBy: (peer) => peer.state, cell: (peer) => (
              <>
                <Badge tone={peer.state === 'established' ? 'ok' : peer.state === 'pending_review' || peer.state === 'deletion_pending' ? 'warn' : 'neutral'}>
                  {peer.state === 'pending_review' ? 'Pending review' : peer.state === 'deletion_pending' ? 'Deletion pending' : peer.state === 'not_started' ? 'Not started' : 'Established'}
                </Badge>
                {stateGuidance(peer) !== null && <div className="muted">{stateGuidance(peer)}</div>}
              </>
            ) },
            { key: 'subject-policy', header: 'ALL-subject consent', cell: (peer) => peer.allow_all_subjects
              ? 'ALL allowed by operator'
              : 'ALL requires operator consent' },
            { key: 'audience', header: 'Expected SET audience', cell: (peer) => <code>{peer.expected_audience}</code> },
            { key: 'pending', header: 'Pending since', cell: (peer) => <Timestamp value={peer.pending_since ?? null} /> },
            { key: 'last_poll', header: 'Last poll', cell: (peer) => <Timestamp value={peer.last_polled_at ?? null} /> },
            { key: 'last_verified', header: 'Last signed verification', cell: (peer) => <Timestamp value={peer.last_verified_at ?? null} /> },
            { key: 'challenge_verified', header: 'Last challenge confirmed', cell: (peer) => <Timestamp value={peer.last_challenge_verified_at ?? null} /> },
            { key: 'actions', header: 'Actions', cell: (peer) => writable ? (
              <Actions>
                {peer.state === 'not_started' && <Button type="button" disabled={busyPeer !== null} onClick={() => operate(peer, 'setup')}>Set up</Button>}
                {peer.state === 'established' && <Button type="button" disabled={busyPeer !== null} onClick={() => operate(peer, 'poll')}>Poll once</Button>}
                {peer.state === 'established' && <Button type="button" disabled={busyPeer !== null} onClick={() => operate(peer, 'verify')}>Check stream</Button>}
                {peer.state === 'established' && <Button type="button" disabled={busyPeer !== null} onClick={() => operate(peer, 'request-verification')}>Request verification</Button>}
                {peer.state === 'established' && <Button type="button" variant="danger" disabled={busyPeer !== null} onClick={() => setDeletePeer(peer)}>Delete stream</Button>}
                {peer.state === 'deletion_pending' && <Button type="button" disabled={busyPeer !== null} onClick={() => operate(peer, 'delete')}>Retry deletion</Button>}
                {peer.state === 'pending_review' && <span className="muted">Review required</span>}
              </Actions>
            ) : <span className="muted">Read only</span> },
          ]}
        />
      )}
    </Panel>
    {deletePeer !== null && <ConfirmDialog
      title="Delete the upstream stream?"
      body={`This removes the poll stream at ${deletePeer.peer_client_id}. A new stream requires setup after deletion is confirmed.`}
      confirmLabel="Delete stream"
      busy={busyPeer !== null}
      onCancel={() => setDeletePeer(null)}
      onConfirm={() => { const peer = deletePeer; setDeletePeer(null); operate(peer, 'delete'); }}
    />}
    </>
  );
}
