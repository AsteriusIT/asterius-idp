/**
 * The Shared Signals screen (`ast-f7m.8`).
 *
 * Two tables. The streams every receiver has configured against this tenant,
 * with SSF 1.0 §8.1.2's status, the reason the server (or an operator) gave
 * for it, the delivery counters and the SETs still owed; and the deliveries
 * the outbox has given up on. Three things an operator can do: pause or
 * re-enable a stream, send it a verification event (§8.1.4), and put an
 * abandoned SET back on the schedule or drop it.
 *
 * # Nothing here is a security control
 *
 * The buttons this screen hides — no retry on a row the server marks as not
 * retryable, no mutation for a caller without the write scope — are
 * usability. The server refuses all of it independently
 * (`crates/admin-api/src/router.rs`, `crates/admin-api/src/rbac.rs`), records
 * every change in the audit trail under the operator's name, and this file
 * being wrong would be a confusing screen rather than an unauthorised change.
 *
 * # What is not on this screen
 *
 * A receiver's push endpoint and its credential. The API does not send them
 * (`crates/admin-api/src/ssf.rs`), so there is nothing here to be careful
 * with; the receiver's `client_id` and the delivery method are what "is this
 * receiver taking anything" needs.
 */
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { mutate, read, type Session } from './api';
import { toast } from './components/ui/toast';
import {
  Actions,
  Badge,
  Button,
  DataTable,
  EmptyState,
  LoadFailure,
  Message,
  Panel,
  Screen,
  Skeleton,
} from './ui';

/** §8.1.2's three states. Only the first two are written from here. */
export type StreamStatus = 'enabled' | 'paused' | 'disabled';

/** One stream, as `GET /ssf/streams` renders it. */
export interface StreamRow {
  readonly stream_id: string;
  readonly receiver: string;
  readonly delivery_method: string;
  readonly events_requested: readonly string[];
  readonly description: string | null;
  readonly created_at: string;
  readonly status: StreamStatus;
  readonly reason: string | null;
  readonly status_changed_at: string | null;
  readonly delivered: number;
  readonly failed: number;
  readonly queue_depth: number;
}

/** One abandoned delivery, as `GET /outbox/dead-letters` renders it. */
export interface DeadLetterRow {
  readonly id: number;
  readonly kind: string;
  readonly family: string;
  readonly attempts: number;
  readonly created_at: string;
  readonly last_attempt_at?: string;
  readonly last_error?: string;
  /** Whether the server accepts a retry or a drop for this row. */
  readonly retryable: boolean;
}

interface Streams {
  readonly items: readonly StreamRow[];
}

interface DeadLetters {
  readonly items: readonly DeadLetterRow[];
}

type Load =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly streams: readonly StreamRow[]; readonly letters: readonly DeadLetterRow[] }
  | { readonly kind: 'failed'; readonly message: string };

/** The delivery method, as a person reads it. */
export function describeDelivery(method: string): string {
  if (method === 'urn:ietf:rfc:8935') {
    return 'push';
  }
  if (method === 'urn:ietf:rfc:8936') {
    return 'poll';
  }
  return method;
}

/** The last segment of an event type URI: `session-revoked` for CAEP's. */
export function shortEvent(uri: string): string {
  const tail = uri.split('/').pop();
  return tail === undefined || tail === '' ? uri : tail;
}

/** Whether the session may change streams and dead letters. */
export function mayWrite(session: Session, scope: 'admin.ssf:write' | 'admin.outbox:write'): boolean {
  return session.scopes.includes(scope);
}

export function SharedSignals({ session }: { session: Session }): JSX.Element {
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [notice, setNotice] = useState<string | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const mayReadLetters = session.scopes.includes('admin.outbox:read');

  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    const letters: Promise<unknown> = mayReadLetters
      ? read('outbox/dead-letters')
      : Promise.resolve({ items: [] });
    Promise.all([read('ssf/streams'), letters]).then(
      ([streams, dead]) =>
        setLoad({
          kind: 'ready',
          streams: (streams as Streams).items,
          letters: (dead as DeadLetters).items,
        }),
      (error: unknown) =>
        setLoad({
          kind: 'failed',
          message: error instanceof Error ? error.message : 'the streams could not be read',
        }),
    );
  }, [mayReadLetters]);

  useEffect(refresh, [refresh]);

  /**
   * Runs one change, then re-reads.
   *
   * Always re-reads rather than patching the tables in place: the server is
   * the only thing that knows what a stream's counters and queue depth are
   * after a retry, and a screen that guessed would show a SET as owed that
   * the worker has already delivered.
   */
  const run = useCallback(
    (action: () => Promise<unknown>, said: string, announced: string) => {
      setBusy(true);
      setNotice(null);
      setRefusal(null);
      action().then(
        () => {
          setNotice(said);
          // The toast announces, the `Message` above records (`ast-f9j5` (3)):
          // a stream this operator paused four acts ago is still written down
          // where they can read it, and the act they just took is said where
          // they are looking — which, on a screen of two tables, is a row and
          // not the top of the page.
          toast.success(announced, said);
          setBusy(false);
          refresh();
        },
        (error: unknown) => {
          const message = error instanceof Error ? error.message : 'the change was refused';
          setRefusal(message);
          toast.error('Nothing changed', message);
          setBusy(false);
        },
      );
    },
    [refresh],
  );

  const setStatus = (stream: StreamRow, status: 'enabled' | 'paused', reason: string): void =>
    run(
      () =>
        mutate(`ssf/streams/${encodeURIComponent(stream.stream_id)}/status`, 'PUT', session, {
          status,
          ...(status === 'paused' && reason !== '' ? { reason } : {}),
        }),
      `${stream.stream_id} is now ${status}.`,
      status === 'paused' ? 'Stream paused' : 'Stream enabled',
    );

  const verify = (stream: StreamRow, state: string): void =>
    run(
      () =>
        mutate(
          `ssf/streams/${encodeURIComponent(stream.stream_id)}/verification`,
          'POST',
          session,
          state === '' ? {} : { state },
        ),
      `A verification event was queued on ${stream.stream_id}.`,
      'Verification queued',
    );

  const retry = (letter: DeadLetterRow): void =>
    run(
      () => mutate(`outbox/dead-letters/${letter.id}/retry`, 'POST', session),
      `Delivery ${letter.id} is back on the schedule.`,
      'Delivery retried',
    );

  const drop = (letter: DeadLetterRow): void =>
    run(
      () => mutate(`outbox/dead-letters/${letter.id}`, 'DELETE', session),
      `Delivery ${letter.id} was dropped; the audit trail keeps its record.`,
      'Delivery dropped',
    );

  if (load.kind === 'loading') {
    return (
      <Screen title="Shared signals">
        <Panel title="Reading">
          <Skeleton rows={4} label="Reading the streams." />
        </Panel>
      </Screen>
    );
  }
  if (load.kind === 'failed') {
    return (
      <Screen title="Shared signals">
        <Panel title="The streams could not be read">
          <LoadFailure message={load.message} onRetry={refresh} />
        </Panel>
      </Screen>
    );
  }

  return (
    <Screen
      title="Shared signals"
      description={
        <>
          Every receiver that has arranged to be told about <strong>{session.tenant}</strong>
          &apos;s users, and how each stream is doing. A paused stream keeps queueing events and
          delivers none of them until it is re-enabled.
        </>
      }
    >
      {notice !== null && <Message tone="success">{notice}</Message>}
      {refusal !== null && <Message tone="error">{refusal}</Message>}

      <Panel id="ssf-streams" title="Streams">
        <StreamTable
          streams={load.streams}
          busy={busy}
          mayWrite={mayWrite(session, 'admin.ssf:write')}
          onStatus={setStatus}
          onVerify={verify}
        />
      </Panel>

      {mayReadLetters && (
        <Panel
          id="ssf-dead-letters"
          title="Dead letters"
          description="Deliveries the outbox gave up on, newest first. A retry gives the row a fresh attempt budget; a drop removes it and leaves only its audit record. Both apply to shared-signal deliveries only."
        >
          <DeadLetterTable
            letters={load.letters}
            busy={busy}
            mayWrite={mayWrite(session, 'admin.outbox:write')}
            onRetry={retry}
            onDrop={drop}
          />
        </Panel>
      )}
    </Screen>
  );
}

function StreamTable({
  streams,
  busy,
  mayWrite,
  onStatus,
  onVerify,
}: {
  streams: readonly StreamRow[];
  busy: boolean;
  mayWrite: boolean;
  onStatus: (stream: StreamRow, status: 'enabled' | 'paused', reason: string) => void;
  onVerify: (stream: StreamRow, state: string) => void;
}): JSX.Element {
  return (
    <DataTable
      rows={streams}
      rowKey={(stream) => stream.stream_id}
      empty={
        <EmptyState
          title="No stream."
          body="No receiver has asked to be told about this tenant&apos;s users."
        />
      }
      // A tenant with twenty receivers is a table nobody reads top to bottom,
      // and the question asked of this screen is about *one* of them
      // (`ast-f9j5` (1)). The status is searched too, so `paused` lists every
      // stream that is delivering nothing.
      search={{
        of: (stream) =>
          `${stream.stream_id} ${stream.receiver} ${stream.status} ${stream.description ?? ''} ${stream.events_requested.map(shortEvent).join(' ')}`,
        placeholder: 'Filter by stream, receiver or status…',
        label: 'Filter these streams by stream, receiver or status',
      }}
      columns={[
        {
          key: 'stream',
          header: 'Stream',
          sortBy: (stream) => stream.stream_id,
          cell: (stream) => (
            <>
              <code>{stream.stream_id}</code>
              {stream.description !== null && <div className="muted">{stream.description}</div>}
            </>
          ),
        },
        {
          key: 'receiver',
          header: 'Receiver',
          sortBy: (stream) => stream.receiver,
          cell: (stream) => <code>{stream.receiver}</code>,
        },
        {
          key: 'delivery',
          header: 'Delivery',
          sortBy: (stream) => describeDelivery(stream.delivery_method),
          cell: (stream) => describeDelivery(stream.delivery_method),
        },
        {
          key: 'events',
          header: 'Events',
          cell: (stream) => stream.events_requested.map(shortEvent).join(', ') || 'none',
        },
        {
          key: 'status',
          header: 'Status',
          sortBy: (stream) => stream.status,
          cell: (stream) => (
            <>
              <Badge tone={stream.status === 'enabled' ? 'ok' : 'warn'}>{stream.status}</Badge>
              {stream.reason !== null && <div className="muted">{stream.reason}</div>}
            </>
          ),
        },
        {
          key: 'delivered',
          header: 'Delivered',
          numeric: true,
          sortBy: (stream) => stream.delivered,
          cell: (stream) => stream.delivered,
        },
        {
          key: 'failed',
          header: 'Failed',
          numeric: true,
          sortBy: (stream) => stream.failed,
          cell: (stream) => stream.failed,
        },
        {
          key: 'queued',
          header: 'Queued',
          numeric: true,
          sortBy: (stream) => stream.queue_depth,
          cell: (stream) => stream.queue_depth,
        },
        ...(mayWrite
          ? [
              {
                key: 'actions',
                header: '',
                actions: true,
                cell: (stream: StreamRow) => (
                  <StreamControls
                    stream={stream}
                    busy={busy}
                    onStatus={onStatus}
                    onVerify={onVerify}
                  />
                ),
              },
            ]
          : []),
      ]}
    />
  );
}

/**
 * The two forms one stream carries, each with its own box.
 *
 * A component rather than markup inside the cell, because the reason and the
 * verification state are state *of this row*: a filter that hides a row and
 * brings it back must not carry what was typed in it to another receiver's.
 */
function StreamControls({
  stream,
  busy,
  onStatus,
  onVerify,
}: {
  stream: StreamRow;
  busy: boolean;
  onStatus: (stream: StreamRow, status: 'enabled' | 'paused', reason: string) => void;
  onVerify: (stream: StreamRow, state: string) => void;
}): JSX.Element {
  const [reason, setReason] = useState('');
  const [state, setState] = useState('');
  const id = stream.stream_id;
  return (
    <>
      {stream.status === 'enabled' ? (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            onStatus(stream, 'paused', reason);
          }}
        >
          <label htmlFor={`reason-${id}`} className="visually-hidden">
            Reason for pausing {id}
          </label>
          <input
            id={`reason-${id}`}
            type="text"
            value={reason}
            placeholder="reason (optional)"
            maxLength={256}
            onChange={(event) => setReason(event.target.value)}
          />{' '}
          <Button type="submit" small disabled={busy}>
            Pause
          </Button>
        </form>
      ) : stream.status === 'paused' ? (
        <Button small disabled={busy} onClick={() => onStatus(stream, 'enabled', '')}>
          Enable
        </Button>
      ) : null}
      <form
        onSubmit={(event) => {
          event.preventDefault();
          onVerify(stream, state);
        }}
      >
        <label htmlFor={`state-${id}`} className="visually-hidden">
          Verification state for {id}
        </label>
        <input
          id={`state-${id}`}
          type="text"
          value={state}
          placeholder="state (optional)"
          maxLength={256}
          onChange={(event) => setState(event.target.value)}
        />{' '}
        <Button type="submit" small disabled={busy}>
          Verify
        </Button>
      </form>
    </>
  );
}

function DeadLetterTable({
  letters,
  busy,
  mayWrite,
  onRetry,
  onDrop,
}: {
  letters: readonly DeadLetterRow[];
  busy: boolean;
  mayWrite: boolean;
  onRetry: (letter: DeadLetterRow) => void;
  onDrop: (letter: DeadLetterRow) => void;
}): JSX.Element {
  return (
    <DataTable
      rows={letters}
      rowKey={(letter) => String(letter.id)}
      empty={
        <EmptyState
          title="No dead letter."
          body="Every delivery the outbox took on has been delivered or is still owed."
        />
      }
      // The error is searched as well as the kind: "how many of these are the
      // same failure" is the question a dead-letter table is opened with, and
      // the count beside the box answers it (`ast-f9j5` (1)).
      search={{
        of: (letter) => `${letter.id} ${letter.kind} ${letter.last_error ?? ''}`,
        placeholder: 'Filter by row, kind or error…',
        label: 'Filter these dead letters by row, kind or error',
      }}
      columns={[
        {
          key: 'id',
          header: 'Row',
          numeric: true,
          sortBy: (letter) => letter.id,
          cell: (letter) => letter.id,
        },
        {
          key: 'kind',
          header: 'Kind',
          sortBy: (letter) => letter.kind,
          cell: (letter) => <code>{letter.kind}</code>,
        },
        {
          key: 'attempts',
          header: 'Attempts',
          numeric: true,
          sortBy: (letter) => letter.attempts,
          cell: (letter) => letter.attempts,
        },
        {
          key: 'queued',
          header: 'Queued',
          sortBy: (letter) => letter.created_at,
          cell: (letter) => letter.created_at,
        },
        {
          key: 'last-attempt',
          header: 'Last attempt',
          sortBy: (letter) => letter.last_attempt_at ?? '',
          cell: (letter) => letter.last_attempt_at ?? 'never',
        },
        { key: 'last-error', header: 'Last error', cell: (letter) => letter.last_error ?? '' },
        ...(mayWrite
          ? [
              {
                key: 'actions',
                header: '',
                actions: true,
                /*
                  The server says which rows its two routes accept, and the
                  buttons follow it: a row of another family answers 409, and a
                  button that offered it would be a button that always fails.
                */
                cell: (letter: DeadLetterRow) =>
                  letter.retryable ? (
                    <Actions>
                      <Button small disabled={busy} onClick={() => onRetry(letter)}>
                        Retry <span className="visually-hidden">delivery {letter.id}</span>
                      </Button>
                      <Button small disabled={busy} onClick={() => onDrop(letter)}>
                        Drop <span className="visually-hidden">delivery {letter.id}</span>
                      </Button>
                    </Actions>
                  ) : (
                    <span className="muted">not retryable from here</span>
                  ),
              },
            ]
          : []),
      ]}
    />
  );
}
