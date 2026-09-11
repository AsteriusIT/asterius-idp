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
    (action: () => Promise<unknown>, said: string) => {
      setBusy(true);
      setNotice(null);
      setRefusal(null);
      action().then(
        () => {
          setNotice(said);
          setBusy(false);
          refresh();
        },
        (error: unknown) => {
          setRefusal(error instanceof Error ? error.message : 'the change was refused');
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
    );

  const retry = (letter: DeadLetterRow): void =>
    run(
      () => mutate(`outbox/dead-letters/${letter.id}/retry`, 'POST', session),
      `Delivery ${letter.id} is back on the schedule.`,
    );

  const drop = (letter: DeadLetterRow): void =>
    run(
      () => mutate(`outbox/dead-letters/${letter.id}`, 'DELETE', session),
      `Delivery ${letter.id} was dropped; the audit trail keeps its record.`,
    );

  if (load.kind === 'loading') {
    return (
      <>
        <h2>Shared signals</h2>
        <p>Reading the streams.</p>
      </>
    );
  }
  if (load.kind === 'failed') {
    return (
      <>
        <h2>Shared signals</h2>
        <p role="alert" className="refusal">
          {load.message}
        </p>
        <button type="button" onClick={refresh}>
          Try again
        </button>
      </>
    );
  }

  return (
    <>
      <h2>Shared signals</h2>
      <p className="muted">
        Every receiver that has arranged to be told about <strong>{session.tenant}</strong>
        &apos;s users, and how each stream is doing. A paused stream keeps queueing events and
        delivers none of them until it is re-enabled.
      </p>
      {notice !== null && (
        <p role="status" aria-live="polite">
          {notice}
        </p>
      )}
      {refusal !== null && (
        <p role="alert" className="refusal">
          {refusal}
        </p>
      )}

      <section aria-labelledby="ssf-streams">
        <h3 id="ssf-streams">Streams</h3>
        <StreamTable
          streams={load.streams}
          busy={busy}
          mayWrite={mayWrite(session, 'admin.ssf:write')}
          onStatus={setStatus}
          onVerify={verify}
        />
      </section>

      {mayReadLetters && (
        <section aria-labelledby="ssf-dead-letters">
          <h3 id="ssf-dead-letters">Dead letters</h3>
          <p className="muted">
            Deliveries the outbox gave up on, newest first. A retry gives the row a fresh attempt
            budget; a drop removes it and leaves only its audit record. Both apply to shared-signal
            deliveries only.
          </p>
          <DeadLetterTable
            letters={load.letters}
            busy={busy}
            mayWrite={mayWrite(session, 'admin.outbox:write')}
            onRetry={retry}
            onDrop={drop}
          />
        </section>
      )}
    </>
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
  if (streams.length === 0) {
    return <p>No stream. No receiver has asked to be told about this tenant&apos;s users.</p>;
  }
  return (
    <table>
      <thead>
        <tr>
          <th scope="col">Stream</th>
          <th scope="col">Receiver</th>
          <th scope="col">Delivery</th>
          <th scope="col">Events</th>
          <th scope="col">Status</th>
          <th scope="col">Delivered</th>
          <th scope="col">Failed</th>
          <th scope="col">Queued</th>
          {mayWrite && (
            <th scope="col">
              <span className="visually-hidden">Actions</span>
            </th>
          )}
        </tr>
      </thead>
      <tbody>
        {streams.map((stream) => (
          <StreamLine
            key={stream.stream_id}
            stream={stream}
            busy={busy}
            mayWrite={mayWrite}
            onStatus={onStatus}
            onVerify={onVerify}
          />
        ))}
      </tbody>
    </table>
  );
}

function StreamLine({
  stream,
  busy,
  mayWrite,
  onStatus,
  onVerify,
}: {
  stream: StreamRow;
  busy: boolean;
  mayWrite: boolean;
  onStatus: (stream: StreamRow, status: 'enabled' | 'paused', reason: string) => void;
  onVerify: (stream: StreamRow, state: string) => void;
}): JSX.Element {
  const [reason, setReason] = useState('');
  const [state, setState] = useState('');
  const id = stream.stream_id;
  return (
    <tr>
      <td>
        <code>{stream.stream_id}</code>
        {stream.description !== null && <div className="muted">{stream.description}</div>}
      </td>
      <td>
        <code>{stream.receiver}</code>
      </td>
      <td>{describeDelivery(stream.delivery_method)}</td>
      <td>{stream.events_requested.map(shortEvent).join(', ') || 'none'}</td>
      <td>
        <strong>{stream.status}</strong>
        {stream.reason !== null && <div className="muted">{stream.reason}</div>}
      </td>
      <td>{stream.delivered}</td>
      <td>{stream.failed}</td>
      <td>{stream.queue_depth}</td>
      {mayWrite && (
        <td>
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
              <button type="submit" disabled={busy}>
                Pause
              </button>
            </form>
          ) : stream.status === 'paused' ? (
            <button type="button" disabled={busy} onClick={() => onStatus(stream, 'enabled', '')}>
              Enable
            </button>
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
            <button type="submit" disabled={busy}>
              Verify
            </button>
          </form>
        </td>
      )}
    </tr>
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
  if (letters.length === 0) {
    return <p>No dead letter. Every delivery the outbox took on has been delivered or is still owed.</p>;
  }
  return (
    <table>
      <thead>
        <tr>
          <th scope="col">Row</th>
          <th scope="col">Kind</th>
          <th scope="col">Attempts</th>
          <th scope="col">Queued</th>
          <th scope="col">Last attempt</th>
          <th scope="col">Last error</th>
          {mayWrite && (
            <th scope="col">
              <span className="visually-hidden">Actions</span>
            </th>
          )}
        </tr>
      </thead>
      <tbody>
        {letters.map((letter) => (
          <tr key={letter.id}>
            <td>{letter.id}</td>
            <td>
              <code>{letter.kind}</code>
            </td>
            <td>{letter.attempts}</td>
            <td>{letter.created_at}</td>
            <td>{letter.last_attempt_at ?? 'never'}</td>
            <td>{letter.last_error ?? ''}</td>
            {mayWrite && (
              <td>
                {/*
                  The server says which rows its two routes accept, and the
                  buttons follow it: a row of another family answers 409, and a
                  button that offered it would be a button that always fails.
                */}
                {letter.retryable ? (
                  <>
                    <button type="button" disabled={busy} onClick={() => onRetry(letter)}>
                      Retry
                    </button>{' '}
                    <button type="button" disabled={busy} onClick={() => onDrop(letter)}>
                      Drop
                    </button>
                  </>
                ) : (
                  <span className="muted">not retryable from here</span>
                )}
              </td>
            )}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
