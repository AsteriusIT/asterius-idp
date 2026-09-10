/**
 * The signing-key screen (`ast-f7m.7`).
 *
 * Every key this tenant holds, grouped by algorithm, with what an operator can
 * do to it: rotate, retire, change the rotation schedule, and read the JWK Set
 * a relying party will fetch.
 *
 * # Nothing here is a security control
 *
 * The buttons this screen hides or disables — no "retire" on the active key, no
 * rotate for a caller without the authority — are *usability*. The server
 * refuses all of it independently (`crates/admin-api/src/router.rs`,
 * `crates/admin-api/src/rbac.rs`), and this file being wrong would be a
 * confusing screen rather than an unauthorised change. The same rule the
 * navigation states, at the one place somebody might mistake a disabled button
 * for a guarantee.
 *
 * # No private key material can reach this file
 *
 * The API does not serve any: the port behind those routes returns public JWKs
 * and has no method that yields a signing key, and the rendering is an
 * allow-list of public JWK members (`crates/admin-api/src/keys.rs`). So there
 * is nothing here to be careful with, and the JWK Set below can be shown
 * verbatim.
 *
 * # No third-party anything
 *
 * The console runs under a strict CSP with `connect-src 'self'` (ADR-0009), so
 * every request is same-origin and relative, and the JWK Set is rendered by
 * `JSON.stringify` rather than by a syntax-highlighting library. A CDN here
 * would not be a slow page, it would be a CSP violation.
 */
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { mutate, read, type Session } from './api';

/** Where a key is in its life, mirroring `asterius_domain::keys::KeyState`. */
export type KeyState = 'pending' | 'active' | 'retiring' | 'retired';

/** One key, as `GET /keys` describes it. */
export interface KeyRow {
  readonly kid: string;
  readonly alg: string;
  readonly use: string;
  readonly state: KeyState;
  readonly published: boolean;
  readonly created_at: number;
  readonly public_jwk: Record<string, unknown>;
}

/** One algorithm's rotation policy, in whole seconds. */
export interface Schedule {
  readonly rotation_period_seconds: number;
  readonly propagation_period_seconds: number;
  readonly grace_period_seconds: number;
  readonly last_rotated_at: number | null;
}

/** One algorithm's keys and policy. */
export interface AlgorithmGroup {
  readonly alg: string;
  readonly keys: readonly KeyRow[];
  readonly schedule: Schedule | null;
}

/** What `GET /keys` answers. */
export interface Inventory {
  readonly algorithms: readonly AlgorithmGroup[];
}

/** What a rotation or a retirement reports. */
export interface RotationResult {
  readonly created_kid: string | null;
  readonly activated_kid: string | null;
  readonly superseded_kid: string | null;
  readonly retired_kids: readonly string[];
  readonly changed: boolean;
}

/** What the screen is doing. */
type Load =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly inventory: Inventory; readonly jwks: unknown }
  | { readonly kind: 'failed'; readonly message: string };

/**
 * A sentence describing what a rotation did.
 *
 * Assembled from the `kid` values the server reported rather than from what the
 * form asked for: an operator who asked for an immediate rotation and got a
 * staged one — because a key was already waiting — should read what happened.
 */
export function describe(result: RotationResult): string {
  if (!result.changed) {
    return 'Nothing changed: a key was already staged and waiting.';
  }
  const said: string[] = [];
  if (result.created_kid !== null) {
    said.push(`staged ${result.created_kid}`);
  }
  if (result.activated_kid !== null) {
    said.push(`${result.activated_kid} is now signing`);
  }
  if (result.superseded_kid !== null) {
    said.push(`${result.superseded_kid} stopped signing and stays published`);
  }
  if (result.retired_kids.length > 0) {
    said.push(`left the JWK Set: ${result.retired_kids.join(', ')}`);
  }
  return `${said.join('; ')}.`;
}

/** Seconds, as a person reads them. */
export function humanise(seconds: number): string {
  const units: readonly (readonly [number, string])[] = [
    [86_400, 'day'],
    [3_600, 'hour'],
    [60, 'minute'],
  ];
  for (const [size, name] of units) {
    if (seconds >= size && seconds % size === 0) {
      const count = seconds / size;
      return `${count} ${name}${count === 1 ? '' : 's'}`;
    }
  }
  return `${seconds} seconds`;
}

export function Keys({ session }: { session: Session }): JSX.Element {
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    Promise.all([read('keys'), read('keys/jwks')]).then(
      ([inventory, jwks]) => setLoad({ kind: 'ready', inventory: inventory as Inventory, jwks }),
      (error: unknown) =>
        setLoad({
          kind: 'failed',
          message: error instanceof Error ? error.message : 'the keys could not be read',
        }),
    );
  }, []);

  useEffect(refresh, [refresh]);

  /**
   * Runs one change, then re-reads.
   *
   * Always re-reads rather than patching the list in place: the server is the
   * only thing that knows what state the keys ended in, and a screen that
   * guessed would show an active key that is not the one signing.
   */
  const run = useCallback(
    (action: () => Promise<unknown>, describeResult: (value: unknown) => string) => {
      setBusy(true);
      setNotice(null);
      action().then(
        (value) => {
          setNotice(describeResult(value));
          setBusy(false);
          refresh();
        },
        (error: unknown) => {
          setNotice(error instanceof Error ? error.message : 'the change was refused');
          setBusy(false);
        },
      );
    },
    [refresh],
  );

  const rotate = (alg: string, immediately: boolean): void =>
    run(
      () => mutate('keys/rotate', 'POST', session, { alg, activate_immediately: immediately }),
      (value) => describe(value as RotationResult),
    );

  const retire = (kid: string): void =>
    run(
      () => mutate(`keys/${encodeURIComponent(kid)}/retire`, 'POST', session),
      (value) => describe(value as RotationResult),
    );

  if (load.kind === 'loading') {
    return (
      <>
        <h2>Signing keys</h2>
        <p>Reading the key set.</p>
      </>
    );
  }
  if (load.kind === 'failed') {
    return (
      <>
        <h2>Signing keys</h2>
        <p>{load.message}</p>
        <button type="button" onClick={refresh}>
          Try again
        </button>
      </>
    );
  }

  return (
    <>
      <h2>Signing keys</h2>
      {notice !== null && (
        <p role="status" aria-live="polite">
          {notice}
        </p>
      )}
      {load.inventory.algorithms.map((group) => (
        <section key={group.alg} aria-labelledby={`alg-${group.alg}`}>
          <h3 id={`alg-${group.alg}`}>{group.alg}</h3>
          {group.schedule !== null && <SchedulePanel schedule={group.schedule} />}
          <KeyTable group={group} busy={busy} onRetire={retire} />
          <p>
            <button type="button" disabled={busy} onClick={() => rotate(group.alg, false)}>
              Rotate {group.alg}
            </button>{' '}
            <button type="button" disabled={busy} onClick={() => rotate(group.alg, true)}>
              Rotate and sign immediately
            </button>
          </p>
          <p className="muted">
            Rotating stages a new key and publishes it. It starts signing after the propagation
            period, so a client holding a cached JWK Set has time to fetch it. Signing immediately
            skips that wait — for a key you no longer trust.
          </p>
        </section>
      ))}
      <section aria-labelledby="jwks">
        <h3 id="jwks">Published JWK Set</h3>
        <p className="muted">
          What a relying party fetches from this tenant right now. Public halves only.
        </p>
        <pre>{JSON.stringify(load.jwks, null, 2)}</pre>
      </section>
    </>
  );
}

function SchedulePanel({ schedule }: { schedule: Schedule }): JSX.Element {
  return (
    <dl>
      <dt>Rotates every</dt>
      <dd>{humanise(schedule.rotation_period_seconds)}</dd>
      <dt>Published before signing</dt>
      <dd>{humanise(schedule.propagation_period_seconds)}</dd>
      <dt>Published after signing</dt>
      <dd>{humanise(schedule.grace_period_seconds)}</dd>
      <dt>Last rotated</dt>
      <dd>
        {schedule.last_rotated_at === null
          ? 'never'
          : new Date(schedule.last_rotated_at * 1000).toISOString()}
      </dd>
    </dl>
  );
}

function KeyTable({
  group,
  busy,
  onRetire,
}: {
  group: AlgorithmGroup;
  busy: boolean;
  onRetire: (kid: string) => void;
}): JSX.Element {
  if (group.keys.length === 0) {
    return <p>No {group.alg} key. A client registered for {group.alg} has nothing to verify.</p>;
  }

  return (
    <table>
      <thead>
        <tr>
          <th scope="col">Key ID</th>
          <th scope="col">State</th>
          <th scope="col">In the JWK Set</th>
          <th scope="col">Created</th>
          <th scope="col">
            <span className="visually-hidden">Actions</span>
          </th>
        </tr>
      </thead>
      <tbody>
        {group.keys.map((key) => (
          <tr key={key.kid}>
            <td>
              <code>{key.kid}</code>
            </td>
            <td>{key.state}</td>
            <td>{key.published ? 'yes' : 'no'}</td>
            <td>{new Date(key.created_at * 1000).toISOString()}</td>
            <td>
              {/*
                The active key has no retire button, and the server refuses one
                anyway with a 409 naming rotation as the way to replace it. The
                two agree because they are two statements of one rule, not
                because this file is trusted.
              */}
              {key.state === 'active' || key.state === 'retired' ? null : (
                <button type="button" disabled={busy} onClick={() => onRetire(key.kid)}>
                  Retire
                </button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
