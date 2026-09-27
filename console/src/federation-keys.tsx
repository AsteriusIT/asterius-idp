/** Tenant Federation signing key lifecycle, backed by the admin API. */
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { ApiError, mutate, read, type Session } from './api';
import { toast } from './components/ui/toast';
import {
  Badge,
  Button,
  DataTable,
  LoadFailure,
  Message,
  Panel,
  Screen,
  Skeleton,
  Timestamp,
  Truncate,
} from './ui';

interface FederationKey {
  readonly kid: string;
  readonly state: 'pending' | 'active' | 'retiring' | 'retired';
  readonly public_jwk: Record<string, unknown>;
  readonly created_at: number;
  readonly activated_at: number | null;
  readonly retired_at: number | null;
}

interface Inventory {
  readonly rotation_period_seconds: number;
  readonly keys: readonly FederationKey[];
}

interface Rotation {
  readonly staged_kid: string;
  readonly propagation_seconds: number;
}

type Load =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly inventory: Inventory }
  | { readonly kind: 'disabled' }
  | { readonly kind: 'failed'; readonly message: string };

function stateTone(state: FederationKey['state']): 'ok' | 'warn' | 'neutral' {
  if (state === 'active') return 'ok';
  if (state === 'pending' || state === 'retiring') return 'warn';
  return 'neutral';
}

/** The admin API serves public key metadata only; no private key reaches this screen. */
export function FederationKeys({ session }: Readonly<{ session: Session }>): JSX.Element {
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const canRotate = session.scopes.includes('admin.keys:write');

  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    read('federation/keys').then(
      (value) => setLoad({ kind: 'ready', inventory: value as Inventory }),
      (error: unknown) => {
        if (error instanceof ApiError && error.status === 404) {
          setLoad({ kind: 'disabled' });
        } else {
          setLoad({
            kind: 'failed',
            message: error instanceof Error ? error.message : 'Federation keys could not be read',
          });
        }
      },
    );
  }, []);

  useEffect(refresh, [refresh]);

  const rotate = (): void => {
    setBusy(true);
    setNotice(null);
    setRefusal(null);
    mutate('federation/keys/rotate', 'POST', session).then(
      (value) => {
        const result = value as Rotation;
        const message = `Key ${result.staged_kid} is staged. It will start signing after at least ${Math.ceil(result.propagation_seconds / 60)} minutes of propagation.`;
        setNotice(message);
        toast.success('Federation key staged', message);
        setBusy(false);
        refresh();
      },
      (error: unknown) => {
        const message = error instanceof Error ? error.message : 'The rotation was refused';
        setRefusal(message);
        toast.error('No key was staged', message);
        setBusy(false);
      },
    );
  };

  const ready = load.kind === 'ready' ? load.inventory : null;
  const pending = ready?.keys.some((key) => key.state === 'pending') ?? false;
  return (
    <Screen
      title="Federation keys"
      description="Inspect this tenant’s dedicated Federation signing keys and stage a successor."
    >
      {notice !== null && <Message tone="success">{notice}</Message>}
      {refusal !== null && <Message tone="error">{refusal}</Message>}
      <Panel
        title="Federation signing keys"
        description="These keys sign the tenant’s federation configuration, separately from sign-in tokens."
        actions={
          ready !== null && canRotate ? (
            <Button onClick={rotate} disabled={busy || pending}>
              {busy ? 'Staging…' : 'Stage successor'}
            </Button>
          ) : undefined
        }
      >
        {load.kind === 'loading' && <Skeleton rows={4} label="Reading Federation keys." />}
        {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
        {load.kind === 'disabled' && (
          <p className="muted">Federation is not enabled for this tenant.</p>
        )}
        {ready !== null && (
          <>
            {pending && <p className="muted">A successor is already staged and awaiting automatic promotion.</p>}
            <DataTable
              caption="Federation signing keys"
              rows={ready.keys}
              rowKey={(key) => key.kid}
              columns={[
                { key: 'kid', header: 'Key ID', cell: (key) => <Truncate text={key.kid} /> },
                { key: 'state', header: 'State', cell: (key) => <Badge tone={stateTone(key.state)}>{key.state}</Badge> },
                { key: 'created', header: 'Created', cell: (key) => <Timestamp value={key.created_at} /> },
                { key: 'activated', header: 'Activated', cell: (key) => <Timestamp value={key.activated_at} /> },
                { key: 'retired', header: 'Retired', cell: (key) => <Timestamp value={key.retired_at} /> },
              ]}
            />
            <p className="muted">
              Successors are promoted after a six minute propagation period; old public keys stay published during the overlap. Automatic rotation is scheduled every {Math.round(ready.rotation_period_seconds / 86400)} days.
            </p>
          </>
        )}
      </Panel>
      <Panel title="Trust anchors" description="Federation peers are accepted only through operator-pinned roots.">
        <p className="muted">
          Trust anchors and authority hints are deployment configuration. Review the tenant’s <code>federation_trust_anchors</code> and <code>federation_authority_hints</code> settings to change them; the admin API does not edit these values.
        </p>
      </Panel>
    </Screen>
  );
}
