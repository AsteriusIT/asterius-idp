/** Tenant SAML IdP signing material. The private key never enters React state. */
import { useCallback, useEffect, useRef, useState } from 'react';
import type { FormEvent, JSX } from 'react';
import { ApiError, mutate, read, type Session } from './api';
import { toast } from './components/ui/toast';
import { Badge, Button, LoadFailure, Message, Panel, Screen, Skeleton, Timestamp } from './ui';

interface IdpKeySummary {
  readonly state: 'pending' | 'active' | 'retiring' | 'retired';
  readonly certificate_sha256: string;
  readonly certificate_der_base64: string;
  readonly created_at: string;
}

interface Inventory {
  readonly keys: readonly IdpKeySummary[];
}

type Load =
  | { readonly kind: 'loading' }
  | { readonly kind: 'empty' }
  | { readonly kind: 'ready'; readonly inventory: Inventory }
  | { readonly kind: 'failed'; readonly message: string };

const KEY_PATH = 'saml/idp-key';
const MIN_DER_BYTES = 256;
const MAX_DER_BYTES = 16_384;

/** Base64 for a bounded DER file, without keeping its bytes in component state. */
async function derBase64(file: File): Promise<string> {
  if (file.size < MIN_DER_BYTES || file.size > MAX_DER_BYTES) {
    throw new Error('Each DER file must be between 256 bytes and 16 KB.');
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  try {
    return btoa(String.fromCharCode(...bytes));
  } finally {
    bytes.fill(0);
  }
}

export function SamlIdpKey({ session }: Readonly<{ session: Session }>): JSX.Element {
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: 'success' | 'error'; text: string } | null>(null);
  const certificateInput = useRef<HTMLInputElement>(null);
  const privateKeyInput = useRef<HTMLInputElement>(null);
  const canWrite = session.scopes.includes('admin.saml:write');
  const keys = load.kind === 'ready' ? load.inventory.keys : [];
  const hasActive = keys.some((key) => key.state === 'active');
  const canImport = canWrite && (load.kind === 'empty' ||
    (load.kind === 'ready' && !keys.some((key) => key.state === 'pending' || key.state === 'retiring')));

  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    read(KEY_PATH).then(
      (value) => {
        const inventory = value as Inventory;
        setLoad(inventory.keys.length === 0 ? { kind: 'empty' } : { kind: 'ready', inventory });
      },
      (error: unknown) => {
        if (error instanceof ApiError && error.status === 404) {
          setLoad({ kind: 'empty' });
        } else {
          setLoad({
            kind: 'failed',
            message: error instanceof Error ? error.message : 'SAML IdP key could not be read.',
          });
        }
      },
    );
  }, []);

  useEffect(refresh, [refresh]);

  const provision = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    const certificate = certificateInput.current?.files?.[0];
    const privateKey = privateKeyInput.current?.files?.[0];
    if (!certificate || !privateKey) {
      setMessage({ tone: 'error', text: 'Select a DER certificate and its matching PKCS#8 private key.' });
      return;
    }
    // File inputs are the only browser-held selection; clear them as soon as
    // the local File handles have been captured, before the network request.
    if (certificateInput.current) certificateInput.current.value = '';
    if (privateKeyInput.current) privateKeyInput.current.value = '';
    setBusy(true);
    setMessage(null);
    try {
      const certificate_der_base64 = await derBase64(certificate);
      const private_key_pkcs8_der_base64 = await derBase64(privateKey);
      // The key and its base64 form are local to this submission. Do not put
      // either in React state, logs, toast text, or a persistent browser store.
      const result = await mutate(KEY_PATH, 'PUT', session, {
        certificate_der_base64,
        private_key_pkcs8_der_base64,
      });
      setLoad({ kind: 'ready', inventory: result as Inventory });
      setMessage({ tone: 'success', text: hasActive ? 'A successor key was staged.' : 'The initial SAML IdP signing key was imported.' });
      toast.success('SAML key imported', 'The public certificate is ready for inspection.');
    } catch (error: unknown) {
      const text = error instanceof Error ? error.message : 'The SAML IdP key import was refused.';
      setMessage({ tone: 'error', text });
      toast.error('SAML key unchanged', text);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Screen title="SAML identity provider" description={`Signing material for ${session.workspace}.`}>
      <Message tone="info">SAML browser SSO is not enabled yet. Importing a key does not enable sign-in.</Message>
      {message !== null && <Message tone={message.tone}>{message.text}</Message>}
      <Panel title="IdP signing certificates" description="Public certificate state for this tenant. Private keys are never returned by the API.">
        {load.kind === 'loading' && <Skeleton rows={3} label="Reading SAML IdP key." />}
        {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
        {load.kind === 'empty' && <p className="muted">No SAML IdP key is provisioned for this tenant.</p>}
        {load.kind === 'ready' && load.inventory.keys.map((key) => (
          <dl className="stats" key={key.certificate_sha256}>
            <div><dt>State</dt><dd><Badge tone={key.state === 'active' ? 'ok' : key.state === 'retired' ? 'neutral' : 'warn'}>{key.state}</Badge></dd></div>
            <div><dt>Certificate SHA-256</dt><dd><code className="break-all">{key.certificate_sha256}</code></dd></div>
            <div><dt>Created</dt><dd><Timestamp value={key.created_at} /></dd></div>
          </dl>
        ))}
      </Panel>
      {canImport && (
        <Panel
          title={hasActive ? 'Stage successor signing key' : 'Import initial signing key'}
          description="Import a matching X.509 certificate and unencrypted private PKCS#8 key, both as DER files. Successor activation and retirement use separate admin operations."
        >
          <form className="flex flex-col gap-3" onSubmit={(event) => { void provision(event); }}>
            <label className="flex flex-col gap-1" htmlFor="saml-idp-certificate">
              X.509 certificate (DER)
              <input id="saml-idp-certificate" ref={certificateInput} type="file" required disabled={busy} autoComplete="off" />
            </label>
            <label className="flex flex-col gap-1" htmlFor="saml-idp-private-key">
              Private key (PKCS#8 DER)
              <input id="saml-idp-private-key" ref={privateKeyInput} type="file" required disabled={busy} autoComplete="off" />
            </label>
            <p className="muted">Choose files from a trusted operator workstation. This form clears both selections after submission and does not retain key material in console state.</p>
            <Button type="submit" disabled={busy}>{busy ? 'Importing…' : hasActive ? 'Stage successor' : 'Import IdP key'}</Button>
          </form>
        </Panel>
      )}
    </Screen>
  );
}
