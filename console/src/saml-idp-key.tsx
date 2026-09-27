/** Tenant SAML IdP signing material. The private key never enters React state. */
import { useCallback, useEffect, useRef, useState } from 'react';
import type { FormEvent, JSX } from 'react';
import { ApiError, mutate, read, type Session } from './api';
import { toast } from './components/ui/toast';
import { Badge, Button, ConfirmDialog, LoadFailure, Message, Panel, Screen, Skeleton, Timestamp } from './ui';

interface IdpKeySummary {
  readonly state: 'pending' | 'active' | 'retiring' | 'retired';
  readonly certificate_sha256: string;
  readonly certificate_der_base64: string;
  readonly created_at: string;
}

interface Inventory {
  readonly keys: readonly IdpKeySummary[];
}

interface SpTrust {
  readonly entity_id: string;
  readonly acs_url: string;
  readonly allow_unsigned_requests: boolean;
  readonly redirect_signing_key_sha256: string | null;
  readonly created_at: string;
}

interface SpInventory {
  readonly service_providers: readonly SpTrust[];
}

type Load =
  | { readonly kind: 'loading' }
  | { readonly kind: 'empty' }
  | { readonly kind: 'ready'; readonly inventory: Inventory }
  | { readonly kind: 'failed'; readonly message: string };

type KeyAction = {
  readonly kind: 'activate' | 'retire';
  readonly certificate_sha256: string;
};

const KEY_PATH = 'saml/idp-key';
const SP_PATH = 'saml/sp-trusts';
const MAX_SP_BODY_BYTES = 4 * 1024;
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
  const [confirming, setConfirming] = useState<KeyAction | null>(null);
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

  const performAction = async (action: KeyAction): Promise<void> => {
    setConfirming(null);
    setBusy(true);
    setMessage(null);
    const activation = action.kind === 'activate';
    try {
      await mutate(`${KEY_PATH}/${activation ? 'activation' : 'retirement'}`, 'POST', session,
        activation
          ? { certificate_sha256: action.certificate_sha256 }
          : { certificate_sha256: action.certificate_sha256, rollover_confirmed: true });
      refresh();
      const text = activation
        ? 'The successor is now active. The previous certificate remains published until retirement.'
        : 'The former certificate was retired and its private key material was erased.';
      setMessage({ tone: 'success', text });
      toast.success(activation ? 'SAML key activated' : 'SAML key retired', text);
    } catch (error: unknown) {
      const text = error instanceof Error ? error.message : 'The SAML key change was refused.';
      setMessage({ tone: 'error', text });
      toast.error('SAML key unchanged', text);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Screen title="SAML identity provider" description={`Signing material for ${session.workspace}.`}>
      <Message tone="info">SAML browser SSO requires an active key and an explicitly trusted SP. {hasActive && <><a href="../saml/metadata">Open signed IdP metadata</a>. </>}SAML Single Logout is not offered.</Message>
      {message !== null && <Message tone={message.tone}>{message.text}</Message>}
      <Panel title="IdP signing certificates" description="Public certificate state for this tenant. Private keys are never returned by the API.">
        {load.kind === 'loading' && <Skeleton rows={3} label="Reading SAML IdP key." />}
        {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
        {load.kind === 'empty' && <p className="muted">No SAML IdP key is provisioned for this tenant.</p>}
        {load.kind === 'ready' && load.inventory.keys.map((key) => (
          <div key={key.certificate_sha256} className="flex flex-col gap-3 border-b border-border py-3 last:border-b-0">
            <dl className="stats">
              <div><dt>State</dt><dd><Badge tone={key.state === 'active' ? 'ok' : key.state === 'retired' ? 'neutral' : 'warn'}>{key.state}</Badge></dd></div>
              <div><dt>Certificate SHA-256</dt><dd><code className="break-all">{key.certificate_sha256}</code></dd></div>
              <div><dt>Created</dt><dd><Timestamp value={key.created_at} /></dd></div>
            </dl>
            {canWrite && key.state === 'pending' && (
              <Button disabled={busy} onClick={() => setConfirming({ kind: 'activate', certificate_sha256: key.certificate_sha256 })}>Activate successor</Button>
            )}
            {canWrite && key.state === 'retiring' && (
              <Button variant="danger" disabled={busy} onClick={() => setConfirming({ kind: 'retire', certificate_sha256: key.certificate_sha256 })}>Retire former certificate</Button>
            )}
          </div>
        ))}
      </Panel>
      {canImport && (
        <Panel
          title={hasActive ? 'Stage successor signing key' : 'Import initial signing key'}
          description="Import a matching X.509 certificate and unencrypted private PKCS#8 key, both as DER files. Stage, activate and retire are separate operator steps."
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
      <SpTrusts session={session} />
      {confirming !== null && (
        <ConfirmDialog
          title={confirming.kind === 'activate' ? 'Activate this SAML signing certificate?' : 'Confirm SP rollover is complete?'}
          body={confirming.kind === 'activate'
            ? <>The pending certificate <code className="break-all">{confirming.certificate_sha256}</code> will sign new assertions. The former active certificate remains in metadata during the rollover window.</>
            : <>Retire certificate <code className="break-all">{confirming.certificate_sha256}</code> only after every SP has obtained the replacement certificate. Retirement stops publishing it and erases its private material. At least ten minutes must have passed since activation.</>}
          confirmLabel={confirming.kind === 'activate' ? 'Activate certificate' : 'SP rollover complete — retire'}
          busy={busy}
          onCancel={() => setConfirming(null)}
          onConfirm={() => { void performAction(confirming); }}
        />
      )}
    </Screen>
  );
}

function SpTrusts({ session }: Readonly<{ session: Session }>): JSX.Element {
  const [load, setLoad] = useState<
    | { readonly kind: 'loading' }
    | { readonly kind: 'ready'; readonly trusts: readonly SpTrust[] }
    | { readonly kind: 'failed'; readonly message: string }
  >({ kind: 'loading' });
  const [entityId, setEntityId] = useState('');
  const [acsUrl, setAcsUrl] = useState('');
  const [allowUnsigned, setAllowUnsigned] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: 'success' | 'error'; text: string } | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);
  const signingKeyInput = useRef<HTMLInputElement>(null);
  const canWrite = session.scopes.includes('admin.saml:write');

  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    read(SP_PATH).then(
      (value) => setLoad({ kind: 'ready', trusts: (value as SpInventory).service_providers }),
      (error: unknown) => setLoad({
        kind: 'failed',
        message: error instanceof Error ? error.message : 'SAML SP trusts could not be read.',
      }),
    );
  }, []);

  useEffect(refresh, [refresh]);

  const provision = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    const keyFile = signingKeyInput.current?.files?.[0];
    try {
      if (new URL(acsUrl).protocol !== 'https:') {
        throw new Error('The assertion consumer service URL must use HTTPS.');
      }
    } catch {
      setMessage({ tone: 'error', text: 'Enter a valid HTTPS assertion consumer service URL.' });
      return;
    }
    if (!allowUnsigned && !keyFile) {
      setMessage({ tone: 'error', text: 'Choose a Redirect signing key or explicitly allow unsigned requests.' });
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      let redirect_signing_public_key_der_base64: string | null = null;
      if (keyFile) {
        if (keyFile.size < 256 || keyFile.size > 4096) {
          throw new Error('The RSA public key DER file must be between 256 bytes and 4 KB.');
        }
        redirect_signing_public_key_der_base64 = btoa(String.fromCharCode(...new Uint8Array(await keyFile.arrayBuffer())));
      }
      const payload = {
        entity_id: entityId,
        acs_url: acsUrl,
        allow_unsigned_requests: allowUnsigned,
        redirect_signing_public_key_der_base64,
      };
      if (new TextEncoder().encode(JSON.stringify(payload)).length > MAX_SP_BODY_BYTES) {
        throw new Error('The SP trust exceeds the API limit of 4 KB. Use a smaller signing key or shorter identifiers.');
      }
      await mutate(SP_PATH, 'PUT', session, payload);
      setEntityId('');
      setAcsUrl('');
      setAllowUnsigned(false);
      if (signingKeyInput.current) signingKeyInput.current.value = '';
      refresh();
      setMessage({ tone: 'success', text: 'The SP trust was added.' });
      toast.success('SP trust added');
    } catch (error: unknown) {
      const text = error instanceof Error ? error.message : 'The SP trust could not be added.';
      setMessage({ tone: 'error', text });
      toast.error('SP trust unchanged', text);
    } finally {
      setBusy(false);
    }
  };

  const remove = async (selectedEntityId: string): Promise<void> => {
    setRemoving(null);
    setBusy(true);
    setMessage(null);
    try {
      await mutate(SP_PATH, 'DELETE', session, { entity_id: selectedEntityId });
      refresh();
      setMessage({ tone: 'success', text: 'The SP trust was removed.' });
      toast.success('SP trust removed');
    } catch (error: unknown) {
      const text = error instanceof Error ? error.message : 'The SP trust could not be removed.';
      setMessage({ tone: 'error', text });
      toast.error('SP trust unchanged', text);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      {message !== null && <Message tone={message.tone}>{message.text}</Message>}
      <Panel title="Trusted service providers" description="Only these exact entity IDs and ACS URLs may use this tenant's SAML IdP.">
        {load.kind === 'loading' && <Skeleton rows={3} label="Reading SAML SP trusts." />}
        {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
        {load.kind === 'ready' && load.trusts.length === 0 && <p className="muted">No service providers are trusted yet.</p>}
        {load.kind === 'ready' && load.trusts.map((trust) => (
          <div key={trust.entity_id} className="flex flex-col gap-3 border-b border-border py-3 last:border-b-0">
            <dl className="stats">
              <div><dt>Entity ID</dt><dd><code className="break-all">{trust.entity_id}</code></dd></div>
              <div><dt>ACS URL</dt><dd><code className="break-all">{trust.acs_url}</code></dd></div>
              <div><dt>Unsigned requests</dt><dd><Badge tone={trust.allow_unsigned_requests ? 'warn' : 'ok'}>{trust.allow_unsigned_requests ? 'Allowed' : 'Refused'}</Badge></dd></div>
              <div><dt>Redirect signing key SHA-256</dt><dd>{trust.redirect_signing_key_sha256 === null ? 'None' : <code className="break-all">{trust.redirect_signing_key_sha256}</code>}</dd></div>
              <div><dt>Added</dt><dd><Timestamp value={trust.created_at} /></dd></div>
            </dl>
            {canWrite && <Button variant="danger" disabled={busy} onClick={() => setRemoving(trust.entity_id)}>Remove trust</Button>}
          </div>
        ))}
      </Panel>
      {canWrite && (
        <Panel title="Add service provider" description="Enter operator-approved values. The IdP matches the entity ID and HTTPS ACS URL exactly; it does not import SP metadata.">
          <form className="flex flex-col gap-3" onSubmit={(event) => { void provision(event); }}>
            <label className="flex flex-col gap-1" htmlFor="saml-sp-entity-id">Entity ID
              <input id="saml-sp-entity-id" value={entityId} onChange={(event) => setEntityId(event.target.value)} maxLength={1024} required disabled={busy} autoComplete="off" />
            </label>
            <label className="flex flex-col gap-1" htmlFor="saml-sp-acs-url">Assertion consumer service URL (HTTPS)
              <input id="saml-sp-acs-url" type="url" value={acsUrl} onChange={(event) => setAcsUrl(event.target.value)} maxLength={2048} required disabled={busy} autoComplete="off" />
            </label>
            <label className="flex flex-col gap-1" htmlFor="saml-sp-signing-key">Redirect signing public key (RSA DER)
              <input id="saml-sp-signing-key" ref={signingKeyInput} type="file" disabled={busy} autoComplete="off" />
            </label>
            <label className="flex items-center gap-2" htmlFor="saml-sp-allow-unsigned">
              <input id="saml-sp-allow-unsigned" type="checkbox" checked={allowUnsigned} onChange={(event) => setAllowUnsigned(event.target.checked)} disabled={busy} />
              Allow unsigned authentication requests for this SP
            </label>
            <p className="muted">Unsigned requests are refused by default. A pinned public key is required unless you explicitly allow them.</p>
            <Button type="submit" disabled={busy}>{busy ? 'Adding…' : 'Add SP trust'}</Button>
          </form>
        </Panel>
      )}
      {removing !== null && (
        <ConfirmDialog
          title="Remove this SP trust?"
          body={<>The service provider <code className="break-all">{removing}</code> will no longer be able to start SAML sign-in for this tenant. Existing replay records remain retained.</>}
          confirmLabel="Remove SP trust"
          busy={busy}
          onCancel={() => setRemoving(null)}
          onConfirm={() => { void remove(removing); }}
        />
      )}
    </>
  );
}
