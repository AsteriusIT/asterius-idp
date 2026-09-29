import { useDialogDraft } from './dialog-draft';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from './components/ui/dialog';
import { useCallback, useEffect, useState } from 'react';
import type { FormEvent, JSX } from 'react';
import { mutate, read, type Session } from './api';
import { JsonView } from './components/json-view';
import { Actions, Button, ConfirmDialog, EmptyState, Field, LoadFailure, Message, Panel, Skeleton } from './ui';

interface Bundle {
  readonly bundle_id: string;
  readonly verifier_issuer: string;
  readonly verified_claims: {
    readonly verification: {
      readonly trust_framework: string;
      readonly time: string;
      readonly verification_process?: string;
      readonly evidence?: readonly unknown[];
    };
    readonly claims: Readonly<Record<string, unknown>>;
  };
}

type Load = { kind: 'loading' } | { kind: 'failed'; message: string } | { kind: 'ready'; items: readonly Bundle[] };

function message(error: unknown): string {
  return error instanceof Error ? error.message : 'The request failed.';
}

function localNow(): string {
  const now = new Date();
  return new Date(now.getTime() - now.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

/** A verified bundle is separate from ordinary account claims and carries its own provenance. */
export function VerifiedClaims({ session, userId }: Readonly<{ session: Session; userId: string }>): JSX.Element {
  const base = `users/${encodeURIComponent(userId)}/verified-claims`;
  const mayWrite = session.scopes.includes('admin.users:write');
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [revokeId, setRevokeId] = useState<string | null>(null);
  const [verifiedAt, setVerifiedAt] = useState(localNow);
  const [claimsText, setClaimsText] = useState('');
  const [process, setProcess] = useState('');
  const [evidenceText, setEvidenceText] = useState('[]');
  const [creating, setCreating] = useState(false);
  const creationDraft = useDialogDraft(creating && (claimsText !== '' || process !== '' || evidenceText !== '[]'), busy, () => { setCreating(false); setClaimsText(''); setProcess(''); setEvidenceText('[]'); });

  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    read(base).then(
      (value) => setLoad({ kind: 'ready', items: (value as { items: readonly Bundle[] }).items }),
      (error: unknown) => setLoad({ kind: 'failed', message: message(error) }),
    );
  }, [base]);

  useEffect(refresh, [refresh]);

  const create = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    setRefusal(null);
    setNotice(null);
    let claims: unknown;
    let evidence: unknown;
    try {
      claims = JSON.parse(claimsText);
      evidence = JSON.parse(evidenceText);
    } catch {
      setRefusal('Claims and evidence must be valid JSON.');
      return;
    }
    if (claims === null || typeof claims !== 'object' || Array.isArray(claims) || Object.keys(claims).length === 0) {
      setRefusal('Claims must be a nonempty JSON object.');
      return;
    }
    if (!Array.isArray(evidence)) {
      setRefusal('Evidence must be a JSON array.');
      return;
    }
    const time = new Date(verifiedAt);
    if (!verifiedAt || Number.isNaN(time.getTime()) || time.getTime() > Date.now()) {
      setRefusal('Verification time must be a valid past date and time.');
      return;
    }
    setBusy(true);
    mutate(base, 'POST', session, {
      verified_at: time.toISOString(),
      claims,
      ...(process.trim() ? { verification_process: process.trim() } : {}),
      evidence,
    }).then(
      () => {
        setBusy(false);
        setNotice('Verified claims bundle added.');
        setCreating(false);
        setClaimsText(''); setProcess(''); setEvidenceText('[]');
        refresh();
      },
      (error: unknown) => {
        setBusy(false);
        setRefusal(message(error));
      },
    );
  };

  const revoke = (): void => {
    if (revokeId === null) return;
    setBusy(true);
    setRefusal(null);
    mutate(`${base}/${encodeURIComponent(revokeId)}`, 'DELETE', session).then(
      () => {
        setBusy(false);
        setRevokeId(null);
        setNotice('Verified claims bundle revoked.');
        refresh();
      },
      (error: unknown) => {
        setBusy(false);
        setRevokeId(null);
        setRefusal(message(error));
      },
    );
  };

  return (
    <Panel title="Verified identity claims" description="Identity assurance records with their verification source and time. These are separate from ordinary account claims." actions={mayWrite ? <Button onClick={() => setCreating(true)}>Add verified claims</Button> : undefined}>
      {notice !== null && <Message tone="success">{notice}</Message>}
      {refusal !== null && <Message tone="error">{refusal}</Message>}
      {load.kind === 'loading' && <Skeleton rows={3} label="Reading verified claims." />}
      {load.kind === 'failed' && <LoadFailure message={load.message} onRetry={refresh} />}
      {load.kind === 'ready' && load.items.length === 0 && <EmptyState title="No verified claims" body="This account has no identity assurance bundles." />}
      {load.kind === 'ready' && load.items.map((item) => (
        <section key={item.bundle_id} className="rounded-lg border p-4" aria-label={`Verification ${item.bundle_id}`}>
          <dl className="stats">
            <div className="stat"><dt>Bundle ID</dt><dd><code>{item.bundle_id}</code></dd></div>
            <div className="stat"><dt>Framework</dt><dd>{item.verified_claims.verification.trust_framework}</dd></div>
            <div className="stat"><dt>Verifier</dt><dd>{item.verifier_issuer}</dd></div>
            <div className="stat"><dt>Verified at</dt><dd><time dateTime={item.verified_claims.verification.time}>{new Date(item.verified_claims.verification.time).toLocaleString()}</time></dd></div>
            {item.verified_claims.verification.verification_process && <div className="stat"><dt>Process</dt><dd>{item.verified_claims.verification.verification_process}</dd></div>}
          </dl>
          <JsonView value={item.verified_claims.claims} label={`Verified claims ${item.bundle_id}`} />
          {(item.verified_claims.verification.evidence?.length ?? 0) > 0 && <JsonView value={item.verified_claims.verification.evidence} label={`Verification evidence ${item.bundle_id}`} />}
          {mayWrite && <Actions><Button variant="danger" disabled={busy} onClick={() => setRevokeId(item.bundle_id)}>Revoke bundle</Button></Actions>}
        </section>
      ))}
      <Dialog open={creating} onOpenChange={open => { if (!open) creationDraft.requestClose(); }}><DialogContent className="max-h-[calc(100vh-2rem)] overflow-y-auto"><DialogHeader><DialogTitle>Add verified claims</DialogTitle><DialogDescription>Record only attributes you verified.</DialogDescription></DialogHeader>{creationDraft.confirmation}
      {mayWrite && (
        <form onSubmit={create} className="flex flex-col gap-3">
          <h4>Add verified claims</h4>
          <p className="muted">Record only attributes you verified. Adding or revoking a bundle requires a passkey authentication within the last two minutes.</p>
          <Field label="Verified at" required>
            {(props) => <input {...props} type="datetime-local" value={verifiedAt} onChange={(event) => setVerifiedAt(event.target.value)} />}
          </Field>
          <Field label="Claims JSON" required hint="A nonempty object with one to 32 verified attributes. Token claims such as sub and iss are refused.">
            {(props) => <textarea {...props} rows={5} placeholder={'{\n  "given_name": "Ada"\n}'} value={claimsText} onChange={(event) => setClaimsText(event.target.value)} />}
          </Field>
          <Field label="Verification process" hint="Optional audit reference identifier.">
            {(props) => <input {...props} value={process} onChange={(event) => setProcess(event.target.value)} />}
          </Field>
          <Field label="Evidence JSON" hint="Optional array of typed evidence objects.">
            {(props) => <textarea {...props} rows={3} value={evidenceText} onChange={(event) => setEvidenceText(event.target.value)} />}
          </Field>
          <Actions><Button onClick={creationDraft.requestClose} disabled={busy}>Cancel</Button><Button type="submit" variant="primary" disabled={busy}>Add verified bundle</Button></Actions>
        </form>
      )}</DialogContent></Dialog>
      {revokeId !== null && <ConfirmDialog title="Revoke verified claims?" body="This bundle will no longer be available for identity assurance responses." confirmLabel="Revoke bundle" busy={busy} onConfirm={revoke} onCancel={() => setRevokeId(null)} />}
    </Panel>
  );
}
