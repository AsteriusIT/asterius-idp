import { useEffect, useState } from 'react';
import { probe, type Session } from './api';
import { Badge, Button, Message, Timestamp } from './ui';

interface Report { checked_at: number; checks: { name: string; status: string; message: string }[] }

/** While this screen is visible, check public metadata, never client credentials. */
export function ProviderHealth({ id, session }: Readonly<{ id: string; session: Session }>) {
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    let active = true;
    let running = false;
    const check = async () => {
      if (running || document.visibilityState === 'hidden') return;
      running = true; setBusy(true); setError(null);
      try {
        const value = await probe('oidc/providers/check', session, { id });
        if (active) setReport(value as Report);
      } catch (reason) { if (active) { setReport(null); setError(reason instanceof Error ? reason.message : 'The provider check failed.'); } }
      finally { running = false; if (active) setBusy(false); }
    };
    void check();
    const timer = window.setInterval(() => void check(), 60000);
    return () => { active = false; window.clearInterval(timer); };
  }, [id, session, retry]);
  return <div className="provider-health">
    {error && <Message tone="error">{error}</Message>}
    {busy && <p role="status">Checking public metadata…</p>}
    {report && <><Badge tone={report.checks.every(check => check.status === 'pass') ? 'ok' : 'warn'}>{report.checks.every(check => check.status === 'pass') ? 'Metadata checks pass' : 'Needs review'}</Badge>
      <details><summary>Check results</summary><ul>{report.checks.map(check => <li key={check.name}><strong>{check.status}</strong> — {check.message}</li>)}</ul><Timestamp value={report.checked_at} /></details></>}
    <Button small disabled={busy} onClick={() => setRetry(retry + 1)}>Check now</Button>
  </div>;
}
