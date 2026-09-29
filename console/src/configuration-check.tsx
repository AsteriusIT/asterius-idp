import { useState } from 'react';
import { read } from './api';
import { Badge, Button, Message, Panel } from './ui';

export interface ConfigurationResult { readonly pass: boolean; readonly message: string; readonly failureMessage: string }

/** Read-only checks explicitly separated from a live protocol exchange. */
export function ConfigurationCheck({ paths, evaluate }: Readonly<{
  paths: readonly string[]; evaluate: (documents: readonly unknown[]) => readonly ConfigurationResult[];
}>) {
  const [results, setResults] = useState<readonly ConfigurationResult[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [checked, setChecked] = useState<string | null>(null);
  const check = async () => {
    setBusy(true); setError(null); setResults(null);
    try { setResults(evaluate(await Promise.all(paths.map(path => read(path))))); setChecked(new Date().toISOString()); }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Configuration could not be checked.'); }
    finally { setBusy(false); }
  };
  return <Panel title="Configuration check" description="Reads the saved configuration and available status records. It does not contact an external application, issue tokens or send email.">
    <Button disabled={busy} onClick={() => void check()}>{busy ? 'Checking…' : 'Check configuration'}</Button>
    {error && <Message tone="error">{error}</Message>}
    {results && <><ul>{results.map(result => <li key={result.message}><Badge tone={result.pass ? 'ok' : 'warn'}>{result.pass ? 'Pass' : 'Review'}</Badge> {result.pass ? result.message : result.failureMessage}</li>)}</ul><p className="muted">Checked at {checked} (UTC)</p></>}
  </Panel>;
}
