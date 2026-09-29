import { useState } from 'react';
import { Button } from '../ui';

/** Clipboard failures remain visible; values never enter telemetry or persistent storage. */
export function CopyValue({ value, label = 'Copy', onCopied }: { value: string; label?: string; onCopied?: () => void }) {
  const [notice, setNotice] = useState('');
  const copy = async () => {
    try { await navigator.clipboard.writeText(value); setNotice('Copied'); onCopied?.(); }
    catch { setNotice('Copy was unavailable. Select and copy the value manually.'); }
  };
  return <span className="copy-value"><Button small onClick={() => void copy()}>{label}</Button><span aria-live="polite">{notice}</span></span>;
}
