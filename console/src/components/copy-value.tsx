import { useLayoutEffect, useRef, useState } from 'react';
import { CheckIcon, CopyIcon } from 'lucide-react';
import { Button } from '../ui';

/** Clipboard failures remain visible; values never enter telemetry or persistent storage. */
export function CopyValue({ value, label = 'Copy', onCopied, iconOnly = false }: { value: string; label?: string; onCopied?: () => void; iconOnly?: boolean }) {
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const generation = useRef(0);
  useLayoutEffect(() => {
    generation.current++;
    setNotice(''); setBusy(false);
    return () => { generation.current++; };
  }, [value]);
  const copy = async () => {
    const request = ++generation.current;
    setBusy(true); setNotice('');
    try {
      await navigator.clipboard.writeText(value);
      if (request === generation.current) { setNotice('Copied'); onCopied?.(); }
    } catch {
      if (request === generation.current) setNotice('Copy was unavailable. Select and copy the value manually.');
    } finally { if (request === generation.current) setBusy(false); }
  };
  return <span className="copy-value"><Button small disabled={busy} aria-busy={busy} variant="ghost" className={iconOnly ? 'copy-icon' : undefined} aria-label={label} title={label} onClick={() => void copy()}>{notice === 'Copied' ? <CheckIcon aria-hidden="true" /> : <CopyIcon aria-hidden="true" />}{!iconOnly && label}</Button><span className={iconOnly && notice === 'Copied' ? 'visually-hidden' : undefined} aria-live="polite">{notice}</span></span>;
}
