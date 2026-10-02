import { useState } from 'react';
import { CheckIcon, CopyIcon } from 'lucide-react';
import { Button } from '../ui';

/** Clipboard failures remain visible; values never enter telemetry or persistent storage. */
export function CopyValue({ value, label = 'Copy', onCopied, iconOnly = false }: { value: string; label?: string; onCopied?: () => void; iconOnly?: boolean }) {
  const [notice, setNotice] = useState('');
  const copy = async () => {
    try { await navigator.clipboard.writeText(value); setNotice('Copied'); onCopied?.(); }
    catch { setNotice('Copy was unavailable. Select and copy the value manually.'); }
  };
  return <span className="copy-value"><Button small variant="ghost" className={iconOnly ? 'copy-icon' : undefined} aria-label={label} title={label} onClick={() => void copy()}>{notice === 'Copied' ? <CheckIcon aria-hidden="true" /> : <CopyIcon aria-hidden="true" />}{!iconOnly && label}</Button><span className={iconOnly && notice === 'Copied' ? 'visually-hidden' : undefined} aria-live="polite">{notice}</span></span>;
}
