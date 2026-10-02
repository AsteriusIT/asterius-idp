import { useState } from 'react';
import { CheckIcon, EyeIcon, EyeOffIcon, KeyRoundIcon } from 'lucide-react';
import { Actions, Button, Panel } from '../ui';
import { CopyValue } from './copy-value';

/** Ephemeral credentials remain in the editor; reveal and clipboard are explicit actions. */
export function OneTimeSecret({ value, onStored }: Readonly<{ value: string; onStored: () => void }>) {
  const [revealed, setRevealed] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  return <Panel className="credential-secret-panel" title="Save your new client secret" description="This value is shown once. Store it in your application’s secret manager before leaving.">
    <div className="secret-value-row">
      <KeyRoundIcon aria-hidden="true" />
      <code aria-label={revealed ? undefined : 'Client secret hidden'}>{revealed ? value : '••••••••••••••••••••••••'}</code>
      <Button variant="ghost" small className="secret-reveal" aria-label={revealed ? 'Hide secret' : 'Show secret'} title={revealed ? 'Hide secret' : 'Show secret'} aria-pressed={revealed} onClick={() => setRevealed(current => !current)}>{revealed ? <EyeOffIcon aria-hidden="true" /> : <EyeIcon aria-hidden="true" />}</Button>
    </div>
    <Actions>
      <CopyValue value={value} label="Copy secret" onCopied={onStored} />
      <Button small variant="ghost" onClick={() => { setAcknowledged(true); onStored(); }}><CheckIcon aria-hidden="true" />I have saved the secret</Button>
    </Actions>
    {acknowledged && <p className="secret-saved" role="status"><CheckIcon aria-hidden="true" />Secret acknowledged. You can leave this page.</p>}
    <p className="muted">Asterius stores only a digest. The original secret cannot be retrieved.</p>
  </Panel>;
}
