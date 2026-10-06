import { useEffect, useState, type ComponentProps } from 'react';
import { EyeIcon, EyeOffIcon } from 'lucide-react';
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput } from './ui/input-group';

/** Reveal only the entered draft. Never read back, copy or persist a stored credential. */
export function SecretInput({ secretLabel = 'password', disabled, value, ...props }: Omit<ComponentProps<typeof InputGroupInput>, 'type'> & { secretLabel?: string }) {
  const [revealed, setRevealed] = useState(false);
  useEffect(() => { if (disabled || value === '') setRevealed(false); }, [disabled, value]);
  return <InputGroup className="secret-input" onBlurCapture={event => {
    if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setRevealed(false);
  }}>
    <InputGroupInput {...props} value={value} disabled={disabled} type={revealed && !disabled ? 'text' : 'password'} />
    <InputGroupAddon align="inline-end"><InputGroupButton size="icon-sm" disabled={disabled || value === ''} aria-pressed={revealed && !disabled} aria-label={`${revealed && !disabled ? 'Hide' : 'Show'} ${secretLabel}`} onClick={() => setRevealed(current => !current)}>{revealed && !disabled ? <EyeOffIcon aria-hidden="true" /> : <EyeIcon aria-hidden="true" />}</InputGroupButton></InputGroupAddon>
  </InputGroup>;
}
