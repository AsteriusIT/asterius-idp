import type { ComponentProps, JSX } from 'react';
import { MinusIcon, PlusIcon } from 'lucide-react';
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput } from '@/components/ui/input-group';
import { Button } from '@/components/ui/button';
import { rateError } from '../rate-limit-model';

/** Explicit adjustments preserve raw drafts; empty always means inherit. */
export function OptionalNumberInput({ value, maximum, label, onValueChange, disabled, ...props }: {
  value: string;
  maximum: number;
  label: string;
  onValueChange: (value: string) => void;
} & Omit<ComponentProps<typeof InputGroupInput>, 'value' | 'onChange' | 'type' | 'min' | 'max' | 'step'>): JSX.Element {
  const valid = rateError(value, maximum) === null;
  const current = value === '' ? maximum : Number(value);
  const step = (direction: -1 | 1) => {
    if (direction === 1 && current >= maximum || direction === -1 && current <= 1) return;
    if (!disabled && valid) onValueChange(String(Math.min(maximum, Math.max(1, current + direction))));
  };
  return <div className="optional-number-control">
    <InputGroup className="optional-number-input" data-disabled={disabled || undefined}>
      <InputGroupInput {...props} type="text" inputMode="numeric" role="spinbutton" value={value} disabled={disabled}
        aria-valuemin={1} aria-valuemax={maximum} {...(valid && value !== '' ? { 'aria-valuenow': current } : {})}
        aria-valuetext={value === '' ? `Inherited deployment maximum: ${maximum}` : value}
        onChange={event => onValueChange(event.target.value)} onKeyDown={event => {
          if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey || !valid) return;
          if (event.key === 'ArrowUp' || event.key === 'ArrowDown') { event.preventDefault(); step(event.key === 'ArrowUp' ? 1 : -1); }
        }} />
      <InputGroupAddon align="inline-end">
        <InputGroupButton size="icon-sm" disabled={disabled || !valid || current <= 1} aria-label={`Decrease ${label}`} onClick={() => step(-1)}><MinusIcon aria-hidden="true" /></InputGroupButton>
        <InputGroupButton size="icon-sm" disabled={disabled || !valid || current >= maximum} aria-label={`Increase ${label}`} onClick={() => step(1)}><PlusIcon aria-hidden="true" /></InputGroupButton>
      </InputGroupAddon>
    </InputGroup>
    <Button type="button" variant="ghost" size="sm" disabled={disabled || value === ''} aria-label={`Use inherited limit for ${label}`} onClick={() => onValueChange('')}>Inherit</Button>
  </div>;
}
