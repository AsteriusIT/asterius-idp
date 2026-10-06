import { useId } from 'react';
import { Field, FieldLabel } from './ui/field';
import { Switch } from './ui/switch';

export function InlineSwitch({ label, accessibleLabel, checked, onCheckedChange }: Readonly<{
  label: string; accessibleLabel?: string; checked: boolean; onCheckedChange: (checked: boolean) => void;
}>) {
  const id = useId();
  return <Field orientation="horizontal" className="inline-switch"><FieldLabel htmlFor={id}>{label}{accessibleLabel && <span className="visually-hidden">{accessibleLabel.slice(label.length)}</span>}</FieldLabel><Switch id={id} checked={checked} onCheckedChange={onCheckedChange} /></Field>;
}
