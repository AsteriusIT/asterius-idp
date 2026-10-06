import { useId, type ComponentProps, type ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import { Field, FieldContent, FieldDescription, FieldLabel } from '@/components/ui/field';
import { Switch } from '@/components/ui/switch';
import { InputGroup, InputGroupAddon, InputGroupInput, InputGroupText } from '@/components/ui/input-group';

/** A draft setting: the switch changes local state; the form's save action commits it. */
export function SettingSwitch({ label, description, icon: Icon, ...props }: ComponentProps<typeof Switch> & {
  label: string;
  description?: ReactNode;
  icon?: LucideIcon;
}) {
  const generated = useId();
  const id = props.id ?? generated;
  const descriptionId = `${id}-description`;
  return <Field orientation="horizontal" className="setting-field" data-disabled={props.disabled || undefined}>
    {Icon && <span className="setting-icon" aria-hidden="true"><Icon /></span>}
    <FieldContent>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      {description !== undefined && <FieldDescription id={descriptionId}>{description}</FieldDescription>}
    </FieldContent>
    <Switch {...props} id={id} {...(description !== undefined ? { 'aria-describedby': descriptionId } : {})} />
  </Field>;
}

/** A unit belongs to the control, while the label retains the full accessible unit. */
export function DurationInput(props: ComponentProps<typeof InputGroupInput>) {
  return <InputGroup className="duration-input" data-disabled={props.disabled || undefined}>
    <InputGroupInput {...props} type="number" />
    <InputGroupAddon align="inline-end" aria-hidden="true"><InputGroupText>sec</InputGroupText></InputGroupAddon>
  </InputGroup>;
}
