import type { ComponentProps } from 'react';
import { Select as SelectPrimitive } from 'radix-ui';
import { CheckIcon, ChevronDownIcon, ChevronUpIcon } from 'lucide-react';
import { cn } from '@/lib/utils';

export const Select = SelectPrimitive.Root;
export const SelectValue = SelectPrimitive.Value;
export function SelectTrigger({ children, className, ...props }: ComponentProps<typeof SelectPrimitive.Trigger>) {
  return <SelectPrimitive.Trigger data-slot="select-trigger" className={cn('select-trigger', className)} {...props}>
    {children}<SelectPrimitive.Icon asChild><ChevronDownIcon aria-hidden="true" /></SelectPrimitive.Icon>
  </SelectPrimitive.Trigger>;
}
export function SelectContent({ children, className, ...props }: ComponentProps<typeof SelectPrimitive.Content>) {
  return <SelectPrimitive.Portal><SelectPrimitive.Content position="popper" sideOffset={5}
    className={cn('select-content', className)} {...props}>
    <SelectPrimitive.ScrollUpButton className="select-scroll"><ChevronUpIcon /></SelectPrimitive.ScrollUpButton>
    <SelectPrimitive.Viewport>{children}</SelectPrimitive.Viewport>
    <SelectPrimitive.ScrollDownButton className="select-scroll"><ChevronDownIcon /></SelectPrimitive.ScrollDownButton>
  </SelectPrimitive.Content></SelectPrimitive.Portal>;
}
export function SelectItem({ children, className, ...props }: ComponentProps<typeof SelectPrimitive.Item>) {
  return <SelectPrimitive.Item className={cn('select-item', className)} {...props}>
    <SelectPrimitive.ItemText>{children}</SelectPrimitive.ItemText>
    <SelectPrimitive.ItemIndicator><CheckIcon aria-hidden="true" /></SelectPrimitive.ItemIndicator>
  </SelectPrimitive.Item>;
}

/** Form adapter: keeps empty values and submitted values in the API's vocabulary. */
export function FormSelect({ value, onValueChange, options, name, disabled, required, ...props }: {
  value: string;
  onValueChange: (value: string) => void;
  options: readonly { value: string; label: string }[];
  name?: string;
  disabled?: boolean;
  required?: boolean;
} & Pick<ComponentProps<typeof SelectTrigger>, 'id' | 'aria-label' | 'aria-describedby' | 'aria-invalid'>) {
  return <>
    {name && <input type="hidden" name={name} value={value} disabled={disabled} />}
    <Select value={`value:${value}`} onValueChange={(next) => onValueChange(next.slice(6))}
      {...(disabled !== undefined ? { disabled } : {})} {...(required !== undefined ? { required } : {})}>
      <SelectTrigger {...props}><SelectValue /></SelectTrigger>
      <SelectContent>{options.map((option) => <SelectItem key={option.value} value={`value:${option.value}`}>{option.label}</SelectItem>)}</SelectContent>
    </Select>
  </>;
}
