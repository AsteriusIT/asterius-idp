import type { ComponentProps } from 'react';
import { Select as SelectPrimitive } from '@base-ui/react/select';
import { CheckIcon, ChevronDownIcon, ChevronUpIcon } from 'lucide-react';
import { cn } from '@/lib/utils';

export const Select = SelectPrimitive.Root;
export const SelectValue = SelectPrimitive.Value;
export function SelectTrigger({ children, className, ...props }: Omit<ComponentProps<typeof SelectPrimitive.Trigger>, 'className'> & { className?: string }) {
  return <SelectPrimitive.Trigger data-slot="select-trigger" className={cn('select-trigger', className)} {...props}>
    {children}<SelectPrimitive.Icon><ChevronDownIcon aria-hidden="true" /></SelectPrimitive.Icon>
  </SelectPrimitive.Trigger>;
}
export const SelectGroup = SelectPrimitive.Group;
export function SelectContent({ children, className, ...props }: Omit<ComponentProps<typeof SelectPrimitive.Popup>, 'className'> & { className?: string }) {
  return <SelectPrimitive.Portal className="console-overlay-portal"><SelectPrimitive.Positioner sideOffset={5} alignItemWithTrigger={false}>
    <SelectPrimitive.Popup data-slot="select-content" className={cn('select-content', className)} {...props}>
      <SelectPrimitive.ScrollUpArrow className="select-scroll"><ChevronUpIcon /></SelectPrimitive.ScrollUpArrow>
      <SelectPrimitive.List>{children}</SelectPrimitive.List>
      <SelectPrimitive.ScrollDownArrow className="select-scroll"><ChevronDownIcon /></SelectPrimitive.ScrollDownArrow>
    </SelectPrimitive.Popup>
  </SelectPrimitive.Positioner></SelectPrimitive.Portal>;
}
export function SelectItem({ children, className, description, ...props }: Omit<ComponentProps<typeof SelectPrimitive.Item>, 'className'> & { className?: string; description?: string }) {
  return <SelectPrimitive.Item className={cn('select-item', className)} {...props}>
    <span className="select-item-copy"><SelectPrimitive.ItemText>{children}</SelectPrimitive.ItemText>{description && <span className="select-item-description">{description}</span>}</span>
    <SelectPrimitive.ItemIndicator><CheckIcon aria-hidden="true" /></SelectPrimitive.ItemIndicator>
  </SelectPrimitive.Item>;
}

/** Form adapter: keeps empty values and submitted values in the API's vocabulary. */
export function FormSelect({ value, onValueChange, options, name, disabled, required, ...props }: {
  value: string;
  onValueChange: (value: string) => void;
  options: readonly { value: string; label: string; description?: string }[];
  name?: string;
  disabled?: boolean;
  required?: boolean;
} & Pick<ComponentProps<typeof SelectTrigger>, 'id' | 'aria-label' | 'aria-describedby' | 'aria-invalid'>) {
  return <>
    {name && <input type="hidden" name={name} value={value} disabled={disabled} />}
    <Select value={value} items={options.map(option => ({ value: option.value, label: option.label }))} onValueChange={(next) => onValueChange(next ?? '')}
      {...(disabled !== undefined ? { disabled } : {})} {...(required !== undefined ? { required } : {})}>
      <SelectTrigger {...props}><SelectValue /></SelectTrigger>
      <SelectContent><SelectGroup>{options.map((option) => <SelectItem key={option.value} value={option.value} {...(option.description ? { description: option.description } : {})}>{option.label}</SelectItem>)}</SelectGroup></SelectContent>
    </Select>
  </>;
}
