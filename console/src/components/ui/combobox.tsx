import type { ComponentProps } from 'react';
import { Combobox as Primitive } from '@base-ui/react/combobox';
import { CheckIcon } from 'lucide-react';
import { Input } from './input';
import { cn } from '@/lib/utils';

// Adapted from CLI-inspected shadcn Base Vega: owned input, tokens and portal stacking.
export const Combobox = Primitive.Root;
export function ComboboxInput(props: ComponentProps<typeof Primitive.Input>) {
  return <Primitive.Input data-slot="combobox-input" render={<Input />} {...props} />;
}
export function ComboboxContent({ className, ...props }: ComponentProps<typeof Primitive.Popup>) {
  return <Primitive.Portal className="console-overlay-portal"><Primitive.Positioner sideOffset={6} align="start">
    <Primitive.Popup data-slot="combobox-content" className={cn('entity-options', className)} {...props} />
  </Primitive.Positioner></Primitive.Portal>;
}
export function ComboboxList(props: ComponentProps<typeof Primitive.List>) {
  return <Primitive.List data-slot="combobox-list" className="entity-option-list" {...props} />;
}
export function ComboboxItem({ children, className, ...props }: ComponentProps<typeof Primitive.Item>) {
  return <Primitive.Item data-slot="combobox-item" className={cn('entity-option', className)} {...props}>
    {children}<Primitive.ItemIndicator className="entity-option-check"><CheckIcon aria-hidden="true" /></Primitive.ItemIndicator>
  </Primitive.Item>;
}
