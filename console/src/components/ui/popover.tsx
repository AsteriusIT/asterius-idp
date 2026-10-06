import type { ComponentProps } from 'react';
import { Popover as Primitive } from '@base-ui/react/popover';
import { cn } from '@/lib/utils';
export const Popover = Primitive.Root;
export const PopoverTrigger = Primitive.Trigger;
export function PopoverContent({ className, align = 'center', side = 'bottom', sideOffset = 4, alignOffset = 0, ...props }:
  Omit<ComponentProps<typeof Primitive.Popup>, 'className'> & { className?: string } & Pick<ComponentProps<typeof Primitive.Positioner>, 'align' | 'side' | 'sideOffset' | 'alignOffset'>) {
  return <Primitive.Portal className="console-overlay-portal"><Primitive.Positioner align={align} side={side} sideOffset={sideOffset} alignOffset={alignOffset}>
    <Primitive.Popup data-slot="popover-content" className={cn('w-72 origin-(--transform-origin) rounded-md border bg-popover p-4 text-popover-foreground shadow-md outline-hidden transition-[opacity,transform] duration-150 data-starting-style:opacity-0 data-ending-style:opacity-0 data-starting-style:scale-95 data-ending-style:scale-95', className)} {...props} />
  </Primitive.Positioner></Primitive.Portal>;
}
export function PopoverHeader({ className, ...props }: ComponentProps<'div'>) {
  return <div data-slot="popover-header" className={cn('flex flex-col gap-1 text-sm', className)} {...props} />;
}
export function PopoverTitle({ className, ...props }: Omit<ComponentProps<typeof Primitive.Title>, 'className'> & { className?: string }) {
  return <Primitive.Title data-slot="popover-title" className={cn('font-medium', className)} {...props} />;
}
export function PopoverDescription({ className, ...props }: Omit<ComponentProps<typeof Primitive.Description>, 'className'> & { className?: string }) {
  return <Primitive.Description data-slot="popover-description" className={cn('text-muted-foreground', className)} {...props} />;
}
