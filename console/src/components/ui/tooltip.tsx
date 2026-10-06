import type { ComponentProps } from 'react';
import { Tooltip as Primitive } from '@base-ui/react/tooltip';
import { cn } from '@/lib/utils';
export function TooltipProvider({ delay = 0, ...props }: ComponentProps<typeof Primitive.Provider>) {
  return <Primitive.Provider delay={delay} {...props} />;
}
export const Tooltip = Primitive.Root;
export const TooltipTrigger = Primitive.Trigger;
export function TooltipContent({ className, side = 'top', align = 'center', sideOffset = 4, alignOffset = 0, children, hidden, ...props }:
  Omit<ComponentProps<typeof Primitive.Popup>, 'className'> & { className?: string } & Pick<ComponentProps<typeof Primitive.Positioner>, 'side' | 'align' | 'sideOffset' | 'alignOffset'>) {
  if (hidden) return null;
  return <Primitive.Portal className="console-overlay-portal"><Primitive.Positioner side={side} align={align} sideOffset={sideOffset} alignOffset={alignOffset}>
    <Primitive.Popup data-slot="tooltip-content" className={cn('w-fit origin-(--transform-origin) rounded-md bg-foreground px-3 py-1.5 text-xs text-balance text-background transition-opacity duration-150 data-starting-style:opacity-0 data-ending-style:opacity-0', className)} {...props}>
      {children}<Primitive.Arrow className="tooltip-arrow" />
    </Primitive.Popup>
  </Primitive.Positioner></Primitive.Portal>;
}
