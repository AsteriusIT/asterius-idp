import type { ComponentProps } from 'react';
import { Tabs as TabsPrimitive } from '@base-ui/react/tabs';
import { cn } from '@/lib/utils';

export const Tabs = TabsPrimitive.Root;
export function TabsList({ className, ...props }: Omit<ComponentProps<typeof TabsPrimitive.List>, 'className'> & { className?: string }) {
  return <TabsPrimitive.List className={cn('console-tabs', className)} {...props} />;
}
export function TabsTrigger({ className, ...props }: Omit<ComponentProps<typeof TabsPrimitive.Tab>, 'className'> & { className?: string }) {
  return <TabsPrimitive.Tab className={cn('console-tab', className)} {...props} />;
}
/** Keep editors mounted so switching tabs never discards an unsaved field. */
export function TabsContent({ className, ...props }: Omit<ComponentProps<typeof TabsPrimitive.Panel>, 'className' | 'keepMounted'> & { className?: string }) {
  return <TabsPrimitive.Panel keepMounted className={cn('console-tab-content', className)} {...props} />;
}
