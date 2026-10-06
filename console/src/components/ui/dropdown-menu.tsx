import type { ComponentProps } from 'react';
import { Menu } from '@base-ui/react/menu';

function Content({ side = 'bottom', align = 'end', sideOffset = 6, alignOffset = 0, collisionPadding = 12, ...props }:
  ComponentProps<typeof Menu.Popup> & Pick<ComponentProps<typeof Menu.Positioner>, 'side' | 'align' | 'sideOffset' | 'alignOffset' | 'collisionPadding'>) {
  return <Menu.Positioner side={side} align={align} sideOffset={sideOffset} alignOffset={alignOffset} collisionPadding={collisionPadding}><Menu.Popup {...props} /></Menu.Positioner>;
}
/** Asterius menus use Base UI with one positioning boundary. */
export const DropdownMenu = {
  Root: Menu.Root, Trigger: Menu.Trigger, Portal: ({ ...props }: ComponentProps<typeof Menu.Portal>) => <Menu.Portal className="console-overlay-portal" {...props} />,
  Content, Group: Menu.Group, GroupLabel: Menu.GroupLabel, Item: Menu.Item, LinkItem: Menu.LinkItem,
  RadioGroup: Menu.RadioGroup, RadioItem: Menu.RadioItem, RadioItemIndicator: Menu.RadioItemIndicator,
  Separator: Menu.Separator,
};
