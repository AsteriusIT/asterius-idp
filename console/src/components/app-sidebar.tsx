import type { JSX } from 'react';
import {
  AppWindowIcon,
  Building2Icon,
  KeyRoundIcon,
  LayoutDashboardIcon,
  RadioIcon,
  ScaleIcon,
  ScrollTextIcon,
  Settings2Icon,
  SlidersHorizontalIcon,
  UsersIcon,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import type { Session } from '@/api';
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarSeparator,
  useSidebar,
} from '@/components/ui/sidebar';
import { sectionsFor } from '@/navigation';
import { hrefOf } from '@/routes';

/** Icons are shared with the overview cards so one route keeps one symbol. */
export const NAVIGATION_ICONS: Readonly<Record<string, LucideIcon>> = {
  overview: LayoutDashboardIcon,
  users: UsersIcon,
  clients: AppWindowIcon,
  keys: KeyRoundIcon,
  policy: ScaleIcon,
  ssf: RadioIcon,
  audit: ScrollTextIcon,
  tenants: Building2Icon,
  settings: SlidersHorizontalIcon,
  preferences: Settings2Icon,
};

/**
 * A fixed icon rail on desktop and a labelled sheet on small screens. It does
 * not collapse, expand or pretend to resize: the topbar owns context, while
 * this rail answers only “where next?”.
 */
export function AppSidebar({
  session,
  current,
}: {
  session: Session;
  current: string;
}): JSX.Element {
  const sections = sectionsFor(session);
  const { setOpenMobile } = useSidebar();

  return (
    <Sidebar collapsible="icon" className="app-sidebar">
      <SidebarHeader className="items-center px-2 py-3">
        <a className="app-mark" href={hrefOf('overview')} aria-label="Asterius overview">
          <span aria-hidden="true">A</span>
          <strong className="md:sr-only">Asterius console</strong>
        </a>
      </SidebarHeader>

      <SidebarContent className="px-2">
        <nav aria-label="Console sections" className="flex flex-col">
          {sections.map((section, sectionIndex) => (
            <div key={section.group}>
              {sectionIndex > 0 && <SidebarSeparator className="my-2" />}
              <SidebarGroup className="p-0">
                <SidebarGroupLabel className="md:sr-only">{section.group}</SidebarGroupLabel>
                <SidebarGroupContent>
                  <SidebarMenu>
                    {section.destinations.map((destination) => {
                      const Icon = NAVIGATION_ICONS[destination.route];
                      const active = destination.route === current;
                      return (
                        <SidebarMenuItem key={destination.route}>
                          <SidebarMenuButton
                            asChild
                            isActive={active}
                            tooltip={destination.label}
                            className="console-nav-link h-10 md:justify-center md:px-0"
                          >
                            <a
                              href={hrefOf(destination.route)}
                              onClick={() => setOpenMobile(false)}
                              aria-current={active ? 'page' : undefined}
                            >
                              {Icon !== undefined && <Icon className="size-[18px]" aria-hidden="true" />}
                              <span className="md:sr-only">{destination.label}</span>
                            </a>
                          </SidebarMenuButton>
                        </SidebarMenuItem>
                      );
                    })}
                  </SidebarMenu>
                </SidebarGroupContent>
              </SidebarGroup>
            </div>
          ))}
        </nav>
      </SidebarContent>
    </Sidebar>
  );
}
