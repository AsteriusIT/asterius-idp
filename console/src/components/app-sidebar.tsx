/**
 * The console's navigation, which is now the whole of it (`ast-gore` (3)).
 *
 * Until this bead there were two: a sticky header carrying the mark, the
 * wordmark and the session, and a rail carrying the destinations. The header
 * is gone. Everything that was in it — who is signed in, which tenant, how to
 * leave — is in the rail, because a console with one navigation has one place
 * to look and one tab order to walk, and the header's row of links was the
 * part that broke first on a narrow window.
 *
 * What the rail does:
 *
 *  - **Groups** the nine screens under five headings (`navigation.ts`), so the
 *    list is read by what it is about rather than from the top every time.
 *  - **Folds** to icons (`Ctrl`/`⌘`+`B`, or the rail's own edge control), with
 *    every label still reachable as a tooltip and as the button's accessible
 *    name.
 *  - **Becomes a drawer** below the mobile breakpoint (`Sheet`), which is what
 *    makes a phone usable at all.
 *  - Carries the **tenant selector** at the top and the **session** at the
 *    bottom: the two things an administrator checks before they act.
 *
 * The links are still `<a href="#/route">` and still filtered by
 * `visibleTo`. Neither is decoration: the fragment is what keeps the document
 * URL — and therefore every relative API URL — where it is (`routes.ts`), and
 * the filter is a courtesy the server re-checks (`navigation.ts`).
 */
import type { JSX } from 'react';
import { useSyncExternalStore } from 'react';
import {
  AppWindowIcon,
  Building2Icon,
  KeyRoundIcon,
  LayoutDashboardIcon,
  LogOutIcon,
  MoonIcon,
  RadioIcon,
  ScaleIcon,
  ScrollTextIcon,
  SettingsIcon,
  SunIcon,
  UsersIcon,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import type { Session } from '@/api';
import { TenantSwitcher } from '@/components/tenant-switcher';
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
  SidebarSeparator,
} from '@/components/ui/sidebar';
import { sectionsFor } from '@/navigation';
import { hrefOf } from '@/routes';
import { setTheme, subscribe, themeNow } from '@/theme';

/**
 * The icon beside each destination.
 *
 * Kept here rather than in `navigation.ts`: that module is the authority a
 * screen is allowed to ask about scopes, and it has no business importing a
 * React component. A route with no icon simply gets none.
 */
const ICONS: Readonly<Record<string, LucideIcon>> = {
  overview: LayoutDashboardIcon,
  users: UsersIcon,
  clients: AppWindowIcon,
  keys: KeyRoundIcon,
  policy: ScaleIcon,
  ssf: RadioIcon,
  audit: ScrollTextIcon,
  tenants: Building2Icon,
  settings: SettingsIcon,
};

export function AppSidebar({
  session,
  current,
  onSignOut,
}: {
  session: Session;
  current: string;
  onSignOut: () => void;
}): JSX.Element {
  const sections = sectionsFor(session);

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader className="gap-2">
        <div className="flex items-center gap-2 px-2 pt-1">
          <span
            className="flex size-7 shrink-0 items-center justify-center rounded-md bg-primary text-sm font-semibold text-primary-foreground"
            aria-hidden="true"
          >
            A
          </span>
          {/* The console's one `<h1>`. The screens are its sections and open
              at `<h2>`, which is the heading order `ui.tsx` already assumed. */}
          <h1 className="truncate text-sm font-semibold group-data-[collapsible=icon]:hidden">
            Asterius console
          </h1>
        </div>
        <TenantSwitcher session={session} />
      </SidebarHeader>

      <SidebarContent>
        {/* A real `<nav>`, and the same accessible name the rail carried
            before `ast-gore`. shadcn's `Sidebar` is a stack of `<div>`s — it
            makes no claim about landmarks — and the console's destinations are
            a navigation landmark whether they are drawn in a rail or a drawer.
            The browser sweep looks for it by that name. */}
        <nav aria-label="Console sections" className="flex flex-col gap-2">
          {sections.map((section) => (
            <SidebarGroup key={section.group}>
              {/* The group of one is drawn without its heading; see `Group`. */}
              {section.group !== 'Overview' && (
                <SidebarGroupLabel>{section.group}</SidebarGroupLabel>
              )}
              <SidebarGroupContent>
                <SidebarMenu>
                  {section.destinations.map((destination) => {
                    const Icon = ICONS[destination.route];
                    const active = destination.route === current;
                    return (
                      <SidebarMenuItem key={destination.route}>
                        <SidebarMenuButton
                          asChild
                          isActive={active}
                          tooltip={destination.label}
                        >
                          <a
                            href={hrefOf(destination.route)}
                            aria-current={active ? 'page' : undefined}
                          >
                            {Icon !== undefined && <Icon aria-hidden="true" />}
                            <span>{destination.label}</span>
                          </a>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                    );
                  })}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          ))}
        </nav>
      </SidebarContent>

      <SidebarFooter>
        <SidebarSeparator />
        <SidebarMenu>
          <SidebarMenuItem>
            <ThemeToggle />
          </SidebarMenuItem>
          <SidebarMenuItem>
            <SidebarMenuButton
              onClick={onSignOut}
              tooltip={`Sign out of ${session.user}`}
            >
              <LogOutIcon aria-hidden="true" />
              <span className="truncate">Sign out</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
        <p className="truncate px-2 pb-1 text-xs text-muted-foreground group-data-[collapsible=icon]:hidden">
          {session.user}
        </p>
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}

/**
 * Light or dark, as one button (`ast-gore` (2)).
 *
 * A switch and not a menu: there are two schemes and no "system", so a menu
 * would be a list of two with a third answer nobody wanted. The label says
 * what pressing it *does*, which is what a screen reader announces.
 */
function ThemeToggle(): JSX.Element {
  const theme = useSyncExternalStore(subscribe, themeNow, themeNow);
  const next = theme === 'dark' ? 'light' : 'dark';
  return (
    <SidebarMenuButton
      onClick={() => setTheme(next)}
      tooltip={`Switch to the ${next} theme`}
      aria-label={`Switch to the ${next} theme`}
    >
      {theme === 'dark' ? <SunIcon aria-hidden="true" /> : <MoonIcon aria-hidden="true" />}
      <span className="truncate">{theme === 'dark' ? 'Light theme' : 'Dark theme'}</span>
    </SidebarMenuButton>
  );
}
