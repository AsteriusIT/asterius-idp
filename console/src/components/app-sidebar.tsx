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
  ChevronsUpDownIcon,
  CopyIcon,
  UserRoundIcon,
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
import { DropdownMenu } from 'radix-ui';
import { toast } from '@/components/ui/toast';
import { sessionRoleLabel } from '@/session-label';
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
  useSidebar,
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
  const { setOpenMobile } = useSidebar();

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
                          className="console-nav-link"
                        >
                          <a
                            href={hrefOf(destination.route)}
                            onClick={() => setOpenMobile(false)}
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
        <AccountMenu session={session} onSignOut={onSignOut} />
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}

/** One account control works in the full rail, icon rail and mobile drawer. */
function AccountMenu({ session, onSignOut }: {
  session: Session;
  onSignOut: () => void;
}): JSX.Element {
  const theme = useSyncExternalStore(subscribe, themeNow, themeNow);
  const next = theme === 'dark' ? 'light' : 'dark';
  const { isMobile } = useSidebar();
  const copyIdentifier = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(session.user);
      toast.success('Account identifier copied');
    } catch {
      toast.error('Could not copy the account identifier');
    }
  };
  return (
    <SidebarMenu>
      <SidebarMenuItem>
        {/* This is an action menu, not a modal: keep surrounding navigation
            available to assistive technology and ordinary Tab navigation. */}
        <DropdownMenu.Root modal={false}>
          <DropdownMenu.Trigger asChild>
            <SidebarMenuButton size="lg" tooltip="Account menu" aria-label="Account menu">
              <span className="flex size-8 shrink-0 items-center justify-center rounded-md bg-accent" aria-hidden="true">
                <UserRoundIcon className="size-4" />
              </span>
              <span className="flex min-w-0 flex-1 flex-col text-left group-data-[collapsible=icon]:hidden">
                <span className="truncate text-sm font-medium" title={session.user}>{session.user}</span>
                <span className="truncate text-xs text-foreground">{sessionRoleLabel(session)}</span>
              </span>
              <ChevronsUpDownIcon className="ml-auto size-4 group-data-[collapsible=icon]:hidden" aria-hidden="true" />
            </SidebarMenuButton>
          </DropdownMenu.Trigger>
          <DropdownMenu.Portal>
            <DropdownMenu.Content className="account-menu" side={isMobile ? 'top' : 'right'} align="end" sideOffset={8}>
              <DropdownMenu.Label className="account-menu-label">Signed in account</DropdownMenu.Label>
              <DropdownMenu.Item className="account-menu-item" onSelect={() => setTheme(next)} aria-label={`Switch to the ${next} theme`}>
                {theme === 'dark' ? <SunIcon aria-hidden="true" /> : <MoonIcon aria-hidden="true" />}
                {theme === 'dark' ? 'Light theme' : 'Dark theme'}
              </DropdownMenu.Item>
              <DropdownMenu.Item className="account-menu-item" onSelect={() => { void copyIdentifier(); }}>
                <CopyIcon aria-hidden="true" />Copy account identifier
              </DropdownMenu.Item>
              <DropdownMenu.Separator className="account-menu-separator" />
              <DropdownMenu.Item className="account-menu-item" onSelect={onSignOut}>
                <LogOutIcon aria-hidden="true" />Sign out
              </DropdownMenu.Item>
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
      </SidebarMenuItem>
    </SidebarMenu>
  );
}
