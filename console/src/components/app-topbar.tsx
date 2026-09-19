import type { JSX } from 'react';
import {
  ChevronDownIcon,
  FingerprintIcon,
  CopyIcon,
  LogOutIcon,
  Settings2Icon,
  UserRoundIcon,
} from 'lucide-react';
import { DropdownMenu } from 'radix-ui';
import type { Session } from '@/api';
import { TenantSwitcher } from '@/components/tenant-switcher';
import { Button } from '@/components/ui/button';
import { SidebarTrigger } from '@/components/ui/sidebar';
import { toast } from '@/components/ui/toast';
import { hrefOf } from '@/routes';
import { sessionRoleLabel } from '@/session-label';

export function AppTopbar({
  session,
  page,
  onSignOut,
}: {
  session: Session;
  page: string;
  onSignOut: () => void;
}): JSX.Element {
  return (
    <header className="app-topbar">
      <a className="skip" href="#content" onClick={(event) => {
        event.preventDefault();
        document.getElementById('content')?.focus();
      }}>Skip to content</a>
      <div className="topbar-context">
        <SidebarTrigger className="md:hidden" />
        <a className="topbar-product" href={hrefOf('overview')}>
          <FingerprintIcon aria-hidden="true" /><span className="asterius-wordmark">asterius<span>Identity control</span></span><h1 className="visually-hidden">Asterius console</h1>
        </a>
        <span className="topbar-divider" aria-hidden="true" />
        <TenantSwitcher session={session} className="topbar-tenant" />

        <span className="topbar-location" aria-current="page">{page}</span>
      </div>

      <div className="topbar-actions">
        <AccountMenu session={session} onSignOut={onSignOut} />
      </div>
    </header>
  );
}

function AccountMenu({
  session,
  onSignOut,
}: {
  session: Session;
  onSignOut: () => void;
}): JSX.Element {
  const copyIdentifier = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(session.user);
      toast.success('Account identifier copied');
    } catch {
      toast.error('Could not copy the account identifier');
    }
  };

  return (
    <DropdownMenu.Root modal={false}>
      <DropdownMenu.Trigger asChild>
        <Button variant="ghost" className="topbar-account" aria-label="Account menu">
          <span className="topbar-avatar" aria-hidden="true">
            <UserRoundIcon />
          </span>
          <span className="topbar-user-copy">
            <strong title={session.user}>{session.user}</strong>
            <span>{sessionRoleLabel(session)}</span>
          </span>
          <ChevronDownIcon className="size-4 opacity-60" aria-hidden="true" />
        </Button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content className="account-menu" side="bottom" align="end" sideOffset={8}>
          <DropdownMenu.Label className="account-menu-label">
            <strong>{session.user}</strong>
            <span>{sessionRoleLabel(session)}</span>
          </DropdownMenu.Label>
          <DropdownMenu.Item asChild className="account-menu-item">
            <a href={hrefOf('preferences')}>
              <Settings2Icon aria-hidden="true" />Preferences
            </a>
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
  );
}
