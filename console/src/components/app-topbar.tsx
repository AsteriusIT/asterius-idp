import { useState, type JSX } from 'react';
import {
  ArrowUpRightIcon,
  HeartPulseIcon,
  BookOpenIcon,
  NetworkIcon,
  ShieldCheckIcon,
  CopyIcon,
  ChevronDownIcon,
  FingerprintIcon,
  LogOutIcon,
  Settings2Icon,
  UserRoundIcon,
} from 'lucide-react';
import { DropdownMenu } from 'radix-ui';
import type { Session } from '@/api';
import { TenantSwitcher } from '@/components/tenant-switcher';
import { Button } from '@/components/ui/button';
import { SidebarTrigger } from '@/components/ui/sidebar';
import { hrefOf } from '@/routes';
import { reaches, DESTINATIONS } from '@/navigation';
import { sessionRoleLabel } from '@/session-label';

export function AppTopbar({
  session,
  page,
  onSignOut,
}: Readonly<{
  session: Session;
  page: string;
  onSignOut: () => void;
}>): JSX.Element {
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
        {reaches(session, DESTINATIONS.find(item => item.route === 'architecture')!) && <Button asChild variant="ghost" size="icon" title="Architecture builder" aria-label="Architecture builder"><a href={hrefOf('architecture')}><NetworkIcon aria-hidden="true" /></a></Button>}
        <Button asChild variant="ghost" size="icon" title="Help and guides" aria-label="Help and guides"><a href={hrefOf('help')}><BookOpenIcon aria-hidden="true" /></a></Button>
        <Button asChild variant="ghost" size="icon" title="Workspace health" aria-label="Workspace health"><a href={hrefOf('health')}><HeartPulseIcon aria-hidden="true" /></a></Button>
        <AccountMenu session={session} onSignOut={onSignOut} />
      </div>
    </header>
  );
}

function AccountMenu({
  session,
  onSignOut,
}: Readonly<{
  session: Session;
  onSignOut: () => void;
}>): JSX.Element {
  const [copyNotice, setCopyNotice] = useState('');
  const copyIdentifier = async () => {
    try { await navigator.clipboard.writeText(session.user); setCopyNotice('Account identifier copied.'); }
    catch { setCopyNotice(`Copy unavailable. Account identifier: ${session.user}`); }
  };
  return <><span className="sr-only" aria-live="polite">{copyNotice}</span>
    <DropdownMenu.Root modal={false}>
      <DropdownMenu.Trigger asChild>
        <Button variant="ghost" className="topbar-account" aria-label="Account menu">
          <span className="topbar-avatar" aria-hidden="true">
            {session.username.trim().slice(0, 1).toUpperCase() || <UserRoundIcon />}
          </span>
          <span className="topbar-user-copy">
            <strong title={session.username}>{session.username}</strong>
            <span>{sessionRoleLabel(session)}</span>
          </span>
          <ChevronDownIcon className="size-4 opacity-60" aria-hidden="true" />
        </Button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content className="account-menu" aria-label="Account actions" side="bottom" align="end" sideOffset={10} collisionPadding={12}>
          <DropdownMenu.Label className="account-menu-identity">
            <span className="account-menu-avatar" aria-hidden="true">{session.username.trim().slice(0, 1).toUpperCase() || <UserRoundIcon />}</span>
            <span className="account-menu-person">
              <strong>{session.username}</strong>
              <span><ShieldCheckIcon aria-hidden="true" />{sessionRoleLabel(session)}</span>
            </span>
          </DropdownMenu.Label>
          <DropdownMenu.Group className="account-menu-actions">
            <DropdownMenu.Item asChild className="account-menu-item account-menu-account">
              <a href="/t/admin/account">
                <UserRoundIcon aria-hidden="true" />
                <span><strong>My account</strong><small>Profile, security and sessions</small></span>
                <ArrowUpRightIcon className="account-menu-trailing" aria-hidden="true" />
              </a>
            </DropdownMenu.Item>
            <DropdownMenu.Item asChild className="account-menu-item">
              <a href={hrefOf('preferences')}><Settings2Icon aria-hidden="true" /><span>Preferences</span></a>
            </DropdownMenu.Item>
            <DropdownMenu.Item className="account-menu-item account-menu-copy" onSelect={() => void copyIdentifier()}>
              <CopyIcon aria-hidden="true" />
              <span><span>Copy account identifier</span><code title={session.user}>{session.user}</code></span>
            </DropdownMenu.Item>
          </DropdownMenu.Group>
          <DropdownMenu.Separator className="account-menu-separator" />
          <DropdownMenu.Group className="account-menu-footer">
            <DropdownMenu.Item className="account-menu-item account-menu-signout" onSelect={onSignOut}>
              <LogOutIcon aria-hidden="true" /><span>Sign out</span>
            </DropdownMenu.Item>
          </DropdownMenu.Group>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root></>;
}
