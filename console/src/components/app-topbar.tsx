import { useState, type JSX } from 'react';
import {
  ArrowUpRightIcon,
  HeartPulseIcon,
  BookOpenIcon,
  NetworkIcon,
  FlaskConicalIcon,
  ShieldCheckIcon,
  CopyIcon,
  ChevronDownIcon,
  FingerprintIcon,
  LogOutIcon,
  Settings2Icon,
  UserRoundIcon,
} from 'lucide-react';
import { DropdownMenu } from '@/components/ui/dropdown-menu';
import type { Session } from '@/api';
import { TenantSwitcher } from '@/components/tenant-switcher';
import { Button, buttonVariants } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { routeOf } from '@/routes';
import { Tooltip, TooltipTrigger, TooltipContent } from '@/components/ui/tooltip';
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
        {reaches(session, DESTINATIONS.find(item => item.route === 'token-console')!) && <Tooltip>
          <TooltipTrigger render={<a href={hrefOf('token-console')} className={cn(buttonVariants({ variant: 'ghost', size: 'icon' }), 'topbar-tool-link')}
            aria-label="Token test console" aria-current={routeOf(window.location.hash) === 'token-console' ? 'page' : undefined}>
            <FlaskConicalIcon aria-hidden="true" />
          </a>} />
          <TooltipContent side="bottom">Token test console</TooltipContent>
        </Tooltip>}
        {reaches(session, DESTINATIONS.find(item => item.route === 'architecture')!) && <Button render={<a href={hrefOf('architecture')} />} nativeButton={false} role="link" variant="ghost" size="icon" title="Architecture builder" aria-label="Architecture builder"><NetworkIcon data-icon="inline-start" aria-hidden="true" /></Button>}
        <Button render={<a href={hrefOf('help')} />} nativeButton={false} role="link" variant="ghost" size="icon" title="Help and guides" aria-label="Help and guides"><BookOpenIcon data-icon="inline-start" aria-hidden="true" /></Button>
        <Button render={<a href={hrefOf('health')} />} nativeButton={false} role="link" variant="ghost" size="icon" title="Workspace health" aria-label="Workspace health"><HeartPulseIcon data-icon="inline-start" aria-hidden="true" /></Button>
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
      <DropdownMenu.Trigger render={<Button variant="ghost" className="topbar-account" aria-label="Account menu">
          <span className="topbar-avatar" aria-hidden="true">
            {session.username.trim().slice(0, 1).toUpperCase() || <UserRoundIcon />}
          </span>
          <span className="topbar-user-copy">
            <strong title={session.username}>{session.username}</strong>
            <span>{sessionRoleLabel(session)}</span>
          </span>
          <ChevronDownIcon className="size-4 opacity-60" aria-hidden="true" />
        </Button>} />
      <DropdownMenu.Portal>
        <DropdownMenu.Content className="account-menu" aria-label="Account menu" side="bottom" align="end" sideOffset={10} collisionPadding={12}>
          <DropdownMenu.Group><DropdownMenu.GroupLabel className="account-menu-identity">
            <span className="account-menu-avatar" aria-hidden="true">{session.username.trim().slice(0, 1).toUpperCase() || <UserRoundIcon />}</span>
            <span className="account-menu-person">
              <strong>{session.username}</strong>
              <span><ShieldCheckIcon aria-hidden="true" />{sessionRoleLabel(session)}</span>
            </span>
          </DropdownMenu.GroupLabel></DropdownMenu.Group>
          <DropdownMenu.Group className="account-menu-actions">
            <DropdownMenu.LinkItem className="account-menu-item account-menu-account" render={<a href="/t/admin/account">
                <UserRoundIcon aria-hidden="true" />
                <span><strong>My account</strong><small>Profile, security and sessions</small></span>
                <ArrowUpRightIcon className="account-menu-trailing" aria-hidden="true" />
              </a>} />
            <DropdownMenu.LinkItem className="account-menu-item" render={<a href={hrefOf('preferences')}><Settings2Icon aria-hidden="true" /><span>Preferences</span></a>} />
            <DropdownMenu.Item className="account-menu-item account-menu-copy" onClick={() => void copyIdentifier()}>
              <CopyIcon aria-hidden="true" />
              <span><span>Copy account identifier</span><code title={session.user}>{session.user}</code></span>
            </DropdownMenu.Item>
          </DropdownMenu.Group>
          <DropdownMenu.Separator className="account-menu-separator" />
          <DropdownMenu.Group className="account-menu-footer">
            <DropdownMenu.Item className="account-menu-item account-menu-signout" onClick={onSignOut}>
              <LogOutIcon aria-hidden="true" /><span>Sign out</span>
            </DropdownMenu.Item>
          </DropdownMenu.Group>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root></>;
}
