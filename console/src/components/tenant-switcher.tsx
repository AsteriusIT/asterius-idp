/**
 * The tenant selector (`ast-gore` (4)).
 *
 * # What it is
 *
 * A combobox in the application topbar: the tenant this session is signed in to,
 * and — when the session may see them — every other tenant of the deployment,
 * searchable, keyboard-driven (`Command` over `Popover`), opened from anywhere
 * with `Ctrl`/`⌘`+`K`.
 *
 * # Where the list comes from, and why there is no new call
 *
 * `GET /tenants`, which the Tenants screen already reads and which
 * `crates/admin-api/src/rbac.rs` admits only to a **deployment**-scoped caller.
 * So the two cases are:
 *
 *  - *deployment administrator* — holds `admin.tenants:read` at deployment
 *    reach, the list is read, and every tenant is offered;
 *  - *tenant administrator* — holds the same scope over their own tenant only,
 *    the call is **not made** (it would be a 403 drawn as a broken menu), and
 *    the control shows the one tenant they administer and says so.
 *
 * That test is `deployment_scopes`, exactly as `navigation.ts` does it, and
 * nothing here is a permission check: the server re-authorises the read, and a
 * console that offered every tenant to everybody would leak a list of names
 * and no access.
 *
 * # What switching does
 *
 * It navigates to `{issuer}/admin/#/overview` — the *other tenant's own
 * console* — and that is the whole mechanism.
 *
 * The console is not multi-tenant in one page and must not become one: a
 * session belongs to exactly one tenant (`ADR-0010`, `ast-1cj`), the console is
 * mounted beneath the tenant it serves (`/t/{id}/admin/`, or the root of a
 * custom host), and every admin API call it makes is relative to *its own*
 * document URL. A selector that swapped a tenant id into the state of this page
 * would leave those calls pointing at the first tenant's API. Sending the
 * browser to the other console makes the tenant a property of the document
 * again. On a shared origin, the reserved tenant's `__Host-` cookie reaches
 * the path-based tenant and the entry guard admits only its deployment-scoped
 * role (`ast-w4g3`). A custom-host origin receives no such cookie and therefore
 * opens the ordinary local login (`ast-wr4`); no credential is transferred
 * between origins.
 *
 * The URL is built by `tenantConsoleUrl` from the **issuer** the API reports
 * and from nothing this page knows about itself, because a tenant reached
 * through a custom host has no `/t/{id}` prefix to copy.
 *
 * The landing screen is **Overview**, deliberately, and not the screen the
 * operator was on: what this session may reach in the other tenant is not
 * known here — it is decided by the roles held *there* — so the one screen
 * that is certain to answer is the one that names who you are and what you
 * reach. See `docs/console/README.md`.
 */
import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { hrefOf } from '@/routes';
import { sessionRoleLabel } from '@/session-label';
import { BuildingIcon, CheckIcon, ChevronsUpDownIcon, SettingsIcon } from 'lucide-react';
import { read, type Session } from '@/api';
import { Button } from '@/components/ui/button';
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { type TenantPage, type TenantRow, tenantConsoleUrl } from '@/tenants';
import { cn } from '@/lib/utils';

/** Where a switch lands. See the module docs for why it is not the current route. */
export const LANDING_ROUTE = 'overview';

/** Whether this session may be offered the deployment's other tenants. */
export function maySwitch(session: Session): boolean {
  return session.deployment_scopes.includes('admin.tenants:read');
}

/** What the list is doing. */
type Load =
  | { readonly kind: 'idle' }
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly tenants: readonly TenantRow[] }
  | { readonly kind: 'failed'; readonly message: string };

export function TenantSwitcher({
  session,
  className,
}: Readonly<{
  session: Session;
  className?: string;
}>): JSX.Element {
  const [open, setOpen] = useState(false);
  const [load, setLoad] = useState<Load>({ kind: 'idle' });
  const switchable = maySwitch(session);

  // Read when the menu opens, and not before: the shell draws on every screen
  // and a list nobody asked for is a call nobody asked for.
  useEffect(() => {
    if (!open || !switchable || load.kind !== 'idle') {
      return;
    }
    setLoad({ kind: 'loading' });
    read('tenants').then(
      (value) => setLoad({ kind: 'ready', tenants: (value as TenantPage).items }),
      (error: unknown) =>
        setLoad({
          kind: 'failed',
          message: error instanceof Error ? error.message : 'the tenants could not be read',
        }),
    );
  }, [open, switchable, load.kind]);

  // `Ctrl`/`⌘`+`K` from anywhere, which is where an operator's hands already
  // are. `⌘` as well as `Ctrl` because this console is used on both.
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key.toLowerCase() === 'k' && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        setOpen((current) => !current);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  const go = useCallback((tenant: TenantRow) => {
    // A full navigation, on purpose: the other tenant's console is another
    // document with another session. See the module docs.
    window.location.assign(tenantConsoleUrl(tenant.issuer, LANDING_ROUTE));
  }, []);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          role="combobox"
          aria-expanded={open}
          aria-label={`Tenant: ${session.workspace}. Switch tenant`}
          // `min-w-0 overflow-hidden`: the trigger is as wide as the rail and
          // its middle column is the only thing allowed to grow (`ast-f9j5`).
          // Without it a long tenant name pushed the chevron past the rail's
          // edge, where it was clipped.
          className={cn(
            'h-auto w-full min-w-0 justify-start gap-2 overflow-hidden px-2 py-1.5 text-left',
            className,
          )}
          title="Switch tenant (Ctrl+K)"
        >
          <BuildingIcon className="size-4 shrink-0" aria-hidden="true" />
          <span className="flex min-w-0 flex-1 flex-col">
            <span className="truncate text-sm font-medium">{session.workspace}</span>
            <span className="tenant-context-label">Workspace</span>
          </span>
          <ChevronsUpDownIcon
            className="size-4 shrink-0 opacity-60"
            aria-hidden="true"
          />
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="tenant-menu w-(--radix-popover-trigger-width) min-w-64 p-0">
        <div className="tenant-menu-heading"><strong>{session.workspace}</strong><span>{sessionRoleLabel(session)}</span></div>
        <Command>
          {switchable && <CommandInput placeholder="Find a tenant…" />}
          <CommandList>
            {!switchable && (
              <div className="p-3 text-sm text-muted-foreground">
                You have access to this tenant. Contact a deployment administrator to access another tenant.
              </div>
            )}
            {switchable && load.kind === 'loading' && (
              <div className="p-3 text-sm text-muted-foreground" aria-live="polite">
                Reading the tenants.
              </div>
            )}
            {switchable && load.kind === 'failed' && (
              <div className="p-3 text-sm text-destructive" role="alert">
                {load.message}
              </div>
            )}
            {switchable && load.kind === 'ready' && (
              <>
                <CommandEmpty>No tenant of that name.</CommandEmpty>
                <CommandGroup heading="Tenants">
                  {load.tenants.map((tenant) => (
                    <CommandItem
                      key={tenant.tenant_id}
                      value={`${tenant.tenant_id} ${tenant.display_name}`}
                      onSelect={() => go(tenant)}
                    >
                      <CheckIcon
                        className={
                          tenant.tenant_id === session.workspace
                            ? 'size-4 opacity-100'
                            : 'size-4 opacity-0'
                        }
                        aria-hidden="true"
                      />
                      {/* The name and the id are one line and not two
                          columns: an id set against the far edge of the menu
                          reads as a second, unrelated label. */}
                      <span className="min-w-0 flex-1 truncate">
                        {tenant.display_name}
                        <span className="ml-1.5 text-xs text-muted-foreground">
                          {tenant.tenant_id}
                        </span>
                      </span>
                      {tenant.status === 'disabled' && (
                        <span className="text-xs text-muted-foreground">suspended</span>
                      )}
                    </CommandItem>
                  ))}
                </CommandGroup>
              </>
            )}
          </CommandList>
        </Command>
        {session.scopes.includes('admin.tenants:write') && (
          <a
            className="tenant-menu-settings"
            href={hrefOf('settings')}
            onClick={() => setOpen(false)}
          >
            <SettingsIcon aria-hidden="true" />
            Tenant settings
          </a>
        )}
      </PopoverContent>
    </Popover>
  );
}
