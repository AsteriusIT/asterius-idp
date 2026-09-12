import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { ApiError, endSession, loadSession, type Session } from './api';
import { AuditExplorer } from './audit';
import { Clients } from './clients';
import { AppSidebar } from './components/app-sidebar';
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from './components/ui/breadcrumb';
import { Separator } from './components/ui/separator';
import {
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from './components/ui/sidebar';
import { Toaster, toast } from './components/ui/toast';
import { Keys } from './keys';
import { DESTINATIONS, visibleTo } from './navigation';
import { Policy } from './policy';
import { hrefOf, paramsOf, routeOf } from './routes';
import { TenantSettings } from './settings';
import { Tenants } from './tenants';
import { SharedSignals } from './ssf';
import { Badge, Button, CenteredCard, Panel, Screen } from './ui';
import { Users } from './users';

/**
 * What the shell is doing, as one value.
 *
 * `signed-out` is a state and not an error, because it has its own screen and
 * its own action: the API answered 401, so whatever the console was showing is
 * no longer backed by a session and must not be left on screen.
 */
type Shell =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly session: Session }
  | { readonly kind: 'signed-out' }
  | { readonly kind: 'failed'; readonly message: string };

export function App(): JSX.Element {
  const [shell, setShell] = useState<Shell>({ kind: 'loading' });
  // The whole fragment and not just the route it names: a fragment may carry
  // parameters (`#/settings?tenant=acme`, `ast-l5bl`), and a state that held
  // only the route would drop them on every hash change.
  const [fragment, setFragment] = useState(() => window.location.hash);
  const route = routeOf(fragment);

  useEffect(() => {
    const onHashChange = (): void => setFragment(window.location.hash);
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  const probe = useCallback(() => {
    setShell({ kind: 'loading' });
    loadSession().then(
      (session) => setShell({ kind: 'ready', session }),
      (error: unknown) => {
        if (error instanceof ApiError && error.isUnauthenticated) {
          setShell({ kind: 'signed-out' });
          return;
        }
        setShell({
          kind: 'failed',
          message: error instanceof Error ? error.message : 'the console could not start',
        });
      },
    );
  }, []);

  useEffect(probe, [probe]);

  /**
   * Ends the session, then shows the signed-out screen.
   *
   * The server does the ending — the cookie is `HttpOnly` — and this state
   * change only follows it. A refusal still lands on the signed-out screen:
   * whatever went wrong, the administrator asked to leave, and leaving a
   * console showing a tenant's configuration behind a failed logout is the
   * outcome the button exists to prevent. The screen's "Check again" re-reads
   * the session, so a logout that did not take is one click from being seen.
   */
  const signOut = useCallback((session: Session) => {
    setShell({ kind: 'loading' });
    endSession(session).then(
      () => setShell({ kind: 'signed-out' }),
      () => {
        toast.error('The server did not confirm the sign-out', 'The console was left anyway.');
        setShell({ kind: 'signed-out' });
      },
    );
  }, []);

  if (shell.kind === 'loading') {
    return (
      <CenteredCard heading="Loading">
        {/* `aria-live` and no `role`, for the reason `Skeleton` gives: the
            status role is what the sweep searches for to tell a saved change
            from a refused one, and "Reading the session" is neither. */}
        <p className="muted" aria-live="polite">
          Reading the session.
        </p>
      </CenteredCard>
    );
  }
  if (shell.kind === 'signed-out') {
    return <SignedOut onRetry={probe} />;
  }
  if (shell.kind === 'failed') {
    return (
      <CenteredCard heading="The console could not start">
        <p className="muted">{shell.message}</p>
      </CenteredCard>
    );
  }

  const destinations = visibleTo(shell.session);
  const current = destinations.some((destination) => destination.route === route)
    ? route
    : (destinations[0]?.route ?? route);
  const here = DESTINATIONS.find((destination) => destination.route === current);

  /**
   * The shell since `ast-gore`: a sidebar, and a bar that says where you are.
   *
   * There is no navigation header any more — the rail is the whole navigation
   * — so the bar above the content carries exactly three things: the control
   * that folds the rail, the trail that says which screen this is, and nothing
   * else. It stays on a narrow window, where the rail has become a drawer and
   * the trigger is the only way back to it.
   */
  return (
    <SidebarProvider>
      <a
        className="skip"
        href={`${hrefOf(current)}`}
        onClick={focusMain}
      >
        Skip to content
      </a>
      <AppSidebar
        session={shell.session}
        current={current}
        onSignOut={() => signOut(shell.session)}
      />
      <SidebarInset>
        <header className="sticky top-0 z-10 flex h-14 shrink-0 items-center gap-2 border-b bg-background px-4">
          <SidebarTrigger className="-ml-1" />
          <Separator orientation="vertical" className="mr-2 !h-4" />
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem className="hidden sm:block">{shell.session.tenant}</BreadcrumbItem>
              {here !== undefined && here.group !== 'Overview' && (
                <>
                  <BreadcrumbSeparator className="hidden sm:block" />
                  <BreadcrumbItem className="hidden sm:block">{here.group}</BreadcrumbItem>
                </>
              )}
              <BreadcrumbSeparator className="hidden sm:block" />
              <BreadcrumbItem>
                <BreadcrumbPage>{here?.label ?? 'Not found'}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        </header>
        <main id="content" tabIndex={-1} className="content">
          <RouteScreen route={current} fragment={fragment} session={shell.session} />
        </main>
      </SidebarInset>
      <Toaster />
    </SidebarProvider>
  );
}

/** Moves keyboard focus to the content, which a fragment link alone does not. */
function focusMain(): void {
  document.getElementById('content')?.focus();
}

/**
 * The screen for one route.
 *
 * The ones that are still placeholders name the bead that will fill them in,
 * and that bead must be an *open* one: `ast-f7m.3`'s scaffold tagged this
 * screen with `ast-f7m.4`, which had shipped as tenant settings, so an
 * administrator opening Users read that it was arriving with a ticket that was
 * already closed. See `navigation.ts`.
 */
function RouteScreen({
  route,
  fragment,
  session,
}: {
  route: string;
  fragment: string;
  session: Session;
}): JSX.Element {
  if (route === 'users') {
    return <Users session={session} />;
  }
  if (route === 'clients') {
    return <Clients session={session} />;
  }
  if (route === 'keys') {
    return <Keys session={session} />;
  }
  if (route === 'settings') {
    // The subject is the session's own tenant unless the Tenants screen named
    // another one, which only a deployment-scoped caller can have reached.
    return <TenantSettings session={session} tenant={paramsOf(fragment).get('tenant')} />;
  }
  if (route === 'tenants') {
    return <Tenants session={session} />;
  }
  if (route === 'ssf') {
    return <SharedSignals session={session} />;
  }
  if (route === 'audit') {
    return <AuditExplorer session={session} />;
  }
  if (route === 'policy') {
    return <Policy session={session} />;
  }
  if (route === 'overview') {
    return <Overview session={session} />;
  }

  const destination = visibleTo(session).find((candidate) => candidate.route === route);
  return (
    <Screen
      title={destination?.label ?? 'Not found'}
      description={`This screen arrives with ${destination?.bead ?? 'a later bead'}.`}
    >
      <Panel title="Not built yet">
        <p className="muted">
          Nothing on this screen works yet, and the ticket above is where the work is
          tracked.
        </p>
      </Panel>
    </Screen>
  );
}

/**
 * Where the console opens: who you are here, and what that lets you reach.
 *
 * It answers the question an administrator asks first — "why can I not see
 * Clients?" — by naming the roles the session carries and the screens they open,
 * rather than leaving the rail's absences unexplained. Every value comes from
 * `GET /session`, which the shell has already read: the overview makes no call
 * of its own.
 */
function Overview({ session }: { session: Session }): JSX.Element {
  const destinations = visibleTo(session);
  return (
    <Screen title="Overview" description="Who this session is, and what it reaches.">
      <Panel title="This session">
        <dl className="stats">
          <div className="stat">
            <dt>Tenant</dt>
            <dd>{session.tenant}</dd>
          </div>
          <div className="stat">
            <dt>User</dt>
            <dd className="wrap-anywhere">{session.user}</dd>
          </div>
          <div className="stat">
            <dt>Roles</dt>
            <dd>
              {session.roles.length > 0 ? (
                <span className="row">
                  {session.roles.map((role) => (
                    <Badge key={role} tone="accent">
                      {role}
                    </Badge>
                  ))}
                </span>
              ) : (
                'none'
              )}
            </dd>
          </div>
        </dl>
      </Panel>
      <Panel
        title="What you can reach"
        description="A screen is listed when this session holds the scope its first call needs. The server checks every one of them again."
      >
        {/*
          Names and not links, deliberately. The sidebar beside this panel is
          the console's one navigation; a second set of links to the same nine
          screens would be a second place for a keyboard user to tab through,
          and two controls carrying one accessible name on one page.
        */}
        <ul className="switches">
          {destinations.map((destination) => (
            <li key={destination.route}>
              <strong>{destination.label}</strong>{' '}
              <span className="muted">{destination.scope}</span>
            </li>
          ))}
        </ul>
      </Panel>
    </Screen>
  );
}

/**
 * What the console shows when the API says 401.
 *
 * The button reloads *this* document, and that is the whole entry: since
 * `ast-wr4` the server guards `/admin/`, so a request for it without a session
 * opens a first-party interaction and answers with the ordinary login page.
 * No URL is constructed here — `location.reload()` asks for the address the
 * browser is already at, so the tenant prefix comes along and nothing in this
 * bundle has to know what it was. It is not `location.href = …` for the same
 * reason: a page that assembles its own sign-in URL is a page that can be
 * talked into assembling somebody else's.
 *
 * A session that ends mid-visit is the case that gets here now; a visitor with
 * no session never sees the shell at all.
 */
function SignedOut({ onRetry }: { onRetry: () => void }): JSX.Element {
  return (
    <CenteredCard heading="Signed out">
      <p className="muted">This console has no session. Sign in again to continue.</p>
      <Button variant="primary" onClick={() => window.location.reload()}>
        Sign in
      </Button>
      <Button variant="ghost" small onClick={onRetry}>
        Check again
      </Button>
    </CenteredCard>
  );
}
