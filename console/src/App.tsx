import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { ApiError, endSession, loadSession, type Session } from './api';
import { AuditExplorer } from './audit';
import { Branding } from './branding';
import { AuthorizationDetailsTypes } from './authorizationDetailsTypes';
import { Roles } from './appRoles';
import { Clients } from './clients';
import { AppSidebar } from './components/app-sidebar';
import { AppTopbar } from './components/app-topbar';
import { SidebarInset, SidebarProvider } from './components/ui/sidebar';
import { Toaster, toast } from './components/ui/toast';
import { Keys } from './keys';
import { DESTINATIONS, visibleTo } from './navigation';
import { Policy } from './policy';
import { Preferences } from './preferences';
import { ResourceServers } from './resourceServers';
import { paramsOf, routeOf } from './routes';
import { TenantSettings } from './settings';
import { Tenants } from './tenants';
import { SharedSignals } from './ssf';
import { Button, CenteredCard, Panel, Screen } from './ui';
import { Users } from './users';
import { Overview } from './overview';
import { Groups } from './groups';

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

  return (
    <SidebarProvider defaultOpen>
      <AppTopbar
        session={shell.session}
        page={here?.label ?? 'Not found'}
        onSignOut={() => signOut(shell.session)}
      />
      <AppSidebar session={shell.session} current={current} />
      <SidebarInset>
        <main id="content" tabIndex={-1} className="content">
          <RouteScreen route={current} fragment={fragment} session={shell.session} />
        </main>
      </SidebarInset>
      <Toaster />
    </SidebarProvider>
  );
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
}: Readonly<{
  route: string;
  fragment: string;
  session: Session;
}>): JSX.Element {
  if (route === 'roles') return <Roles session={session} client={paramsOf(fragment).get('client')} />;
  if (route === 'users') {
    return <Users session={session} />;
  }
  if (route === 'groups') return <Groups session={session} />;
  if (route === 'clients') {
    return <Clients session={session} />;
  }
  if (route === 'resources') {
    return <ResourceServers session={session} />;
  }
  if (route === 'authorization-details') {
    return <AuthorizationDetailsTypes session={session} />;
  }
  if (route === 'keys') {
    return <Keys session={session} />;
  }
  if (route === 'settings') {
    // The subject is the session's own tenant unless the Tenants screen named
    // another one, which only a deployment-scoped caller can have reached.
    return <TenantSettings session={session} tenant={paramsOf(fragment).get('tenant')} />;
  }
  if (route === 'branding') {
    return <Branding session={session} />;
  }
  if (route === 'preferences') {
    return <Preferences />;
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
 * rather than leaving the rail's absences unexplained. Workspace identity
 * comes from `GET /session`; the activity cards are loaded independently by
 * `overview.tsx`, each under the detailed resource's own read scope.
 */
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
function SignedOut({ onRetry }: Readonly<{ onRetry: () => void }>): JSX.Element {
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
