import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { ApiError, endSession, loadSession, type Session } from './api';
import { AuditExplorer } from './audit';
import { Clients } from './clients';
import { Keys } from './keys';
import { visibleTo } from './navigation';
import { Policy } from './policy';
import { hrefOf, routeOf } from './routes';
import { TenantSettings } from './settings';
import { SharedSignals } from './ssf';
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
  const [route, setRoute] = useState(() => routeOf(window.location.hash));

  useEffect(() => {
    const onHashChange = (): void => setRoute(routeOf(window.location.hash));
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
      () => setShell({ kind: 'signed-out' }),
    );
  }, []);

  if (shell.kind === 'loading') {
    return <Notice heading="Loading" body="Reading the session." />;
  }
  if (shell.kind === 'signed-out') {
    return <SignedOut onRetry={probe} />;
  }
  if (shell.kind === 'failed') {
    return <Notice heading="The console could not start" body={shell.message} />;
  }

  const destinations = visibleTo(shell.session);
  const current = destinations.some((destination) => destination.route === route)
    ? route
    : (destinations[0]?.route ?? route);

  return (
    <>
      <a className="skip" href={`${hrefOf(current)}`} onClick={focusMain}>
        Skip to content
      </a>
      <header>
        <h1>Asterius console</h1>
        <p className="who">
          Signed in to <strong>{shell.session.tenant}</strong>{' '}
          <button type="button" onClick={() => signOut(shell.session)}>
            Sign out
          </button>
        </p>
      </header>
      <nav aria-label="Console sections">
        <ul>
          {destinations.map((destination) => (
            <li key={destination.route}>
              <a
                href={hrefOf(destination.route)}
                aria-current={destination.route === current ? 'page' : undefined}
              >
                {destination.label}
              </a>
            </li>
          ))}
        </ul>
      </nav>
      <main id="content" tabIndex={-1}>
        <Screen route={current} session={shell.session} />
      </main>
    </>
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
function Screen({ route, session }: { route: string; session: Session }): JSX.Element {
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
    return <TenantSettings session={session} />;
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
    return (
      <>
        <h2>Overview</h2>
        <dl>
          <dt>Tenant</dt>
          <dd>{session.tenant}</dd>
          <dt>User</dt>
          <dd>{session.user}</dd>
          <dt>Roles</dt>
          <dd>{session.roles.length > 0 ? session.roles.join(', ') : 'none'}</dd>
        </dl>
      </>
    );
  }

  const destination = visibleTo(session).find((candidate) => candidate.route === route);
  return (
    <>
      <h2>{destination?.label ?? 'Not found'}</h2>
      <p>This screen arrives with {destination?.bead ?? 'a later bead'}.</p>
    </>
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
    <main id="content" tabIndex={-1}>
      <h1>Signed out</h1>
      <p>This console has no session. Sign in again to continue.</p>
      <button type="button" onClick={() => window.location.reload()}>
        Sign in
      </button>
      <p className="muted">
        <button type="button" onClick={onRetry}>
          Check again
        </button>
      </p>
    </main>
  );
}

function Notice({ heading, body }: { heading: string; body: string }): JSX.Element {
  return (
    <main id="content" tabIndex={-1}>
      <h1>{heading}</h1>
      <p>{body}</p>
    </main>
  );
}
