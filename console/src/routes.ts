/**
 * Routing on the fragment, deliberately.
 *
 * A path-routed console would change the document URL as the user moves
 * around, and every relative asset and API URL on the page would then resolve
 * against a different base. The alternative is root-relative URLs, which lose
 * the `/t/{id}` prefix a tenant may be reached through — the same failure the
 * browser sweep already records for the interaction pages. Routing on the
 * fragment keeps the document at `…/admin/` whatever the user is looking at,
 * so one server-rendered entry document serves every screen and no server-side
 * catch-all route is needed.
 */
import { DESTINATIONS } from './navigation';

/** The screen shown when the fragment names nothing. */
export const DEFAULT_ROUTE = 'overview';

/**
 * A fragment may carry parameters (`ast-l5bl`).
 *
 * `#/settings?tenant=acme` is one screen looking at a subject that is not the
 * session's own tenant: the admin API's settings routes name their tenant in
 * the path and admit a deployment-scoped caller for any of them, so the
 * Tenants screen can send an operator straight to the settings of the row they
 * were reading. The alternative — a second settings screen, or a link to the
 * other tenant's console — would be either a duplicate of a screen that works
 * or a link to a door this session has no key to.
 *
 * Nothing here is trusted. The parameter reaches one screen, which puts it in
 * a path the server re-authorises; a fragment naming a tenant this caller may
 * not read is a 403 drawn as a failed load.
 */
function bodyOf(fragment: string): string {
  return fragment.replace(/^#\/?/, '');
}

/** The route named by a fragment, or the default if it names none of them. */
export function routeOf(fragment: string): string {
  const wanted = bodyOf(fragment).split('?')[0] ?? '';
  return DESTINATIONS.some((destination) => destination.route === wanted)
    ? wanted
    : DEFAULT_ROUTE;
}

/** The parameters a fragment carries, which is usually none. */
export function paramsOf(fragment: string): URLSearchParams {
  return new URLSearchParams(bodyOf(fragment).split('?').slice(1).join('?'));
}

/** The `href` for a route, as a fragment relative to the entry document. */
export function hrefOf(route: string, params?: Readonly<Record<string, string>>): string {
  const query = params === undefined ? '' : new URLSearchParams(params).toString();
  return query === '' ? `#/${route}` : `#/${route}?${query}`;
}
