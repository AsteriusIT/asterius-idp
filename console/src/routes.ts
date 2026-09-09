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

/** The route named by a fragment, or the default if it names none of them. */
export function routeOf(fragment: string): string {
  const wanted = fragment.replace(/^#\/?/, '');
  return DESTINATIONS.some((destination) => destination.route === wanted)
    ? wanted
    : DEFAULT_ROUTE;
}

/** The `href` for a route, as a fragment relative to the entry document. */
export function hrefOf(route: string): string {
  return `#/${route}`;
}
