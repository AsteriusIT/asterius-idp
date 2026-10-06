import { LayoutDashboardIcon } from 'lucide-react';
import { NAVIGATION_ICONS } from '../route-icons';
import { routeOf } from '../routes';

/** Decorative route context; titles and navigation carry all meaning. */
export function PageIllustration() {
  const route = routeOf(window.location.hash);
  const Icon = NAVIGATION_ICONS[route] ?? LayoutDashboardIcon;
  return <span className="page-illustration" aria-hidden="true" data-page-illustration={route}>
    <span className="page-illustration-sheet" />
    <span className="page-illustration-symbol"><Icon /></span>
  </span>;
}
