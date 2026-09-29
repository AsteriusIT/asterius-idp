import { useEffect, useState } from 'react';
import { hrefOf, paramsOf, routeOf } from './routes';

/** Only non-secret identifiers and section names belong in shareable routes. */
export function useRouteParameters(): URLSearchParams {
  const [fragment, setFragment] = useState(() => window.location.hash);
  useEffect(() => {
    const changed = () => setFragment(window.location.hash);
    window.addEventListener('hashchange', changed);
    return () => window.removeEventListener('hashchange', changed);
  }, []);
  return paramsOf(fragment);
}

export function setRouteParameters(route: string, values: Record<string, string | null>): void {
  const params = routeOf(window.location.hash) === route ? paramsOf(window.location.hash) : new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value === null) params.delete(key); else params.set(key, value);
  }
  window.location.hash = hrefOf(route, Object.fromEntries(params));
}

/** Switching a persistent tab keeps the same editor and its drafts mounted. */
export function sameEditor(left: string, right: string): boolean {
  const a = new URL(left), b = new URL(right);
  if (a.origin !== b.origin || a.pathname !== b.pathname || a.search !== b.search) return false;
  if (routeOf(a.hash) !== routeOf(b.hash) || !['users', 'clients'].includes(routeOf(a.hash))) return false;
  const x = paramsOf(a.hash), y = paramsOf(b.hash);
  x.delete('tab'); y.delete('tab');
  return x.toString() === y.toString();
}

/** A successful creation adopts its server ID without discarding the one-time result. */
export function replaceSavedRoute(route: string, values: Record<string, string>): void {
  window.history.replaceState(window.history.state, '', hrefOf(route, values));
  window.dispatchEvent(new HashChangeEvent('hashchange'));
}
