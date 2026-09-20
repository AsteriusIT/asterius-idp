import type { Session } from './api';

export interface MetricDefinition {
  readonly path: string;
  readonly scope: string;
  readonly label: string;
  readonly empty: string;
}

export interface MetricDocument {
  readonly metric: string;
  readonly value: number;
  readonly definition: string;
  readonly window_seconds: number | null;
  readonly collected_at: number;
}

export type MetricState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly document: MetricDocument }
  | { readonly kind: 'failed'; readonly message: string };

/** The tenant-wide application profile policy, phrased for an at-a-glance badge. */
export function applicationPolicyPresentation(allowNonFapiClients: boolean): {
  readonly label: string;
  readonly tone: 'ok' | 'warn';
} {
  return allowNonFapiClients
    ? { label: 'Non-FAPI exceptions enabled', tone: 'warn' }
    : { label: 'FAPI-only applications', tone: 'ok' };
}

export const OVERVIEW_METRICS: readonly MetricDefinition[] = [
  { path: 'overview/users', scope: 'admin.users:read', label: 'Active users', empty: 'No active accounts' },
  { path: 'overview/sessions', scope: 'admin.sessions:read', label: 'Active sessions', empty: 'No active sessions' },
  { path: 'overview/applications', scope: 'admin.clients:read', label: 'Applications', empty: 'No applications registered' },
  { path: 'overview/authentication', scope: 'admin.audit:read', label: 'Authentication failures', empty: 'No failures in the last 24 hours' },
  { path: 'overview/keys', scope: 'admin.keys:read', label: 'Active signing keys', empty: 'No active signing key' },
  { path: 'overview/delivery', scope: 'admin.outbox:read', label: 'Delivery failures', empty: 'No failures in the last 24 hours' },
];

/** The API re-checks every path; this only avoids requesting forbidden cards. */
export function visibleMetrics(session: Pick<Session, 'scopes'>): readonly MetricDefinition[] {
  return OVERVIEW_METRICS.filter((metric) => session.scopes.includes(metric.scope));
}

export function loadingMetrics(definitions: readonly MetricDefinition[]): ReadonlyMap<string, MetricState> {
  return new Map(definitions.map((definition) => [definition.path, { kind: 'loading' }]));
}

/** Replaces one card while preserving every independently-loaded neighbour. */
export function updateMetric(
  current: ReadonlyMap<string, MetricState>,
  path: string,
  state: MetricState,
): ReadonlyMap<string, MetricState> {
  return new Map(current).set(path, state);
}
