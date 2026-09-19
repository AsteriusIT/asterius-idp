import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { read, type Session } from './api';
import { NAVIGATION_ICONS } from './components/app-sidebar';
import { visibleTo } from './navigation';
import {
  loadingMetrics,
  updateMetric,
  visibleMetrics,
  type MetricDefinition,
  type MetricDocument,
  type MetricState,
} from './overview-model';
import { hrefOf } from './routes';
import { Badge, Button, EmptyState, LoadFailure, Panel, Screen, Skeleton, Timestamp } from './ui';

export function Overview({ session }: Readonly<{ session: Session }>): JSX.Element {
  const definitions = visibleMetrics(session);
  const [metrics, setMetrics] = useState<ReadonlyMap<string, MetricState>>(() => new Map());
  const [refresh, setRefresh] = useState(0);
  const destinations = visibleTo(session).filter((destination) => destination.route !== 'overview' && !destination.menuOnly);

  const reload = useCallback(() => setRefresh((value) => value + 1), []);
  useEffect(() => {
    let active = true;
    setMetrics(loadingMetrics(definitions));
    for (const definition of definitions) {
      read(definition.path).then(
        (value) => {
          if (!active) return;
          setMetrics((current) => updateMetric(current, definition.path, { kind: 'ready', document: value as MetricDocument }));
        },
        (error: unknown) => {
          if (!active) return;
          const message = error instanceof Error ? error.message : 'This summary could not be read.';
          setMetrics((current) => updateMetric(current, definition.path, { kind: 'failed', message }));
        },
      );
    }
    return () => { active = false; };
  }, [refresh, session.workspace]);

  return (
    <Screen
      title="Overview"
      description={`Activity and health for ${session.workspace}, limited to the data this session may read.`}
      actions={<Button onClick={reload}>Refresh summaries</Button>}
    >
      <div className="overview-bento">
        <Panel className="overview-identity" title="Workspace" description="The active tenant and your effective access.">
          <dl className="stats">
            <div className="stat"><dt>Tenant</dt><dd>{session.workspace}</dd></div>
            <div className="stat"><dt>User</dt><dd className="wrap-anywhere">{session.user}</dd></div>
            <div className="stat"><dt>Roles</dt><dd>{session.roles.length > 0 ? <span className="row">{session.roles.map((role) => <Badge key={role} tone="neutral">{role}</Badge>)}</span> : 'none'}</dd></div>
          </dl>
        </Panel>

        <Panel title="Tenant activity and health" description="Each figure is independently authorized and collected from this tenant.">
          {definitions.length === 0 ? (
            <EmptyState title="No summaries available" body="This session has no permission to read tenant activity or operational health." />
          ) : (
            <div className="stats overview-metrics">
              {definitions.map((definition) => <MetricCard key={definition.path} definition={definition} state={metrics.get(definition.path) ?? { kind: 'loading' }} retry={reload} />)}
            </div>
          )}
        </Panel>

        <Panel className="overview-access" title="Available areas" description={`${destinations.length} areas are available with your current permissions.`}>
          <div className="workspace-grid">
            {destinations.map((destination) => {
              const Icon = NAVIGATION_ICONS[destination.route];
              return <a className="workspace-card" key={destination.route} href={hrefOf(destination.route)}><span className="workspace-icon" aria-hidden="true">{Icon !== undefined && <Icon />}</span><span><strong>{destination.label}</strong><small>{destination.group}</small></span></a>;
            })}
          </div>
        </Panel>
      </div>
    </Screen>
  );
}

function MetricCard({ definition, state, retry }: Readonly<{ definition: MetricDefinition; state: MetricState; retry: () => void }>): JSX.Element {
  if (state.kind === 'loading') {
    return <div className="stat"><dt>{definition.label}</dt><dd><Skeleton rows={1} label={`Loading ${definition.label.toLowerCase()}.`} /></dd></div>;
  }
  if (state.kind === 'failed') {
    return <div className="stat"><dt>{definition.label}</dt><dd><LoadFailure message={state.message} onRetry={retry} retryLabel="Refresh all" /></dd></div>;
  }
  const { document } = state;
  return (
    <div className="stat">
      <dt>{definition.label}</dt>
      <dd>{document.value === 0 ? <span className="overview-empty">{definition.empty}</span> : document.value.toLocaleString()}</dd>
      <p className="muted overview-definition">{document.definition}</p>
      <small className="muted">Refreshed <Timestamp value={document.collected_at} /></small>
    </div>
  );
}
