import { useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { read, type Session } from './api';
import {
  applicationPolicyPresentation,
  loadingMetrics,
  updateMetric,
  visibleMetrics,
  type MetricDefinition,
  type MetricDocument,
  type MetricState,
} from './overview-model';
import { Badge, Button, EmptyState, LoadFailure, Panel, Screen, Skeleton, Timestamp } from './ui';

export function Overview({ session }: Readonly<{ session: Session }>): JSX.Element {
  const definitions = visibleMetrics(session);
  const [metrics, setMetrics] = useState<ReadonlyMap<string, MetricState>>(() => new Map());
  const [refresh, setRefresh] = useState(0);
  const [allowNonFapiClients, setAllowNonFapiClients] = useState<boolean | null>(null);
  const mayReadTenant = session.scopes.includes('admin.tenants:read');

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

  useEffect(() => {
    let active = true;
    if (!mayReadTenant) {
      setAllowNonFapiClients(null);
      return () => { active = false; };
    }
    read(`tenants/${encodeURIComponent(session.workspace)}/settings`).then(
      (value) => {
        if (!active) return;
        const document = value as { allow_non_fapi_clients?: boolean };
        setAllowNonFapiClients(document.allow_non_fapi_clients ?? false);
      },
      () => { if (active) setAllowNonFapiClients(null); },
    );
    return () => { active = false; };
  }, [mayReadTenant, refresh, session.workspace]);

  const applicationPolicy = allowNonFapiClients === null
    ? null
    : applicationPolicyPresentation(allowNonFapiClients);

  return (
    <Screen
      title="Overview"
      description={`Activity and health for ${session.workspace}, limited to the data this session may read.`}
      actions={<Button onClick={reload}>Refresh summaries</Button>}
    >
      <div className="overview-bento">
        <Panel
          className="overview-identity"
          title={session.workspace}
          description="Active workspace"
          actions={applicationPolicy !== null && <Badge tone={applicationPolicy.tone}>{applicationPolicy.label}</Badge>}
        >
          <dl className="stats overview-context">
            <div className="stat"><dt>User</dt><dd className="wrap-anywhere">{session.user}</dd></div>
            <div className="stat"><dt>Roles</dt><dd>{session.roles.length > 0 ? <span className="row">{session.roles.map((role) => <Badge key={role} tone="neutral">{role}</Badge>)}</span> : 'none'}</dd></div>
          </dl>
        </Panel>

        <Panel className="overview-activity" title="Tenant activity and health" description="Each figure is independently authorized and collected from this tenant.">
          {definitions.length === 0 ? (
            <EmptyState title="No summaries available" body="This session has no permission to read tenant activity or operational health." />
          ) : (
            <div className="stats overview-metrics">
              {definitions.map((definition) => <MetricCard key={definition.path} definition={definition} state={metrics.get(definition.path) ?? { kind: 'loading' }} retry={reload} />)}
            </div>
          )}
        </Panel>
      </div>
    </Screen>
  );
}

function MetricCard({ definition, state, retry }: Readonly<{ definition: MetricDefinition; state: MetricState; retry: () => void }>): JSX.Element {
  if (state.kind === 'loading') {
    return <div className="stat"><p className="metric-label">{definition.label}</p><div className="metric-value"><Skeleton rows={1} label={`Loading ${definition.label.toLowerCase()}.`} /></div></div>;
  }
  if (state.kind === 'failed') {
    return <div className="stat"><p className="metric-label">{definition.label}</p><div className="metric-value"><LoadFailure message={state.message} onRetry={retry} retryLabel="Refresh all" /></div></div>;
  }
  const { document } = state;
  return (
    <div className="stat">
      <p className="metric-label">{definition.label}</p>
      <p className="metric-value">{document.value === 0 ? <span className="overview-empty">{definition.empty}</span> : document.value.toLocaleString()}</p>
      <p className="muted overview-definition">{document.definition}</p>
      <small className="muted">Refreshed <Timestamp value={document.collected_at} /></small>
    </div>
  );
}
