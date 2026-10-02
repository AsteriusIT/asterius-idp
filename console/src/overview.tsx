import { ArrowUpRightIcon, RefreshCwIcon, FingerprintIcon, ShieldCheckIcon, Building2Icon, NetworkIcon } from 'lucide-react';
import { NAVIGATION_ICONS } from './components/app-sidebar';
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
import { visibleTo } from './navigation';
import { hrefOf } from './routes';

export function Overview({ session }: Readonly<{ session: Session }>): JSX.Element {
  const definitions = visibleMetrics(session);
  const [metrics, setMetrics] = useState<ReadonlyMap<string, MetricState>>(() => new Map());
  const [refresh, setRefresh] = useState(0);
  const [collectedAt, setCollectedAt] = useState<string | null>(null);
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
          setCollectedAt(new Date().toISOString());
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
  const available = new Set(visibleTo(session).map((destination) => destination.route));
  const shortcuts = [
    { route: 'users', title: 'Find a person', detail: 'Review their profile, sessions, and access.' },
    { route: 'clients', title: 'Connect an application', detail: 'Register an app and review its sign-in settings.' },
    { route: 'groups', title: 'Manage group access', detail: 'Add members and assign application roles.' },
    { route: 'audit', title: 'Investigate an event', detail: 'Trace changes and sign-in activity.' },
  ].filter((shortcut) => available.has(shortcut.route));

  return (
    <Screen
      title="Overview"
      description={`Manage identity and application access for ${session.workspace}.`}
      actions={<Button variant="ghost" onClick={reload}><RefreshCwIcon aria-hidden="true" />Refresh summaries</Button>}
    >
      <div className="overview-bento">
        <section className="overview-hero" aria-labelledby="tenant-hero-title">
          <div className="overview-hero-copy">
            <span className="overview-hero-label"><Building2Icon aria-hidden="true" />Active tenant</span>
            <h3 id="tenant-hero-title">{session.workspace}</h3>
            <p>Your identity workspace. Connect applications, manage people, and keep access in view.</p>
            <div className="overview-hero-actions">
              {applicationPolicy !== null && <Badge tone={applicationPolicy.tone}><ShieldCheckIcon aria-hidden="true" />{applicationPolicy.label}</Badge>}
              <a href={hrefOf('health')}>View workspace health<ArrowUpRightIcon aria-hidden="true" /></a>
            </div>
          </div>
          <div className="overview-hero-network" aria-hidden="true">
            <span className="hero-network-orbit" /><span className="hero-network-core"><FingerprintIcon /></span>
            <span className="hero-network-node hero-network-app"><NetworkIcon /></span>
            <span className="hero-network-node hero-network-trust"><ShieldCheckIcon /></span>
            <span className="hero-network-node hero-network-tenant"><Building2Icon /></span>
          </div>
          <div className="overview-hero-footer"><span>Signed in as <strong>{session.username}</strong></span><span className="row">{session.roles.map(role => <Badge key={role} tone="neutral">{role}</Badge>)}</span></div>
        </section>
        <Panel className="overview-start" title="Start here" description="Common tasks in your identity workspace.">
          <div className="quick-link-grid">
            {shortcuts.map((shortcut) => {
              const Icon = NAVIGATION_ICONS[shortcut.route];
              return <a className="quick-link" key={shortcut.route} href={hrefOf(shortcut.route)}>
                {Icon && <Icon className="quick-link-icon" aria-hidden="true" />}
                <div><strong>{shortcut.title}</strong><small>{shortcut.detail}</small></div>
                <ArrowUpRightIcon className="quick-link-arrow" aria-hidden="true" />
              </a>;
            })}
          </div>
          <p className="muted">Connecting your first app? <a href={hrefOf('help')}>Read the integration guide</a>.</p>
        </Panel>

        <Panel className="overview-activity" title="Tenant activity and health" description="Current activity from the summaries your account can read.">
          {definitions.length === 0 ? (
            <EmptyState title="No summaries available" body="This session has no permission to read tenant activity or operational health." />
          ) : (
            <div className="stats overview-metrics">
              {definitions.map((definition) => <MetricCard key={definition.path} definition={definition} state={metrics.get(definition.path) ?? { kind: 'loading' }} retry={reload} />)}
            </div>
          )}
        </Panel>
      </div>
      <div className="overview-footer">
        <span>{collectedAt ? <>Latest update <Timestamp value={collectedAt} /></> : 'Waiting for activity summaries.'}</span>

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
