import { ConditionalExamples } from './conditional-examples';
import { ENFORCEMENT_ACTIONS, factExamples, type EnforcementAction, type ExampleFactName, type FactExample } from './conditional-policy-model';
import { useEffect, useState, type JSX } from 'react';
import { probe, read, type Session } from './api';
import { Verdict, type DecisionDocument } from './policy';
import { Actions, Badge, Button, DataTable, Field, Message, Panel } from './ui';

interface References {
  users: readonly { user_id: string; username: string }[];
  clients: readonly { client_id: string; client_name?: string }[];
  resources: readonly { identifier: string }[];
}

/** Actual tenant identities; hypothetical evidence never becomes production authority. */
export function PolicySimulation({ session, revision, draft }: Readonly<{
  session: Session; revision: string | null; draft: string;
}>): JSX.Element {
  const permitted = ['admin.policies:read', 'admin.users:read', 'admin.clients:read', 'admin.resource_servers:read']
    .every((scope) => session.scopes.includes(scope));
  const [snapshot, setSnapshot] = useState(revision);
  useEffect(() => { setSnapshot(revision); setDecision(null); }, [revision]);
  const [references, setReferences] = useState<References | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [user, setUser] = useState('');
  const [client, setClient] = useState('');
  const [resource, setResource] = useState('');
  const [kind, setKind] = useState('resource-server');
  const [action, setAction] = useState('read');
  const [boundary, setBoundary] = useState<EnforcementAction>('access_evaluation');
  const [useExamples, setUseExamples] = useState(false);
  const [examples, setExamples] = useState<Partial<Record<ExampleFactName, FactExample>>>({});
  const [context, setContext] = useState('{}');
  const [useDraft, setUseDraft] = useState(false);
  const [busy, setBusy] = useState(false);
  const [decision, setDecision] = useState<DecisionDocument | null>(null);
  useEffect(() => {
    if (!permitted) return;
    let current = true;
    Promise.all([read('users?limit=100'), read('clients?limit=100'), read('resource-servers')])
      .then(([users, clients, resources]) => {
        if (current) setReferences({
          users: (users as { items: References['users'] }).items,
          clients: (clients as { items: References['clients'] }).items,
          resources: (resources as { items: References['resources'] }).items,
        });
      }, (error: unknown) => { if (current) setFailure(String(error)); });
    return () => { current = false; };
  }, [permitted]);

  useEffect(() => { setDecision(null); }, [user, client, resource, kind, action, boundary, useExamples, examples, context, useDraft, draft]);
  const simulate = async (): Promise<void> => {
    setBusy(true); setFailure(null); setDecision(null);
    try {
      const result = await probe('policies/simulate', session, {
        user_id: user, client_id: client, resource_id: resource,
        resource_type: kind, action, enforcement_action: boundary, expected_policy_revision: snapshot,
        ...(useExamples ? { hypothetical_trusted_context: factExamples(examples) } : {}),
        hypothetical_context: JSON.parse(context) as unknown,
        ...(useDraft ? { hypothetical_policy: JSON.parse(draft) as unknown } : {}),
      });
      setDecision(result as DecisionDocument);
    } catch (error: unknown) {
      setFailure(error instanceof Error ? error.message : 'Simulation refused');
    } finally { setBusy(false); }
  };
  return <Panel title="What-if simulation" description="Choose actual tenant records, then try hypothetical context or the editor draft. Groups, roles and active grants come from the server. Transaction evidence is absent unless explicitly supplied as a hypothetical example. Each inspection is audited.">
    {!permitted ? <p>Requires policy, user, application and resource read access.</p> : <>
      <p className="muted">The selectors show the first 100 accounts and applications. A simulation grants no access and saves no policy.</p>
      <p className="muted">Simulation stored snapshot: {snapshot ? <code>{snapshot}</code> : 'No stored policy'}. Refreshing this snapshot does not reload the editor draft.</p>
      <form className="toolbar" onSubmit={(event) => { event.preventDefault(); void simulate(); }}>
        <Field label="Tenant user">{(props) => <select {...props} required value={user} onChange={(event) => setUser(event.target.value)}>
          <option value="">Choose an account</option>{references?.users.map((row) => <option key={row.user_id} value={row.user_id}>{row.username}</option>)}
        </select>}</Field>
        <Field label="Application">{(props) => <select {...props} required value={client} onChange={(event) => setClient(event.target.value)}>
          <option value="">Choose an application</option>{references?.clients.map((row) => <option key={row.client_id} value={row.client_id}>{row.client_name ?? row.client_id}</option>)}
        </select>}</Field>
        <Field label="Registered resource">{(props) => <select {...props} required value={resource} onChange={(event) => setResource(event.target.value)}>
          <option value="">Choose a resource</option>{references?.resources.map((row) => <option key={row.identifier} value={row.identifier}>{row.identifier}</option>)}
        </select>}</Field>
        <Field label="Resource category">{(props) => <input {...props} required maxLength={256} value={kind} onChange={(event) => setKind(event.target.value)} />}</Field>
        <Field label="Hypothetical operation">{(props) => <input {...props} required maxLength={256} value={action} onChange={(event) => setAction(event.target.value)} />}</Field>
        <Field label="Enforcement boundary">{props => <select {...props} value={boundary} onChange={event => setBoundary(event.target.value as EnforcementAction)}>{ENFORCEMENT_ACTIONS.map(value => <option key={value} value={value}>{value}</option>)}</select>}</Field>
        <ConditionalExamples enabled={useExamples} examples={examples} onEnable={setUseExamples} onChange={(name,value) => setExamples(current => { const next={...current}; if(value) next[name]=value; else delete next[name]; return next; })} />
        <Field label="Hypothetical context properties (JSON)">{(props) => <textarea {...props} maxLength={65536} value={context} onChange={(event) => setContext(event.target.value)} />}</Field>
        <label><input type="checkbox" checked={useDraft} onChange={(event) => setUseDraft(event.target.checked)} /> Use the editor draft as hypothetical policy</label>
        <Actions><Button type="submit" variant="primary" disabled={busy || references === null}>Simulate</Button><Button onClick={() => {
          void read('policies').then((value) => { setSnapshot((value as { revision: string | null }).revision); setDecision(null); setFailure(null); }, (error: unknown) => setFailure(String(error)));
        }} disabled={busy}>Refresh policy snapshot</Button></Actions>
      </form>
      {failure !== null && <Message tone="error">{failure}</Message>}
      {decision !== null && <><Message tone="info">Hypothetical result — no access granted. Policy: {decision.simulation?.provenance.policy === 'hypothetical' ? 'editor draft' : 'stored snapshot'}. Context properties: hypothetical. Identity facts: server resolved. Trusted examples, if used, are labelled separately.</Message><ConditionalResult conditional={decision.simulation?.conditional} /><Verdict answer={{ kind: 'answered', decision }} /></>}
    </>}
  </Panel>;
}

function ConditionalResult({ conditional }: Readonly<{ conditional: NonNullable<DecisionDocument['simulation']>['conditional'] }>): JSX.Element | null {
  if (!conditional) return null;
  return <div className="stack">
    <p>Enforcement boundary: <code>{conditional.enforcement_action}</code>. Base result: {conditional.legacy_would_permit ? 'permit' : 'deny'}. With active scopes: {conditional.active_would_permit ? 'permit' : 'deny'}.</p>
    {conditional.evaluated_policy_revision && <p className="muted">Evaluated document: <code>{conditional.evaluated_policy_revision}</code>.</p>}
    <DataTable rows={conditional.facts} rowKey={fact => fact.name} columns={[
      {key:'fact',header:'Trusted fact',cell:fact => fact.name},
      {key:'availability',header:'Availability',cell:fact => <Badge tone={fact.availability === 'known' ? 'ok' : 'warn'}>{fact.availability}</Badge>},
      {key:'source',header:'Evidence source',cell:fact => <>{fact.hypothetical && <Badge tone="warn">Hypothetical example</Badge>} <code>{fact.source}</code></>},
    ]} />
    <DataTable rows={conditional.scopes} rowKey={scope => scope.id} columns={[
      {key:'scope',header:'Scope',cell:scope => scope.id},
      {key:'mode',header:'Mode',cell:scope => <Badge tone={scope.mode === 'active' ? 'bad' : 'warn'}>{scope.mode === 'active' ? 'Active enforcement' : 'Report-only'}</Badge>},
      {key:'result',header:'Would result',cell:scope => scope.would_decision ? 'Permit' : 'Deny'},
      {key:'facts',header:'Required evidence',cell:scope => <>{scope.required_facts.join(', ') || 'No additional facts'}{scope.missing_required_evidence && <p>Required evidence is missing, stale, invalid or unavailable.</p>}{scope.assurance_remedy !== null && <p>Attainable assurance remedy: {scope.assurance_remedy}</p>}</>},
    ]} />
  </div>;
}
