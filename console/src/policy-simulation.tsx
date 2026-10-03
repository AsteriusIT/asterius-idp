import { useEffect, useState, type JSX } from 'react';
import { probe, read, type Session } from './api';
import { Verdict, type DecisionDocument } from './policy';
import { Actions, Button, Field, Message, Panel } from './ui';

interface References {
  users: readonly { user_id: string; username: string }[];
  clients: readonly { client_id: string; client_name?: string }[];
  resources: readonly { identifier: string }[];
}

/** Actual tenant references; only the draft and context may be invented. */
export function PolicySimulation({ session, revision, draft }: Readonly<{
  session: Session; revision: string | null; draft: string;
}>): JSX.Element {
  const permitted = ['admin.users:read', 'admin.clients:read', 'admin.resource_servers:read']
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

  const simulate = async (): Promise<void> => {
    setBusy(true); setFailure(null); setDecision(null);
    try {
      const result = await probe('policies/simulate', session, {
        user_id: user, client_id: client, resource_id: resource,
        resource_type: kind, action, expected_policy_revision: snapshot,
        hypothetical_context: JSON.parse(context) as unknown,
        ...(useDraft ? { hypothetical_policy: JSON.parse(draft) as unknown } : {}),
      });
      setDecision(result as DecisionDocument);
    } catch (error: unknown) {
      setFailure(error instanceof Error ? error.message : 'Simulation refused');
    } finally { setBusy(false); }
  };
  return <Panel title="What-if simulation" description="Choose actual tenant records, then try hypothetical context or the editor draft. Groups, roles, active grants and authentication level come from the server. Each inspection is audited.">
    {!permitted ? <p>Requires access to users, clients and resource servers.</p> : <>
      <p className="muted">The selectors show the first 100 accounts and applications. A simulation grants no access and saves no policy.</p>
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
        <Field label="Hypothetical context (JSON)">{(props) => <textarea {...props} maxLength={65536} value={context} onChange={(event) => setContext(event.target.value)} />}</Field>
        <label><input type="checkbox" checked={useDraft} onChange={(event) => setUseDraft(event.target.checked)} /> Use the editor draft as hypothetical policy</label>
        <Actions><Button type="submit" variant="primary" disabled={busy || references === null}>Simulate</Button><Button onClick={() => {
          void read('policies').then((value) => { setSnapshot((value as { revision: string | null }).revision); setDecision(null); setFailure(null); }, (error: unknown) => setFailure(String(error)));
        }} disabled={busy}>Refresh policy snapshot</Button></Actions>
      </form>
      {failure !== null && <Message tone="error">{failure}</Message>}
      {decision !== null && <><Message tone="info">Hypothetical result — no access granted. Policy: {decision.simulation?.provenance.policy === 'hypothetical' ? 'editor draft' : 'stored snapshot'}. Context: hypothetical. Identity and authorization facts: server resolved.</Message><Verdict answer={{ kind: 'answered', decision }} /></>}
    </>}
  </Panel>;
}
