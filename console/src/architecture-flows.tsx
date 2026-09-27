import { memo, useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { AppWindow, Database, Users, UserRound, ShieldCheck, Radio, LogIn, ArrowLeft, Plus, Pencil, Eye } from 'lucide-react';
import {
  Background, Controls, Handle, MiniMap, Position, ReactFlow,
  applyEdgeChanges, applyNodeChanges,
  type Edge as CanvasEdge, type EdgeChange,
  type Node as CanvasNode, type NodeChange,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { mutate, read, type Session } from './api';
import { validConnection, type ArchitectureNode, type Flow, type Graph, type Kind, type Mode, type Plan, type ResourceLink } from './architecture-model';
import { hrefOf, paramsOf } from './routes';
import { toast } from './components/ui/toast';
import { Button, Field, LoadFailure, Panel, Screen, Skeleton } from './ui';

const TYPES: Readonly<Record<Kind, string>> = {
  application: 'Web application', api: 'API', group: 'Group', role: 'Role',
  stream: 'Security event stream', identity_provider: 'External identity provider', user: 'User',
};
const ICONS = { application: AppWindow, api: Database, group: Users, user: UserRound, role: ShieldCheck, stream: Radio, identity_provider: LogIn };
interface CanvasData extends Record<string, unknown> { label: string; kind: Kind; identifier: string; mode: Mode }
const ArchitectureCard = memo(function ArchitectureCard({ data }: { data: CanvasData }): JSX.Element {
  const Icon = ICONS[data.kind];
  const leaf = ['role', 'user', 'api', 'stream'].includes(data.kind);
  return <div className={`architecture-card ${data.kind === 'role' ? 'architecture-role-leaf' : ''}`}>
    {data.kind !== 'identity_provider' && <Handle type="target" position={Position.Left} />}
    <span className="architecture-card-kind"><Icon size={18} aria-hidden="true" />{TYPES[data.kind]}</span>
    <strong>{data.label}</strong>
    {data.kind !== 'role' && <span className="muted">{data.kind === 'application' && data.mode === 'managed' ? 'Application' : data.identifier || 'Select to configure'}</span>}
    {!leaf && <Handle type="source" position={Position.Right} />}
  </div>;
});
const NODE_TYPES = { architecture: ArchitectureCard };

function FlowCanvas({ graph, writable, onSelect, onChange }: { graph: Graph; writable: boolean; onSelect: (id: string) => void; onChange: (graph: Graph) => void }): JSX.Element {
  const [nodes, setNodes] = useState<CanvasNode<CanvasData>[]>([]);
  const [edges, setEdges] = useState<CanvasEdge[]>([]);
  useEffect(() => setNodes(previous => graph.nodes.map(node => {
    const old = previous.find(item => item.id === node.id);
    return { ...old, id: node.id, type: 'architecture', position: { x: node.x, y: node.y },
      data: { label: node.label, kind: node.kind, identifier: node.identifier, mode: node.mode } };
  })), [graph.nodes]);
  useEffect(() => setEdges(graph.edges.map(edge => {
    const from = graph.nodes.find(node => node.id === edge.source)?.kind;
    const to = graph.nodes.find(node => node.id === edge.target)?.kind;
    return { ...edge, label: to === 'role' ? from === 'group' ? 'Grants' : 'Defines' : from === 'identity_provider' ? 'Supplies identities' : to === 'api' ? 'Calls' : 'Sends events' };
  })), [graph.edges, graph.nodes]);
  const onNodesChange = useCallback((changes: NodeChange<CanvasNode<CanvasData>>[]) => setNodes(current => applyNodeChanges(changes, current)), []);
  const onEdgesChange = useCallback((changes: EdgeChange<CanvasEdge>[]) => setEdges(current => applyEdgeChanges(changes, current)), []);
  return <ReactFlow nodes={nodes} edges={edges} nodeTypes={NODE_TYPES} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
    onNodeClick={(_, node) => onSelect(node.id)} nodesDraggable={writable} nodesConnectable={writable} deleteKeyCode={null}
    onNodeDragStop={(_, moved, dragged) => onChange({ ...graph, nodes: graph.nodes.map(node => { const position = (dragged.length ? dragged : [moved]).find(item => item.id === node.id)?.position; return position ? { ...node, ...position } : node; }) })}
    onConnect={connection => { if (writable && connection.source && connection.target && validConnection(graph, connection.source, connection.target)) onChange({ ...graph, edges: [...graph.edges, { id: crypto.randomUUID(), source: connection.source, target: connection.target }] }); }}
    isValidConnection={connection => Boolean(connection.source && connection.target && validConnection(graph, connection.source, connection.target))} fitView>
    <Background /><MiniMap pannable zoomable /><Controls showInteractive={false} />
  </ReactFlow>;
}

export function ArchitectureFlows({ session, fragment }: { session: Session; fragment: string }): JSX.Element {
  const params = paramsOf(fragment);
  const id = params.get('flow');
  const mode = params.get('mode');
  if (id || mode === 'new') return <ArchitectureWorkspace key={`${id ?? 'new'}:${mode ?? 'view'}`} session={session} flowId={id} editing={mode === 'edit' || mode === 'new'} templateRequested={params.get('template') === 'web'} initialNode={params.get('node')} />;
  return <ArchitectureDirectory session={session} />;
}

function ArchitectureDirectory({ session }: { session: Session }): JSX.Element {
  const [items, setItems] = useState<Flow[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const refresh = useCallback(() => { setLoading(true); setError(''); read('flows').then(value => setItems((value as { items: Flow[] }).items), error => setError(String(error))).finally(() => setLoading(false)); }, []);
  useEffect(refresh, [refresh]);
  return <Screen title="Architectures" description="Plan your applications and access, then manage the resources they create."
    actions={session.scopes.includes('admin.flows:write') ? <div className="architecture-toolbar"><a className="architecture-action" href={hrefOf('architecture', { mode: 'new', template: 'web' })}>Web app + API template</a><a className="architecture-action primary" href={hrefOf('architecture', { mode: 'new' })}><Plus size={16} />New architecture</a></div> : undefined}>
    <Panel title="Saved architectures">
      {loading ? <Skeleton rows={3} label="Loading architectures" /> : error ? <LoadFailure message={error} onRetry={refresh} /> : items.length === 0 ? <p>Create your first architecture from a template or start with a blank canvas.</p> :
        <div className="architecture-directory">{items.map(item => <article key={item.id}><AppWindow aria-hidden="true" /><div><h2><a href={hrefOf('architecture', { flow: item.id })}>{item.name}</a></h2><p>{item.graph.nodes.length} objects · {item.applied_revision === item.revision ? 'Applied' : 'Draft changes'}</p><small>Updated {new Date(item.updated_at).toLocaleString()}</small></div><a aria-label={`View ${item.name}`} href={hrefOf('architecture', { flow: item.id })}><Eye size={18} />View</a>{session.scopes.includes('admin.flows:write') && <a aria-label={`Edit ${item.name}`} href={hrefOf('architecture', { flow: item.id, mode: 'edit' })}><Pencil size={18} />Edit</a>}</article>)}</div>}
    </Panel>
  </Screen>;
}
const EMPTY: Graph = { schema_version: 1, nodes: [], edges: [] };

function ArchitectureWorkspace({ session, flowId, editing, templateRequested, initialNode }: { session: Session; flowId: string | null; editing: boolean; templateRequested: boolean; initialNode: string | null }): JSX.Element {
  const [loadError, setLoadError] = useState('');
  const [tab, setTab] = useState<'object' | 'connections' | 'review' | 'resources'>('object');
  const [flow, setFlow] = useState<Flow | null>(null);
  const [name, setName] = useState('');
  const [graph, setGraph] = useState<Graph>(EMPTY);
  const [selected, setSelected] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [invalidKeys, setInvalidKeys] = useState<Record<string, boolean>>({});
  const [keyDrafts, setKeyDrafts] = useState<Record<string, string>>({});
  const hasInvalidKeys = graph.nodes.some(node => invalidKeys[node.id]);
  const [plan, setPlan] = useState<Plan | null>(null);
  const [links, setLinks] = useState<ResourceLink[]>([]);
  const [linkRefresh, setLinkRefresh] = useState(0);
  const [planning, setPlanning] = useState(false);
  const [applying, setApplying] = useState(false);
  const canWrite = editing && session.scopes.includes('admin.flows:write') && !applying && !busy;
  const refresh = (): void => { setLinkRefresh(value => value + 1); };
  useEffect(() => {
    if (!flowId) { if (templateRequested) template(); else create(); return; }
    const target = flowId;
    let active = true;
    read(`flows/${encodeURIComponent(target)}`).then(value => {
      if (!active) return;
      const item = value as Flow;
      setFlow(item); setName(item.name); setGraph(item.graph); setDirty(false); setPlan(null);
      const node = initialNode;
      setSelected(node && item.graph.nodes.some(entry => entry.id === node) ? node : null);
    }, error => setLoadError(error instanceof Error ? error.message : 'Architecture could not be opened'));
    return () => { active = false; };
  }, [flowId, session.workspace]);
  useEffect(() => {
    if (!flow) { setLinks([]); return; }
    let active = true;
    read(`flows/${encodeURIComponent(flow.id)}/links`).then(
      value => { if (active) setLinks((value as { items: ResourceLink[] }).items); },
      () => { if (active) setLinks([]); },
    );
    return () => { active = false; };
  }, [flow?.id, flow?.applied_revision, linkRefresh, session.workspace]);
  const open = (item: Flow): void => {
    setFlow(item); setName(item.name); setGraph(item.graph); setSelected(null); setDirty(false); setPlan(null); setLinkRefresh(value => value + 1);
  };
  const create = (): void => {
    setFlow(null); setName('Untitled architecture'); setGraph(EMPTY); setSelected(null); setDirty(false); setPlan(null); setLinks([]);
  };
  const template = (): void => {
    const [app, api, role, group] = Array.from({ length: 4 }, () => crypto.randomUUID());
    setFlow(null); setName('Web app and API'); setSelected(null); setPlan(null); setDirty(true);
    setGraph({ schema_version: 1, nodes: [
      { id: app!, kind: 'application', label: 'Web application', identifier: '', mode: 'managed', x: 40, y: 100, settings: { redirect_uris: [], jwks_uri: '' } },
      { id: api!, kind: 'api', label: 'API', identifier: '', mode: 'managed', x: 350, y: 40, settings: { scopes: [], default_token_lifetime_seconds: 300 } },
      { id: role!, kind: 'role', label: 'Reader', identifier: 'reader', mode: 'managed', x: 350, y: 220, settings: { description: 'Read access to this application' } },
      { id: group!, kind: 'group', label: 'Team', identifier: 'team', mode: 'managed', x: 40, y: 320, settings: {} },
    ], edges: [
      { id: crypto.randomUUID(), source: app!, target: api! },
      { id: crypto.randomUUID(), source: app!, target: role! },
      { id: crypto.randomUUID(), source: group!, target: role! },
    ] });
  };
  const change = (next: Graph): void => { setGraph(next); setDirty(true); setPlan(null); };
  const save = (): void => {
    if (!canWrite || hasInvalidKeys) return;
    setBusy(true);
    const path = flow ? `flows/${encodeURIComponent(flow.id)}` : 'flows';
    const method = flow ? 'PUT' : 'POST';
    mutate(path, method, session, { name: name.trim(), graph, ...(flow ? { revision: flow.revision } : {}) }).then(value => {
      const saved = value as Flow;
      open(saved); refresh(); toast.success('Architecture saved', saved.name);
      if (!flowId) window.location.hash = hrefOf('architecture', { flow: saved.id, mode: 'edit' });
    }, error => toast.error('Architecture was not saved', error instanceof Error ? error.message : 'Try again')).finally(() => setBusy(false));
  };
  const preview = (): void => {
    if (!flow) return;
    setPlanning(true); setPlan(null);
    mutate(`flows/${encodeURIComponent(flow.id)}/plan`, 'POST', session, { revision: flow.revision }).then(value => {
      setPlan(value as Plan);
    }, error => toast.error('Preview could not be built', error instanceof Error ? error.message : 'Try again')).finally(() => setPlanning(false));
  };
  const apply = (): void => {
    if (!flow || !plan?.applicable) return;
    setApplying(true);
    mutate(`flows/${encodeURIComponent(flow.id)}/apply`, 'POST', session, { revision: plan.revision, digest: plan.digest }).then(() => {
      setLinkRefresh(value => value + 1);
      toast.success('Architecture applied', 'Created resources are now linked to this flow.');
      read(`flows/${encodeURIComponent(flow.id)}`).then(value => open(value as Flow), () => refresh());
      refresh();
    }, error => {
      setLinkRefresh(value => value + 1);
      setPlan(null);
      toast.error('Apply stopped', error instanceof Error ? error.message : 'Preview the flow again to inspect partial progress.');
      read(`flows/${encodeURIComponent(flow.id)}`).then(value => open(value as Flow), () => refresh());
    }).finally(() => setApplying(false));
  };
  const addNode = (kind: Kind): void => {
    const id = crypto.randomUUID();
    const index = graph.nodes.length;
    const settings = kind === 'application' ? { redirect_uris: [], jwks_uri: '' }
      : kind === 'api' ? { scopes: [], default_token_lifetime_seconds: 300 }
      : kind === 'role' ? { description: '' } : {};
    change({ ...graph, nodes: [...graph.nodes, { id, kind, label: TYPES[kind], identifier: '', mode: kind === 'stream' || kind === 'identity_provider' || kind === 'user' ? 'reference' : 'managed', x: 60 + (index % 4) * 230, y: 80 + Math.floor(index / 4) * 150, settings }] });
    setSelected(id);
  };
  const selectedNode = graph.nodes.find(node => node.id === selected);
  const updateSelected = (patch: Partial<ArchitectureNode>): void => {
    change({ ...graph, nodes: graph.nodes.map(node => node.id === selected ? { ...node, ...patch } : node) });
  };
  const removeSelected = (): void => {
    if (!selected) return;
    change({ ...graph, nodes: graph.nodes.filter(node => node.id !== selected), edges: graph.edges.filter(edge => edge.source !== selected && edge.target !== selected) });
    setSelected(null);
  };
  const addConnection = (source: string, target: string): void => {
    if (validConnection(graph, source, target)) change({ ...graph, edges: [...graph.edges, { id: crypto.randomUUID(), source, target }] });
  };

  useEffect(() => {
    if (!dirty) return;
    const prevent = (event: BeforeUnloadEvent): void => { event.preventDefault(); };
    window.addEventListener('beforeunload', prevent);
    return () => window.removeEventListener('beforeunload', prevent);
  }, [dirty]);
  const navigate = (href: string): void => { if (!dirty || window.confirm('Leave this architecture and discard unsaved changes?')) window.location.hash = href; };
  if (loadError) return <Screen title="Architecture"><LoadFailure message={loadError} onRetry={() => window.location.reload()} /><a href={hrefOf('architecture')}>Back to architectures</a></Screen>;
  if (flowId && !flow) return <Skeleton rows={5} label="Loading architecture" />;
  return <section className="architecture-workspace" aria-label={editing ? 'Architecture editor' : 'Architecture viewer'}>
    <header className="architecture-workspace-header">
      <Button onClick={() => navigate(hrefOf('architecture'))} disabled={applying || busy}><ArrowLeft size={18} />Architectures</Button>
      <div className="architecture-title"><strong>{name}</strong><small>{session.workspace} · {editing ? dirty ? 'Unsaved changes' : 'Editing draft' : 'Viewing saved architecture'}</small></div>
      {editing ? <><Button disabled={!canWrite || hasInvalidKeys || !name.trim() || !dirty && Boolean(flow)} onClick={save}>{busy ? 'Saving…' : 'Save draft'}</Button>{flow && <Button disabled={busy || applying} onClick={() => navigate(hrefOf('architecture', { flow: flow.id }))}>View</Button>}</> : session.scopes.includes('admin.flows:write') && flow && <Button onClick={() => navigate(hrefOf('architecture', { flow: flow.id, mode: 'edit' }))}><Pencil size={16} />Edit architecture</Button>}
      {flow && <Button disabled={dirty || planning || applying} onClick={() => { setTab('review'); preview(); }}>{planning ? 'Checking…' : 'Review changes'}</Button>}
    </header>
    <div className="architecture-workspace-body">
      <div className="architecture-stage">
        {canWrite && <div className="architecture-palette" aria-label="Add an object">{(Object.keys(TYPES) as Kind[]).map(kind => { const Icon = ICONS[kind]; return <Button key={kind} small onClick={() => { addNode(kind); setTab('object'); }}><Icon size={16} />{TYPES[kind]}</Button>; })}</div>}
        <div className="architecture-stage-canvas"><FlowCanvas graph={graph} writable={canWrite} onSelect={id => { setSelected(id); setTab('object'); }} onChange={change} /></div>
      </div>
      <aside className="architecture-sidepane" aria-label="Architecture details">
        {graph.edges.some(edge => !validConnection({ ...graph, edges: graph.edges.filter(item => item.id !== edge.id) }, edge.source, edge.target)) && <p role="alert" className="architecture-pane-content">This diagram has an unsupported link. Open Links to remove it. Identity providers can connect only to groups or users.</p>}
        <nav className="architecture-pane-tabs" aria-label="Details sections">{(['object', 'connections', 'review', 'resources'] as const).map(value => <button type="button" key={value} aria-pressed={tab === value} onClick={() => setTab(value)}>{value === 'object' ? 'Objects' : value === 'review' ? 'Review' : value === 'resources' ? 'Resources' : 'Links'}</button>)}</nav>
        {tab === 'object' && <div className="architecture-pane-content">
          <Field label="Architecture name">{props => <input {...props} value={name} maxLength={120} disabled={!canWrite} onChange={event => { setName(event.target.value); setDirty(true); setPlan(null); }} />}</Field>
          <Field label="Object to inspect">{props => <select {...props} value={selected ?? ''} onChange={event => setSelected(event.target.value || null)}><option value="">Select an object on the canvas</option>{graph.nodes.map(node => <option key={node.id} value={node.id}>{node.label} · {TYPES[node.kind]}</option>)}</select>}</Field>
          {!selectedNode && <p className="muted">Select an object to see its settings. Add objects from the toolbar, then connect their handles or use Links.</p>}
        {selectedNode && <div className="architecture-inspector">
          <Field label="Display name">{props => <input {...props} value={selectedNode.label} disabled={!canWrite} onChange={event => updateSelected({ label: event.target.value })} />}</Field>
          {(selectedNode.kind !== 'application' || selectedNode.mode === 'reference') &&
            <Field label={selectedNode.kind === 'user' ? 'Username' : selectedNode.kind === 'api' ? 'API audience URL' : selectedNode.kind === 'role' ? 'Role name' : selectedNode.kind === 'group' ? 'Group machine name' : 'Identifier'}>{props => <input {...props} value={selectedNode.identifier} disabled={!canWrite} onChange={event => updateSelected({ identifier: event.target.value })} />}</Field>}
          <Field label="Ownership">{props => <select {...props} value={selectedNode.mode} disabled={!canWrite || selectedNode.kind === 'stream' || selectedNode.kind === 'identity_provider' || selectedNode.kind === 'user'} onChange={event => updateSelected({ mode: event.target.value as Mode })}>
            <option value="managed">Create with flow</option><option value="reference">{selectedNode.kind === 'stream' || selectedNode.kind === 'identity_provider' || selectedNode.kind === 'user' ? 'Diagram context only' : 'Existing reference'}</option>
          </select>}</Field>
          {(selectedNode.kind === 'stream' || selectedNode.kind === 'identity_provider' || selectedNode.kind === 'user') &&
            <p className="muted">Shown for architecture context. Apply does not configure or verify this integration.</p>}
          {selectedNode.kind === 'application' && selectedNode.mode === 'managed' && <>
            <LinesField key={`${selectedNode.id}:redirects`} label="Sign-in callback URLs" values={asStrings(selectedNode.settings.redirect_uris)} disabled={!canWrite} onChange={values => updateSelected({ settings: { ...selectedNode.settings, redirect_uris: values } })} />
            <KeySource key={selectedNode.id} node={selectedNode} draft={keyDrafts[selectedNode.id]} onDraft={text => setKeyDrafts(current => ({ ...current, [selectedNode.id]: text }))} disabled={!canWrite} onValidity={valid => setInvalidKeys(current => ({ ...current, [selectedNode.id]: !valid }))} onChange={settings => updateSelected({ settings })} />
          </>}
          {selectedNode.kind === 'api' && selectedNode.mode === 'managed' && <>
            <LinesField key={`${selectedNode.id}:scopes`} label="API permissions (one per line)" values={asStrings(selectedNode.settings.scopes)} disabled={!canWrite} onChange={values => updateSelected({ settings: { ...selectedNode.settings, scopes: values } })} />
            <Field label="Default token lifetime (seconds)">{props => <input {...props} type="number" min={1} max={86400} disabled={!canWrite}
              value={Number(selectedNode.settings.default_token_lifetime_seconds ?? 300)}
              onChange={event => updateSelected({ settings: { ...selectedNode.settings, default_token_lifetime_seconds: Number(event.target.value) } })} />}</Field>
          </>}
          {selectedNode.kind === 'role' && <Field label="What this role permits">{props => <textarea {...props} rows={2} disabled={!canWrite}
            value={String(selectedNode.settings.description ?? '')}
            onChange={event => updateSelected({ settings: { ...selectedNode.settings, description: event.target.value } })} />}</Field>}
          {selectedNode.kind === 'group' && <p className="muted">Use a lowercase machine name such as <code>engineering</code> as the stable identifier.</p>}
          {selectedNode.kind === 'api' && <p className="muted">The stable identifier is an absolute HTTPS resource URL.</p>}
          {selectedNode.kind === 'application' && selectedNode.mode === 'reference' && <p className="muted">Enter the existing application client ID as its identifier.</p>}
          {selectedNode.kind === 'identity_provider' && <p>Connect this provider to a group or user. This describes where identities come from; it does not configure sign-in.</p>}
          {selectedNode.kind === 'role' && <p>A role is a leaf: one application defines it, and groups may grant it.</p>}
          {canWrite && <Button onClick={removeSelected}>Remove object from diagram</Button>}
        </div>}
        </div>}
      {tab === 'connections' && <Panel title="Connections" description="Application → API; application → role; group → role; application → stream; identity provider → group or user.">
        <ul className="architecture-object-list">{graph.edges.map(edge => <li key={edge.id}>
          <span>{graph.nodes.find(node => node.id === edge.source)?.label} → {graph.nodes.find(node => node.id === edge.target)?.label}</span>
          {canWrite && <Button small onClick={() => change({ ...graph, edges: graph.edges.filter(item => item.id !== edge.id) })}>Remove</Button>}
        </li>)}</ul>
        {canWrite && <ConnectionForm graph={graph} onAdd={addConnection} />}
      </Panel>}
      {tab === 'review' && flow && <Panel title="Preview and apply" description="Preview checks every object, connection and required permission. Applying uses this exact saved revision.">
        <div className="architecture-toolbar">
          <Button disabled={dirty || planning || applying} onClick={preview}>{planning ? 'Checking…' : 'Preview changes'}</Button>
          {canWrite && plan?.applicable && <Button variant="primary" disabled={dirty || applying} onClick={apply}>{applying ? 'Applying…' : 'Apply this plan'}</Button>}
        </div>
        {dirty && <p className="muted">Save the diagram before previewing it.</p>}
        {flow.applied_revision != null && <p className="muted">Last fully applied revision: {flow.applied_revision}.</p>}
        {flow.last_apply_error && <p role="alert">Last apply stopped: {flow.last_apply_error}. Preview again to inspect progress.</p>}
        {plan && <>
          <p role="status">{plan.applicable ? 'Ready to apply.' : 'Resolve the conflicts below before applying.'} {plan.steps.length} planned items.</p>
          <ul className="architecture-plan-list">{plan.steps.map(step => <li key={step.id}>
            <strong>{step.label}</strong><span>{step.action}</span><span className="muted">{step.explanation || step.scope}</span>
          </li>)}</ul>
        </>}
      </Panel>}
      {tab === 'resources' && flow && <Panel title="Linked resources" description="Created resources keep this flow as their origin. Removing an object from the diagram never deletes its live resource.">
        {links.length === 0 ? <p className="muted">No resources linked yet. Apply a plan to create or attach them.</p> :
          <ul className="architecture-object-list">{links.map(link => <li key={link.node_id}>
            <span><strong>{graph.nodes.find(node => node.id === link.node_id)?.label ?? link.node_id}</strong>
              {' · '}{link.resource_kind} · {link.relation === 'managed' ? 'Created here' : 'Existing reference'}
              {link.state === 'pending' ? ' · Apply pending' : ''}
              {!graph.nodes.some(node => node.id === link.node_id) ? ' · Removed from draft; live resource kept' : ''}
              <small className="architecture-resource-id">{link.resource_id}</small></span>
            <a href={resourceHref(link)}>{resourceLabel(link.resource_kind)} →</a>
          </li>)}</ul>}
      </Panel>}

        {!flow && (tab === 'review' || tab === 'resources') && <p className="architecture-pane-content">Save this architecture first to review changes and track its resources.</p>}
      </aside>
    </div>
  </section>;
}

function LinesField({ label, values, disabled, onChange }: { label: string; values: string[]; disabled: boolean; onChange: (values: string[]) => void }): JSX.Element {
  const [text, setText] = useState(values.join('\n'));
  return <Field label={label} hint="One value per line.">{props => <textarea {...props} rows={4} value={text} disabled={disabled} onChange={event => { setText(event.target.value); onChange(lines(event.target.value)); }} />}</Field>;
}
function KeySource({ node, disabled, onChange, onValidity, draft, onDraft }: { draft: string | undefined; onDraft: (text: string) => void; node: ArchitectureNode; disabled: boolean; onValidity: (valid: boolean) => void; onChange: (settings: Record<string, unknown>) => void }): JSX.Element {
  const [mode, setMode] = useState(node.settings.jwks || draft !== undefined && draft !== '' ? 'json' : 'url');
  const [text, setText] = useState(draft ?? (node.settings.jwks ? JSON.stringify(node.settings.jwks, null, 2) : ''));
  const [error, setError] = useState('');
  const changeMode = (mode: string): void => { setMode(mode); setText(''); onDraft(''); setError(''); onValidity(true); const { jwks: _keys, jwks_uri: _uri, ...rest } = node.settings; onChange(mode === 'url' ? { ...rest, jwks_uri: '' } : rest); };
  const commit = (text: string): void => {
    try {
      const keys = JSON.parse(text) as { keys?: Record<string, unknown>[] };
      if (Object.keys(keys).length !== 1 || !Array.isArray(keys.keys) || keys.keys.length === 0 || keys.keys.some(key => !key || Object.keys(key).some(field => !['kty', 'kid', 'use', 'key_ops', 'alg', 'n', 'e', 'crv', 'x', 'y', 'x5c', 'x5t', 'x5t#S256', 'x5u'].includes(field)) || !['RSA', 'EC', 'OKP'].includes(String(key.kty)))) throw new Error('Paste a public JWKS with a non-empty keys array. Private and symmetric keys cannot be saved.');
      const { jwks_uri: _uri, ...rest } = node.settings; onChange({ ...rest, jwks: keys }); setError(''); onValidity(true);
    } catch (error) { onValidity(false); const { jwks: _keys, ...rest } = node.settings; onChange(rest); setError(error instanceof Error ? error.message : 'Invalid public JWKS'); }
  };
  return <><Field label="Application public keys">{props => <select {...props} value={mode} disabled={disabled} onChange={event => changeMode(event.target.value)}><option value="url">Fetch from a JWKS URL</option><option value="json">Paste public JWKS JSON</option></select>}</Field>
    {mode === 'url' ? <Field label="Public JWKS URL" hint="HTTPS endpoint published by your application.">{props => <input {...props} type="url" value={String(node.settings.jwks_uri ?? '')} disabled={disabled} onChange={event => onChange({ ...node.settings, jwks_uri: event.target.value })} />}</Field> : <Field label="Public JWKS JSON" hint="Paste the public key set. Never paste private keys.">{props => <textarea {...props} rows={9} value={text} disabled={disabled} onChange={event => { setText(event.target.value); onDraft(event.target.value); commit(event.target.value); }} spellCheck={false} />}</Field>}
    {error && <p role="alert">{error}</p>}</>;
}

function lines(value: string): string[] { return value.split('\n').map(item => item.trim()).filter(Boolean); }
function asStrings(value: unknown): string[] { return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []; }

function resourceLabel(kind: string): string {
  if (kind === 'application') return 'Open applications';
  if (kind === 'api') return 'Open resource servers';
  if (kind === 'group') return 'Open groups';
  if (kind === 'role') return 'Open roles';
  return 'Open architecture';
}
function resourceHref(link: ResourceLink): string {
  if (link.resource_kind === 'application') return hrefOf('clients');
  if (link.resource_kind === 'api') return hrefOf('resources');
  if (link.resource_kind === 'group') return hrefOf('groups');
  if (link.resource_kind === 'role') {
    try {
      const [client] = JSON.parse(link.resource_id) as [string, string];
      return hrefOf('roles', { client });
    } catch { return hrefOf('roles'); }
  }
  return hrefOf('architecture');
}

function ConnectionForm({ graph, onAdd }: { graph: Graph; onAdd: (source: string, target: string) => void }): JSX.Element {
  const [source, setSource] = useState('');
  const [target, setTarget] = useState('');
  return <div className="architecture-toolbar">
    <Field label="From">{props => <select {...props} value={source} onChange={event => setSource(event.target.value)}><option value="">Choose object</option>{graph.nodes.map(node => <option key={node.id} value={node.id}>{node.label}</option>)}</select>}</Field>
    <Field label="To">{props => <select {...props} value={target} onChange={event => setTarget(event.target.value)}><option value="">Choose object</option>{graph.nodes.filter(node => validConnection(graph, source, node.id)).map(node => <option key={node.id} value={node.id}>{node.label}</option>)}</select>}</Field>
    <Button disabled={!validConnection(graph, source, target)} onClick={() => { onAdd(source, target); setSource(''); setTarget(''); }}>Connect objects</Button>
  </div>;
}
