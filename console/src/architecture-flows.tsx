import { FormSelect } from './components/ui/select';
import { memo, useCallback, useEffect, useState } from 'react';
import type { JSX } from 'react';
import { AppWindow, Database, Users, UserRound, ShieldCheck, Radio, LogIn, ArrowLeft, Plus, Pencil, Eye, Trash2, X, Network, Layers, Keyboard, List, LayoutGrid } from 'lucide-react';
import {
  Background, Controls, Handle, MiniMap, Position, ReactFlow, BaseEdge, EdgeLabelRenderer, getBezierPath,
  applyEdgeChanges, applyNodeChanges,
  type Edge as CanvasEdge, type EdgeChange,
  type Node as CanvasNode, type NodeChange, type EdgeProps,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { mutate, read, type Session } from './api';
import { bffPreset, connectionLabel, contextOnlyNode, contextOnlyConnection, validConnection, type ArchitectureNode, type Flow, type Graph, type Kind, type Mode, type Plan, type ResourceLink } from './architecture-model';
import { hrefOf, paramsOf } from './routes';
import { toast } from './components/ui/toast';
import { Button, ConfirmDialog, Field, LoadFailure, Panel, Screen, Skeleton } from './ui';

const TYPES: Readonly<Record<Kind, string>> = {
  application: 'Web application', api: 'API', group: 'Group', role: 'Role',
  stream: 'Security event stream', identity_provider: 'External identity provider', user: 'User', gateway: 'API gateway',
};
const ICONS = { application: AppWindow, api: Database, group: Users, user: UserRound, role: ShieldCheck, stream: Radio, identity_provider: LogIn, gateway: Network };
interface CanvasData extends Record<string, unknown> { label: string; kind: Kind; identifier: string; mode: Mode }
const ArchitectureCard = memo(function ArchitectureCard({ data }: { data: CanvasData }): JSX.Element {
  const Icon = ICONS[data.kind];
  const leaf = ['role', 'user', 'stream'].includes(data.kind);
  return <div className={`architecture-card ${data.kind === 'role' ? 'architecture-role-leaf' : ''} ${contextOnlyNode(data.kind) ? 'architecture-context-only' : ''}`}>
    {data.kind !== 'identity_provider' && <Handle type="target" position={Position.Left} />}
    <span className="architecture-card-kind"><Icon size={18} aria-hidden="true" />{TYPES[data.kind]}</span>
    <strong>{data.label}</strong>
    {data.kind !== 'role' && <span className="muted">{contextOnlyNode(data.kind) ? 'Context only' : data.kind === 'application' && data.mode === 'managed' ? 'Application' : data.identifier || 'Select to configure'}</span>}
    {!leaf && <Handle type="source" position={Position.Right} />}
  </div>;
});
const NODE_TYPES = { architecture: ArchitectureCard };

function ArchitectureLink(props: EdgeProps): JSX.Element {
  const [path, x, y] = getBezierPath(props);
  const remove = props.data?.remove as (() => void) | undefined;
  return <><BaseEdge path={path} style={{ ...(props.data?.contextOnly ? { strokeDasharray: '6 4' } : {}), ...(props.selected ? { stroke: 'var(--accent, #6366f1)', strokeWidth: 2 } : {}) }} />
    <EdgeLabelRenderer><div className="architecture-edge-label nodrag nopan" style={{ transform: `translate(-50%, -50%) translate(${x}px, ${y}px)` }}>
      <span>{props.label}</span>{props.selected && remove && <button type="button" title="Remove connection from diagram" aria-label="Remove connection from diagram" onClick={event => { event.stopPropagation(); remove(); }}><Trash2 size={15} /></button>}
    </div></EdgeLabelRenderer></>;
}
const EDGE_TYPES = { architecture: ArchitectureLink };

function FlowCanvas({ graph, writable, selected, selectedEdge, onEdgeSelect, onSelect, onChange }: { selected: string | null; selectedEdge: string | null; onEdgeSelect: (id: string | null) => void; graph: Graph; writable: boolean; onSelect: (id: string | null) => void; onChange: (graph: Graph) => void }): JSX.Element {
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
    return { ...edge, type: 'architecture', data: { contextOnly: contextOnlyConnection(from, to), remove: writable ? () => onChange({ ...graph, edges: graph.edges.filter(item => item.id !== edge.id) }) : undefined }, label: connectionLabel(from, to) };
  })), [graph, writable, onChange]);
  useEffect(() => {
    setNodes(current => current.map(node => ({ ...node, selected: node.id === selected })));
    setEdges(current => current.map(edge => ({ ...edge, selected: edge.id === selectedEdge })));
  }, [selected, selectedEdge]);
  const onNodesChange = useCallback((changes: NodeChange<CanvasNode<CanvasData>>[]) => setNodes(current => applyNodeChanges(changes, current)), []);
  const onEdgesChange = useCallback((changes: EdgeChange<CanvasEdge>[]) => setEdges(current => applyEdgeChanges(changes, current)), []);
  return <ReactFlow nodes={nodes} edges={edges} nodeTypes={NODE_TYPES} edgeTypes={EDGE_TYPES} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
    onNodeClick={(_, node) => { onSelect(node.id); onEdgeSelect(null); }} onPaneClick={() => { onSelect(null); onEdgeSelect(null); }} onEdgeClick={(_, edge) => { onSelect(null); onEdgeSelect(edge.id); }} nodesDraggable={writable} nodesConnectable={writable} deleteKeyCode={null}
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
  if (id || mode === 'new') return <ArchitectureWorkspace key={`${id ?? 'new'}:${mode ?? 'view'}`} session={session} flowId={id} editing={mode === 'edit' || mode === 'new'} templateRequested={params.get('template')} initialNode={params.get('node')} />;
  return <ArchitectureDirectory session={session} />;
}

function ArchitectureDirectory({ session }: { session: Session }): JSX.Element {
  const [items, setItems] = useState<Flow[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const refresh = useCallback(() => { setLoading(true); setError(''); read('flows').then(value => setItems((value as { items: Flow[] }).items), error => setError(String(error))).finally(() => setLoading(false)); }, []);
  useEffect(refresh, [refresh]);
  return <Screen title="Architectures" description="Plan your applications and access, then manage the resources they create."
    actions={session.scopes.includes('admin.flows:write') ? <div className="architecture-toolbar"><a className="architecture-action" href={hrefOf('architecture', { mode: 'new', template: 'web' })}>Web app + API template</a><a className="architecture-action" href={hrefOf('architecture', { mode: 'new', template: 'bff' })}><Layers size={16} />BFF template</a><a className="architecture-action primary" href={hrefOf('architecture', { mode: 'new' })}><Plus size={16} />New architecture</a></div> : undefined}>
    <Panel title="Saved architectures">
      {loading ? <Skeleton rows={3} label="Loading architectures" /> : error ? <LoadFailure message={error} onRetry={refresh} /> : items.length === 0 ? <p>Create your first architecture from a template or start with a blank canvas.</p> :
        <div className="architecture-directory">{items.map(item => <article key={item.id}><AppWindow aria-hidden="true" /><div><h2><a href={hrefOf('architecture', { flow: item.id })}>{item.name}</a></h2><p>{item.graph.nodes.length} objects · {item.applied_revision === item.revision ? 'Applied' : 'Draft changes'}</p><small>Updated {new Date(item.updated_at).toLocaleString()}</small></div><a aria-label={`View ${item.name}`} href={hrefOf('architecture', { flow: item.id })}><Eye size={18} />View</a>{session.scopes.includes('admin.flows:write') && <a aria-label={`Edit ${item.name}`} href={hrefOf('architecture', { flow: item.id, mode: 'edit' })}><Pencil size={18} />Edit</a>}</article>)}</div>}
    </Panel>
  </Screen>;
}

/** Flow identifiers are UUIDs, never arbitrary URL segments from a response or hash. */
function flowPath(id: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    throw new Error('Invalid architecture identifier');
  }
  return `flows/${encodeURIComponent(id)}`;
}
const PANE_LABELS = { object: 'Settings', review: 'Review', resources: 'Resources' };
const EMPTY: Graph = { schema_version: 1, nodes: [], edges: [] };

function ArchitectureWorkspace({ session, flowId, editing, templateRequested, initialNode }: { session: Session; flowId: string | null; editing: boolean; templateRequested: string | null; initialNode: string | null }): JSX.Element {
  const [loadError, setLoadError] = useState('');
  const [tab, setTab] = useState<'object' | 'review' | 'resources'>('object');
  const [flow, setFlow] = useState<Flow | null>(null);
  const [name, setName] = useState('');
  const [graph, setGraph] = useState<Graph>(EMPTY);
  const [selected, setSelected] = useState<string | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<string | null>(null);
  const [listView, setListView] = useState(false);
  const [connectionSource, setConnectionSource] = useState('');
  const [connectionTarget, setConnectionTarget] = useState('');
  const [pendingRemoval, setPendingRemoval] = useState<string | null>(null);
  const [pendingNavigation, setPendingNavigation] = useState<string | null>(null);
  const [showShortcuts, setShowShortcuts] = useState(false);
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
    if (!flowId) { if (templateRequested === 'bff') { setName('Backend for frontend'); setGraph(bffPreset()); setDirty(true); } else if (templateRequested === 'web') template(); else create(); return; }
    const target = flowId;
    let active = true;
    Promise.resolve().then(() => read(flowPath(target))).then(value => {
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
    read(flowPath(flow.id) + '/links').then(
      value => { if (active) setLinks((value as { items: ResourceLink[] }).items); },
      () => { if (active) setLinks([]); },
    );
    return () => { active = false; };
  }, [flow?.id, flow?.applied_revision, linkRefresh, session.workspace]);
  const open = (item: Flow): void => {
    setFlow(item); setName(item.name); setGraph(item.graph); setSelected(null); setSelectedEdge(null); setDirty(false); setPlan(null); setLinkRefresh(value => value + 1);
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
  const change = useCallback((next: Graph): void => { setGraph(next); setDirty(true); setPlan(null); }, []);
  const save = (): void => {
    if (!canWrite || hasInvalidKeys || !name.trim() || (!dirty && flow)) return;
    setBusy(true);
    const path = flow ? flowPath(flow.id) : 'flows';
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
    mutate(flowPath(flow.id) + '/plan', 'POST', session, { revision: flow.revision }).then(value => {
      setPlan(value as Plan);
    }, error => toast.error('Preview could not be built', error instanceof Error ? error.message : 'Try again')).finally(() => setPlanning(false));
  };
  const apply = (): void => {
    if (!flow || !plan?.applicable) return;
    setApplying(true);
    mutate(flowPath(flow.id) + '/apply', 'POST', session, { revision: plan.revision, digest: plan.digest }).then(() => {
      setLinkRefresh(value => value + 1);
      toast.success('Architecture applied', 'Created resources are now linked to this flow.');
      read(flowPath(flow.id)).then(value => open(value as Flow), () => refresh());
      refresh();
    }, error => {
      setLinkRefresh(value => value + 1);
      setPlan(null);
      toast.error('Apply stopped', error instanceof Error ? error.message : 'Preview the flow again to inspect partial progress.');
      read(flowPath(flow.id)).then(value => open(value as Flow), () => refresh());
    }).finally(() => setApplying(false));
  };
  const addNode = (kind: Kind): void => {
    setSelectedEdge(null);
    const id = crypto.randomUUID();
    const index = graph.nodes.length;
    const settings = initialSettings(kind);
    change({ ...graph, nodes: [...graph.nodes, { id, kind, label: TYPES[kind], identifier: '', mode: kind === 'stream' || kind === 'identity_provider' || kind === 'user' || kind === 'gateway' ? 'reference' : 'managed', x: 60 + (index % 4) * 230, y: 80 + Math.floor(index / 4) * 150, settings }] });
    setSelected(id);
  };
  const addBff = (): void => {
    setSelectedEdge(null);
    const next = bffPreset(() => crypto.randomUUID(), Math.max(0, ...graph.nodes.map(node => node.y)) + 180);
    change({ ...graph, nodes: [...graph.nodes, ...next.nodes], edges: [...graph.edges, ...next.edges] });
    setSelected(next.nodes[0]!.id); setTab('object');
  };
  const selectedNode = graph.nodes.find(node => node.id === selected);
  const updateSelected = (patch: Partial<ArchitectureNode>): void => {
    change({ ...graph, nodes: graph.nodes.map(node => node.id === selected ? { ...node, ...patch } : node) });
  };
  const removeNode = (id: string): void => {
    change({ ...graph, nodes: graph.nodes.filter(node => node.id !== id), edges: graph.edges.filter(edge => edge.source !== id && edge.target !== id) });
    setSelected(null);
  };
  const removalNode = graph.nodes.find(node => node.id === pendingRemoval);

  useEffect(() => {
    if (!dirty) return;
    const prevent = (event: BeforeUnloadEvent): void => { event.preventDefault(); };
    window.addEventListener('beforeunload', prevent);
    return () => window.removeEventListener('beforeunload', prevent);
  }, [dirty]);
  useEffect(() => {
    const deleteSelection = (event: KeyboardEvent): void => {
      if (!selected && !selectedEdge) return;
      event.preventDefault();
      if (selected) setPendingRemoval(selected);
      else change({ ...graph, edges: graph.edges.filter(edge => edge.id !== selectedEdge) });
      setSelectedEdge(null);
    };
    const handleKey = (event: KeyboardEvent): void => {
      if (event.defaultPrevented || event.isComposing || event.repeat || (flowId && !flow) || loadError) return;
      const target = event.target instanceof Element ? event.target : null;
      if (target?.closest('[role="dialog"], [role="alertdialog"]')) return;
      if (isSaveShortcut(event)) {
        event.preventDefault(); save(); return;
      }
      if (event.ctrlKey || event.metaKey || event.altKey || target?.closest('input, textarea, select, [contenteditable="true"], [role="textbox"], [role="combobox"]')) return;
      if (event.key === '?') { event.preventDefault(); setShowShortcuts(value => !value); return; }
      if (event.key === 'Escape') { event.preventDefault(); setSelected(null); setSelectedEdge(null); setTab('object'); setShowShortcuts(false); return; }
      if (!canWrite) return;
      if (event.key === 'Delete' || event.key === 'Backspace') { deleteSelection(event); return; }
      if (event.shiftKey) return;
      const kind = ({ a: 'application', i: 'api', g: 'gateway' } as const)[event.key.toLowerCase() as 'a' | 'i' | 'g'];
      if (kind) { event.preventDefault(); addNode(kind); setTab('object'); setSelectedEdge(null); }
      else if (event.key.toLowerCase() === 'b') { event.preventDefault(); addBff(); setSelectedEdge(null); }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  });
  const navigate = (href: string): void => {
    if (dirty) setPendingNavigation(href);
    else window.location.hash = href;
  };
  if (loadError) return <Screen title="Architecture"><LoadFailure message={loadError} onRetry={() => window.location.reload()} /><a href={hrefOf('architecture')}>Back to architectures</a></Screen>;
  if (flowId && !flow) return <Skeleton rows={5} label="Loading architecture" />;
  return <section className="architecture-workspace" aria-label={editing ? 'Architecture editor' : 'Architecture viewer'}>
    <WorkspaceHeader name={name} session={session} editing={editing} dirty={dirty} applying={applying} busy={busy}
      canWrite={canWrite} hasInvalidKeys={hasInvalidKeys} flow={flow} planning={planning} showShortcuts={showShortcuts}
      save={save} navigate={navigate} onReview={() => { setSelected(null); setTab('review'); preview(); }}
      onShortcuts={() => setShowShortcuts(value => !value)} />
    {showShortcuts && <div className="architecture-shortcuts" role="region" aria-label="Keyboard shortcuts guide"><span><kbd>Ctrl/Cmd + S</kbd> Save draft</span><span><kbd>A</kbd> Web app</span><span><kbd>I</kbd> API</span><span><kbd>G</kbd> Gateway</span><span><kbd>B</kbd> BFF</span><span><kbd>Delete / Backspace</kbd> Remove selected object or connection from diagram</span><span><kbd>Escape</kbd> Architecture settings</span><span><kbd>?</kbd> Toggle this guide</span><small>Single-key shortcuts pause while typing. Editing shortcuts require edit access. Removing a linked object keeps its live resource.</small></div>}
    <div className="architecture-workspace-body">
      <div className="architecture-stage">
        <div className="architecture-stage-toolbar">
        {canWrite && <div className="architecture-palette" aria-label="Add an object"><Button variant="ghost" small title="Add backend for frontend preset (B)" aria-keyshortcuts="B" onClick={addBff}><Layers size={18} />BFF</Button>{(Object.keys(TYPES) as Kind[]).map(kind => { const Icon = ICONS[kind]; return <Button variant="ghost" key={kind} small title={`Add ${TYPES[kind].toLowerCase()}`} aria-label={`Add ${TYPES[kind].toLowerCase()}`} onClick={() => { addNode(kind); setTab('object'); }}><Icon size={18} />{(kind === 'identity_provider' || kind === 'stream' || kind === 'gateway') && TYPES[kind]}</Button>; })}</div>}
        <div className="architecture-view-switch"><Button small aria-pressed={listView} onClick={() => setListView(value => !value)}>{listView ? <LayoutGrid aria-hidden="true" /> : <List aria-hidden="true" />}{listView ? 'Show canvas' : 'Show object list'}</Button></div>
        </div>
        {listView ? <div className="architecture-object-list" aria-label="Architecture objects">
          <p className="muted">Select an object to configure it. Changes affect this draft until reviewed and applied.</p>
          <ul>{graph.nodes.map(node => <li key={node.id}><Button aria-pressed={selected === node.id} onClick={() => { setSelected(node.id); setTab('object'); }}>{node.label} · {TYPES[node.kind]}</Button>{canWrite && <Button small variant="danger" onClick={() => setPendingRemoval(node.id)}>Remove {node.label}</Button>}</li>)}</ul>
          <h2>Connections</h2>
          <ul>{graph.edges.map(edge => <li key={edge.id}><span>{graph.nodes.find(node => node.id === edge.source)?.label} → {graph.nodes.find(node => node.id === edge.target)?.label}</span>{canWrite && <Button small onClick={() => change({ ...graph, edges: graph.edges.filter(item => item.id !== edge.id) })}>Remove connection</Button>}</li>)}</ul>
          {canWrite && <form onSubmit={event => { event.preventDefault(); if (validConnection(graph, connectionSource, connectionTarget)) { change({ ...graph, edges: [...graph.edges, { id: crypto.randomUUID(), source: connectionSource, target: connectionTarget }] }); setConnectionTarget(''); } }}>
            <Field label="Connect from">{props => <FormSelect {...props} value={connectionSource} onValueChange={value => { setConnectionSource(value); setConnectionTarget(''); }} options={[{ value: '', label: 'Choose an object' }, ...graph.nodes.map(node => ({ value: node.id, label: node.label }))]} />}</Field>
            <Field label="Connect to">{props => <FormSelect {...props} value={connectionTarget} onValueChange={setConnectionTarget} options={[{ value: '', label: 'Choose a compatible object' }, ...graph.nodes.filter(node => validConnection(graph, connectionSource, node.id)).map(node => ({ value: node.id, label: node.label }))]} />}</Field>
            <Button type="submit" disabled={!validConnection(graph, connectionSource, connectionTarget)}>Add connection</Button>
          </form>}
        </div> : <div className="architecture-stage-canvas"><FlowCanvas graph={graph} writable={canWrite} selected={selected} selectedEdge={selectedEdge} onEdgeSelect={setSelectedEdge} onSelect={id => { setSelected(id); setTab('object'); }} onChange={change} /></div>}
      </div>
      <aside className="architecture-sidepane" aria-label="Architecture details">
        {graph.edges.some(edge => !validConnection({ ...graph, edges: graph.edges.filter(item => item.id !== edge.id) }, edge.source, edge.target)) && <p role="alert" className="architecture-pane-content">This diagram has an unsupported link. Select the link on the canvas to remove it. Identity providers can connect only to groups or users.</p>}
        {selectedNode ? <div className="architecture-pane-heading"><strong>{TYPES[selectedNode.kind]}</strong><Button variant="ghost" className="architecture-icon-button" small title="Architecture settings (Escape)" aria-label="Architecture settings" onClick={() => { setSelected(null); setTab('object'); }}><X size={18} /></Button></div> :
          <nav className="architecture-pane-tabs" aria-label="Architecture settings sections">{(['object', 'review', 'resources'] as const).map(value => <button type="button" key={value} aria-pressed={tab === value} onClick={() => setTab(value)}>{PANE_LABELS[value]}</button>)}</nav>}
        {tab === 'object' && <div className="architecture-pane-content">
          {!selectedNode && <><h2>Architecture settings</h2><Field label="Architecture name">{props => <input {...props} value={name} maxLength={120} disabled={!canWrite} onChange={event => { setName(event.target.value); setDirty(true); setPlan(null); }} />}</Field>
            <p className="muted">BFF adds a sign-in application and API with bff.access permission and a five-minute token lifetime. Add callbacks, public keys and the API audience before applying. API chains and gateways are context only. Select an object to edit it. Drag between handles to connect objects. Select a connection to remove it. Click the canvas background to return here.</p><Button onClick={() => navigate(hrefOf('help'))}>Developer integration guide</Button></>}
        {selectedNode && <NodeInspector selectedNode={selectedNode} canWrite={canWrite} links={links}
          keyDraft={keyDrafts[selectedNode.id]} onKeyDraft={text => setKeyDrafts(current => ({ ...current, [selectedNode.id]: text }))}
          onKeyValidity={valid => setInvalidKeys(current => ({ ...current, [selectedNode.id]: !valid }))}
          updateSelected={updateSelected} onRemove={() => setPendingRemoval(selectedNode.id)} />}
        </div>}
      {tab === 'review' && flow && <ReviewPanel flow={flow} dirty={dirty} planning={planning} applying={applying} canWrite={canWrite} plan={plan} preview={preview} apply={apply} />}
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
    {pendingNavigation !== null && <ConfirmDialog title="Discard unsaved architecture changes?"
      body="Leaving this architecture will discard changes that have not been saved as a draft."
      confirmLabel="Discard and leave" onCancel={() => setPendingNavigation(null)}
      onConfirm={() => { const href = pendingNavigation; setPendingNavigation(null); window.location.hash = href; }} />}
    {removalNode !== undefined && <ConfirmDialog
      title={links.some(link => link.node_id === removalNode.id) ? `Remove ${removalNode.label} from the diagram?` : `Delete ${removalNode.label} from the draft?`}
      body={links.some(link => link.node_id === removalNode.id)
        ? 'The linked live resource remains in place. This removes only the diagram object and its connections.'
        : 'This removes the draft object and all its diagram connections. Save the draft afterward to keep the change.'}
      confirmLabel={links.some(link => link.node_id === removalNode.id) ? 'Remove from diagram' : 'Delete draft object'}
      onCancel={() => setPendingRemoval(null)}
      onConfirm={() => { const id = removalNode.id; setPendingRemoval(null); removeNode(id); }} />}
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
  return <><Field label="Application public keys">{props => <FormSelect {...props} value={mode} disabled={disabled} onValueChange={changeMode} options={[{ value: 'url', label: 'Fetch from a JWKS URL' }, { value: 'json', label: 'Paste public JWKS JSON' }]} />}</Field>
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

const IDENTIFIER_LABELS: Record<Kind, string> = { user: 'Username', gateway: 'Gateway address (optional)', api: 'API audience URL', role: 'Role name', group: 'Group machine name', application: 'Identifier', identity_provider: 'Identifier', stream: 'Identifier' };
function NodeInspector({ selectedNode, canWrite, links, keyDraft, onKeyDraft, onKeyValidity, updateSelected, onRemove }: Readonly<{
  selectedNode: ArchitectureNode; canWrite: boolean; links: ResourceLink[]; keyDraft: string | undefined;
  onKeyDraft: (text: string) => void; onKeyValidity: (valid: boolean) => void;
  updateSelected: (patch: Partial<ArchitectureNode>) => void; onRemove: () => void;
}>): JSX.Element {
  return <div className="architecture-inspector">
          <Field label="Display name">{props => <input {...props} value={selectedNode.label} disabled={!canWrite} onChange={event => updateSelected({ label: event.target.value })} />}</Field>
          {(selectedNode.kind !== 'application' || selectedNode.mode === 'reference') &&
            <Field label={IDENTIFIER_LABELS[selectedNode.kind]}>{props => <input {...props} value={selectedNode.identifier} disabled={!canWrite} onChange={event => updateSelected({ identifier: event.target.value })} />}</Field>}
          <Field label="Ownership">{props => <FormSelect {...props} value={selectedNode.mode} disabled={!canWrite || contextOnlyNode(selectedNode.kind)} onValueChange={value => updateSelected({ mode: value as Mode })} options={[{ value: 'managed', label: 'Create with flow' }, { value: 'reference', label: contextOnlyNode(selectedNode.kind) ? 'Diagram context only' : 'Existing reference' }]} />}</Field>
          {(contextOnlyNode(selectedNode.kind)) &&
            <p className="muted">Shown for architecture context. Apply does not configure or verify this integration.</p>}
          {selectedNode.kind === 'application' && selectedNode.mode === 'managed' && <>
            <LinesField key={`${selectedNode.id}:redirects`} label="Sign-in callback URLs" values={asStrings(selectedNode.settings.redirect_uris)} disabled={!canWrite} onChange={values => updateSelected({ settings: { ...selectedNode.settings, redirect_uris: values } })} />
            <KeySource key={selectedNode.id} node={selectedNode} draft={keyDraft} onDraft={onKeyDraft} disabled={!canWrite} onValidity={onKeyValidity} onChange={settings => updateSelected({ settings })} />
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
          {selectedNode.kind === 'api' && <p className="muted">Use the exact HTTPS audience URL. API-to-API and API-to-gateway links describe calls only; they do not grant access or configure token exchange.</p>}
          {selectedNode.kind === 'application' && selectedNode.mode === 'reference' && <p className="muted">Enter the existing application client ID as its identifier.</p>}
          {selectedNode.kind === 'identity_provider' && <p>Connect this provider to a group or user. This describes where identities come from; it does not configure sign-in.</p>}
          {selectedNode.kind === 'gateway' && <p>A gateway describes routing in your architecture. Connect applications or APIs to it, then connect it to downstream APIs. Apply does not deploy routes, credentials or access policies.</p>}
          {selectedNode.kind === 'application' && selectedNode.mode === 'managed' && <p className="muted">Creates a confidential FAPI client with private_key_jwt, PAR and DPoP. For a BFF, keep tokens and signing keys on the server and implement a browser session cookie in your application.</p>}
          {selectedNode.kind === 'role' && <p>A role is a leaf: one application defines it, and groups may grant it.</p>}
          {canWrite && <Button variant="danger" onClick={onRemove}><Trash2 size={16} />{links.some(link => link.node_id === selectedNode.id) ? 'Remove from diagram' : 'Delete draft object'}</Button>}
          {links.some(link => link.node_id === selectedNode.id) && <p className="muted">This object has a linked resource. Removing it from the diagram keeps the live resource.</p>}
        </div>;
}

function workspaceState(editing: boolean, dirty: boolean): string {
  if (!editing) return 'Viewing saved architecture';
  return dirty ? 'Unsaved changes' : 'Editing draft';
}

function WorkspaceHeader({ name, session, editing, dirty, applying, busy, canWrite, hasInvalidKeys, flow, planning, showShortcuts, save, navigate, onReview, onShortcuts }: Readonly<{
  name: string; session: Session; editing: boolean; dirty: boolean; applying: boolean; busy: boolean;
  canWrite: boolean; hasInvalidKeys: boolean; flow: Flow | null; planning: boolean; showShortcuts: boolean;
  save: () => void; navigate: (href: string) => void; onReview: () => void; onShortcuts: () => void;
}>): JSX.Element {
  return <header className="architecture-workspace-header">
      <Button variant="ghost" className="architecture-icon-button" title="Back to architectures" aria-label="Back to architectures" onClick={() => navigate(hrefOf('architecture'))} disabled={applying || busy}><ArrowLeft size={18} /></Button>
      <div className="architecture-title"><strong>{name}</strong><small>{session.workspace} · {workspaceState(editing, dirty)}</small></div>
      {editing ? <><Button disabled={!canWrite || hasInvalidKeys || !name.trim() || !dirty && Boolean(flow)} aria-keyshortcuts="Control+s Meta+s" title="Save draft (Ctrl/Cmd+S)" onClick={save}>{busy ? 'Saving…' : 'Save draft'}</Button>{flow && <Button variant="ghost" className="architecture-icon-button" disabled={busy || applying} title="View architecture" aria-label="View architecture" onClick={() => navigate(hrefOf('architecture', { flow: flow.id }))}><Eye size={18} /></Button>}</> : session.scopes.includes('admin.flows:write') && flow && <Button onClick={() => navigate(hrefOf('architecture', { flow: flow.id, mode: 'edit' }))}><Pencil size={16} />Edit architecture</Button>}
      {flow && <Button disabled={dirty || planning || applying} onClick={onReview}>{planning ? 'Checking…' : 'Review changes'}</Button>}
      <Button variant="ghost" className="architecture-icon-button" title="Keyboard shortcuts (?)" aria-label="Keyboard shortcuts" aria-expanded={showShortcuts} onClick={onShortcuts}><Keyboard size={18} /></Button>
    </header>;
}

function isSaveShortcut(event: KeyboardEvent): boolean {
  return (event.ctrlKey || event.metaKey) && !event.altKey && !event.shiftKey && event.key.toLowerCase() === 's';
}

function initialSettings(kind: Kind): Record<string, unknown> {
  switch (kind) {
    case 'application': return { redirect_uris: [], jwks_uri: '' };
    case 'api': return { scopes: [], default_token_lifetime_seconds: 300 };
    case 'role': return { description: '' };
    default: return {};
  }
}

function ReviewPanel({ flow, dirty, planning, applying, canWrite, plan, preview, apply }: Readonly<{
  flow: Flow; dirty: boolean; planning: boolean; applying: boolean; canWrite: boolean;
  plan: Plan | null; preview: () => void; apply: () => void;
}>): JSX.Element {
  return <Panel title="Preview and apply" description="Preview checks every object, connection and required permission. Applying uses this exact saved revision.">
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
      </Panel>;
}
