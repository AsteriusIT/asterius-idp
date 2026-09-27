import { useCallback, useEffect, useMemo, useState } from 'react';
import type { JSX } from 'react';
import {
  Background, Controls, Handle, MiniMap, Position, ReactFlow,
  applyEdgeChanges, applyNodeChanges,
  type Connection, type Edge as CanvasEdge, type EdgeChange,
  type Node as CanvasNode, type NodeChange,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { mutate, read, type Session } from './api';
import { validConnection, type ArchitectureNode, type Flow, type Graph, type Kind, type Mode } from './architecture-model';
import { toast } from './components/ui/toast';
import { Button, Field, LoadFailure, Panel, Screen, Skeleton } from './ui';

const TYPES: Readonly<Record<Kind, string>> = {
  application: 'Web application', api: 'API', group: 'Group', role: 'Role',
  stream: 'Security event stream', identity_provider: 'External identity provider',
};
interface CanvasData extends Record<string, unknown> { label: string; kind: Kind; identifier: string; mode: Mode }
function ArchitectureCard({ data }: { data: CanvasData }): JSX.Element {
  return <div className="architecture-card">
    <Handle type="target" position={Position.Left} />
    <span className="architecture-card-kind">{TYPES[data.kind]}</span>
    <strong>{data.label}</strong>
    <span className="muted">{data.identifier || 'Set an identifier'}</span>
    <Handle type="source" position={Position.Right} />
  </div>;
}
const NODE_TYPES = { architecture: ArchitectureCard };
const EMPTY: Graph = { schema_version: 1, nodes: [], edges: [] };

export function ArchitectureFlows({ session }: { session: Session }): JSX.Element {
  const [catalogue, setCatalogue] = useState<Flow[]>([]);
  const [load, setLoad] = useState<'loading' | 'ready' | 'failed'>('loading');
  const [failure, setFailure] = useState('');
  const [flow, setFlow] = useState<Flow | null>(null);
  const [name, setName] = useState('');
  const [graph, setGraph] = useState<Graph>(EMPTY);
  const [selected, setSelected] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [dirty, setDirty] = useState(false);
  const canWrite = session.scopes.includes('admin.flows:write');
  const refresh = useCallback(() => {
    setLoad('loading');
    read('flows').then(value => {
      setCatalogue((value as { items: Flow[] }).items); setLoad('ready');
    }, error => { setFailure(error instanceof Error ? error.message : 'Flows could not be loaded'); setLoad('failed'); });
  }, []);
  useEffect(refresh, [refresh]);
  const open = (item: Flow): void => {
    setFlow(item); setName(item.name); setGraph(item.graph); setSelected(null); setDirty(false);
  };
  const create = (): void => {
    setFlow(null); setName('Untitled architecture'); setGraph(EMPTY); setSelected(null); setDirty(false);
  };
  const change = (next: Graph): void => { setGraph(next); setDirty(true); };
  const save = (): void => {
    setBusy(true);
    const path = flow ? `flows/${encodeURIComponent(flow.id)}` : 'flows';
    const method = flow ? 'PUT' : 'POST';
    mutate(path, method, session, { name: name.trim(), graph, ...(flow ? { revision: flow.revision } : {}) }).then(value => {
      const saved = value as Flow;
      open(saved); refresh(); toast.success('Architecture saved', saved.name);
    }, error => toast.error('Architecture was not saved', error instanceof Error ? error.message : 'Try again')).finally(() => setBusy(false));
  };
  const addNode = (kind: Kind): void => {
    const id = crypto.randomUUID();
    const index = graph.nodes.length;
    change({ ...graph, nodes: [...graph.nodes, { id, kind, label: TYPES[kind], identifier: '', mode: 'managed', x: 60 + (index % 4) * 230, y: 80 + Math.floor(index / 4) * 150, settings: {} }] });
    setSelected(id);
  };
  const nodes: CanvasNode<CanvasData>[] = useMemo(() => graph.nodes.map(node => ({
    id: node.id, type: 'architecture', position: { x: node.x, y: node.y },
    data: { label: node.label, kind: node.kind, identifier: node.identifier, mode: node.mode },
    selected: node.id === selected,
  })), [graph.nodes, selected]);
  const edges: CanvasEdge[] = useMemo(() => graph.edges.map(edge => ({ ...edge, animated: false })), [graph.edges]);
  const onNodesChange = (changes: NodeChange<CanvasNode<CanvasData>>[]): void => {
    if (!canWrite || !changes.some(change => change.type === 'position' || change.type === 'remove')) return;
    const next = applyNodeChanges(changes, nodes);
    const live = new Set(next.map(node => node.id));
    change({ ...graph, nodes: graph.nodes.filter(node => live.has(node.id)).map(node => {
      const updated = next.find(item => item.id === node.id);
      return updated ? { ...node, x: updated.position.x, y: updated.position.y } : node;
    }), edges: graph.edges.filter(edge => live.has(edge.source) && live.has(edge.target)) });
  };
  const onEdgesChange = (changes: EdgeChange<CanvasEdge>[]): void => {
    if (!canWrite || !changes.some(change => change.type === 'remove')) return;
    const live = new Set(applyEdgeChanges(changes, edges).map(edge => edge.id));
    change({ ...graph, edges: graph.edges.filter(edge => live.has(edge.id)) });
  };
  const connect = (connection: Connection): void => {
    if (!connection.source || !connection.target || !validConnection(graph, connection.source, connection.target)) return;
    change({ ...graph, edges: [...graph.edges, { id: crypto.randomUUID(), source: connection.source, target: connection.target }] });
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
    if (validConnection(graph, source, target)) connect({ source, target, sourceHandle: null, targetHandle: null });
  };

  return <Screen title="Architecture builder" description="Draw how applications, APIs and access fit together. Save a draft before provisioning resources."
    actions={canWrite ? <Button variant="primary" onClick={create}>New architecture</Button> : undefined}>
    <Panel title="Saved architectures" description="Open a diagram to edit its layout and connections.">
      {load === 'loading' && <Skeleton rows={3} label="Reading architectures." />}
      {load === 'failed' && <LoadFailure message={failure} onRetry={refresh} />}
      {load === 'ready' && (catalogue.length === 0 ? <p className="muted">No architectures saved yet.</p> :
        <ul className="architecture-flow-list">{catalogue.map(item => <li key={item.id}>
          <button type="button" className="identity-link" onClick={() => open(item)}>{item.name}</button>
          <span className="muted">{item.graph.nodes.length} objects · Updated {new Date(item.updated_at).toLocaleString()}</span>
        </li>)}</ul>)}
    </Panel>
    {(flow || name) && <>
      <Panel title={flow ? `Edit ${flow.name}` : 'New architecture'} description="Use the canvas or the object and connection lists below. The diagram is a draft until you apply a plan.">
        <div className="architecture-toolbar">
          <Field label="Architecture name">{props => <input {...props} value={name} maxLength={120} disabled={!canWrite} onChange={event => { setName(event.target.value); setDirty(true); }} />}</Field>
          {canWrite && <Button variant="primary" disabled={busy || !dirty && Boolean(flow) || !name.trim()} onClick={save}>{busy ? 'Saving…' : 'Save diagram'}</Button>}
        </div>
        {dirty && <p role="status" className="muted">Unsaved changes</p>}
        {canWrite && <div className="architecture-palette" aria-label="Add object">
          {(Object.keys(TYPES) as Kind[]).map(kind => <Button key={kind} small onClick={() => addNode(kind)}>Add {TYPES[kind]}</Button>)}
        </div>}
        <div className="architecture-canvas" aria-label="Architecture diagram">
          <ReactFlow nodes={nodes} edges={edges} nodeTypes={NODE_TYPES} onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange} onConnect={connect}
            isValidConnection={connection => Boolean(connection.source && connection.target && validConnection(graph, connection.source, connection.target))}
            onNodeClick={(_, node) => setSelected(node.id)} nodesDraggable={canWrite} nodesConnectable={canWrite} elementsSelectable fitView>
            <Background /><MiniMap pannable zoomable /><Controls />
          </ReactFlow>
        </div>
      </Panel>
      <Panel title="Objects" description="Select an object to edit its display name and stable identifier. Reference objects are linked without being owned by this flow.">
        <ul className="architecture-object-list">{graph.nodes.map(node => <li key={node.id}>
          <button type="button" className="identity-link" onClick={() => setSelected(node.id)} aria-current={selected === node.id ? 'true' : undefined}>{node.label}</button>
          <span>{TYPES[node.kind]} · {node.mode === 'managed' ? 'Create with flow' : 'Existing reference'}</span>
        </li>)}</ul>
        {selectedNode && <div className="architecture-inspector">
          <Field label="Display name">{props => <input {...props} value={selectedNode.label} disabled={!canWrite} onChange={event => updateSelected({ label: event.target.value })} />}</Field>
          <Field label="Stable identifier">{props => <input {...props} value={selectedNode.identifier} disabled={!canWrite} onChange={event => updateSelected({ identifier: event.target.value })} />}</Field>
          <Field label="Ownership">{props => <select {...props} value={selectedNode.mode} disabled={!canWrite} onChange={event => updateSelected({ mode: event.target.value as Mode })}>
            <option value="managed">Create with flow</option><option value="reference">Existing reference</option>
          </select>}</Field>
          {canWrite && <Button onClick={removeSelected}>Remove object from diagram</Button>}
        </div>}
      </Panel>
      <Panel title="Connections" description="Application → API; application → role; group → role; application → stream; identity provider → application.">
        <ul className="architecture-object-list">{graph.edges.map(edge => <li key={edge.id}>
          <span>{graph.nodes.find(node => node.id === edge.source)?.label} → {graph.nodes.find(node => node.id === edge.target)?.label}</span>
          {canWrite && <Button small onClick={() => change({ ...graph, edges: graph.edges.filter(item => item.id !== edge.id) })}>Remove</Button>}
        </li>)}</ul>
        {canWrite && <ConnectionForm graph={graph} onAdd={addConnection} />}
      </Panel>
    </>}
  </Screen>;
}

function ConnectionForm({ graph, onAdd }: { graph: Graph; onAdd: (source: string, target: string) => void }): JSX.Element {
  const [source, setSource] = useState('');
  const [target, setTarget] = useState('');
  return <div className="architecture-toolbar">
    <Field label="From">{props => <select {...props} value={source} onChange={event => setSource(event.target.value)}><option value="">Choose object</option>{graph.nodes.map(node => <option key={node.id} value={node.id}>{node.label}</option>)}</select>}</Field>
    <Field label="To">{props => <select {...props} value={target} onChange={event => setTarget(event.target.value)}><option value="">Choose object</option>{graph.nodes.map(node => <option key={node.id} value={node.id}>{node.label}</option>)}</select>}</Field>
    <Button disabled={!validConnection(graph, source, target)} onClick={() => { onAdd(source, target); setSource(''); setTarget(''); }}>Connect objects</Button>
  </div>;
}
