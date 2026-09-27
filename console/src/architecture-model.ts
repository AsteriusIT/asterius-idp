export type Kind = 'application' | 'api' | 'group' | 'role' | 'stream' | 'identity_provider';
export type Mode = 'managed' | 'reference';
export interface ArchitectureNode {
  id: string; kind: Kind; label: string; identifier: string; mode: Mode;
  x: number; y: number; settings: Record<string, unknown>;
}
export interface ArchitectureEdge { id: string; source: string; target: string }
export interface Graph { schema_version: 1; nodes: ArchitectureNode[]; edges: ArchitectureEdge[] }
export interface Flow { id: string; name: string; graph: Graph; revision: number; updated_at: string }

const VALID_CONNECTIONS = new Set([
  'application:api', 'group:role', 'application:role',
  'application:stream', 'identity_provider:application',
]);

export function validConnection(graph: Graph, source: string, target: string): boolean {
  const from = graph.nodes.find(node => node.id === source);
  const to = graph.nodes.find(node => node.id === target);
  return Boolean(from && to && VALID_CONNECTIONS.has(`${from.kind}:${to.kind}`) &&
    !graph.edges.some(edge => edge.source === source && edge.target === target));
}
