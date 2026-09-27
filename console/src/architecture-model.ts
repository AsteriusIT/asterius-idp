export type Kind = 'application' | 'api' | 'group' | 'role' | 'stream' | 'identity_provider' | 'user';
export type Mode = 'managed' | 'reference';
export interface ArchitectureNode {
  id: string; kind: Kind; label: string; identifier: string; mode: Mode;
  x: number; y: number; settings: Record<string, unknown>;
}
export interface ArchitectureEdge { id: string; source: string; target: string }
export interface Graph { schema_version: 1; nodes: ArchitectureNode[]; edges: ArchitectureEdge[] }
export interface Flow {
  id: string; name: string; graph: Graph; revision: number; updated_at: string;
  applied_revision?: number | null; last_apply_error?: string | null;
}

export interface PlanStep {
  id: string; label: string; kind: string; action: 'create' | 'update' | 'reference' | 'unchanged' | 'retry' | 'attach' | 'document' | 'detached' | 'conflict';
  scope: string; resource_id: string | null; explanation: string;
}
export interface Plan { flow_id: string; revision: number; digest: string; applicable: boolean; steps: PlanStep[] }
export interface ResourceLink {
  node_id: string; resource_kind: string; resource_id: string;
  relation: 'managed' | 'reference'; state: 'pending' | 'applied';
  created_in_revision: number; last_applied_revision: number | null;
}

const VALID_CONNECTIONS = new Set([
  'application:api', 'group:role', 'application:role',
  'application:stream', 'identity_provider:group', 'identity_provider:user',
]);

export function validConnection(graph: Graph, source: string, target: string): boolean {
  const from = graph.nodes.find(node => node.id === source);
  const to = graph.nodes.find(node => node.id === target);
  return Boolean(from && to && VALID_CONNECTIONS.has(`${from.kind}:${to.kind}`) &&
    !graph.edges.some(edge => edge.source === source && edge.target === target));
}
