export type Kind = 'application' | 'api' | 'group' | 'role' | 'stream' | 'identity_provider' | 'user' | 'gateway';
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
  live?: { current?: Record<string, unknown> | null; desired?: Record<string, unknown>; contract?: Record<string, unknown>; requires_credential?: boolean };
}
export interface Plan { flow_id: string; revision: number; digest: string; applicable: boolean; steps: PlanStep[] }
export interface ResourceLink {
  node_id: string; resource_kind: string; resource_id: string;
  relation: 'managed' | 'reference'; state: 'pending' | 'applied';
  created_in_revision: number; last_applied_revision: number | null;
}

const VALID_CONNECTIONS = new Set([
  'application:api', 'group:role', 'application:role',
  'application:stream', 'application:gateway', 'api:api', 'api:gateway', 'gateway:api', 'identity_provider:group', 'identity_provider:user',
]);

export function validConnection(graph: Graph, source: string, target: string): boolean {
  const from = graph.nodes.find(node => node.id === source);
  const to = graph.nodes.find(node => node.id === target);
  return Boolean(source !== target && from && to && VALID_CONNECTIONS.has(`${from.kind}:${to.kind}`) &&
    !graph.edges.some(edge => edge.source === source && edge.target === target));
}

/** BFF is a composition of supported resources, not a new provisioning kind. */
export function bffPreset(id: () => string = () => crypto.randomUUID(), y = 80): Graph {
  const application = id();
  const api = id();
  return { schema_version: 1, nodes: [
    { id: application, kind: 'application', label: 'BFF sign-in', identifier: '', mode: 'managed', x: 60, y,
      settings: { redirect_uris: [], jwks_uri: '' } },
    { id: api, kind: 'api', label: 'BFF API', identifier: '', mode: 'managed', x: 390, y,
      settings: { scopes: ['bff.access'], default_token_lifetime_seconds: 300 } },
  ], edges: [{ id: id(), source: application, target: api }] };
}

export function connectionLabel(source: Kind | undefined, target: Kind | undefined): string {
  if (source === 'gateway') return 'Routes to · context only';
  if (target === 'gateway' || source === 'api') return 'Calls · context only';
  if (target === 'role') return source === 'group' ? 'Grants' : 'Defines';
  if (source === 'identity_provider') return 'Supplies identities · context only';
  return target === 'api' ? 'Authorized API access' : 'Sends events · context only';
}

export function contextOnlyNode(kind: Kind, settings?: Record<string, unknown>): boolean {
  return ['gateway', 'user'].includes(kind) || (['stream', 'identity_provider'].includes(kind) && settings?.integration !== true);
}

/** Only changed provider nodes may carry an apply-only credential. Never spread graph settings. */
export function integrationCredentials(plan: Plan, draft: Record<string, string>): Record<string, string> {
  return Object.fromEntries(plan.steps.filter(step => step.kind === 'identity_provider' && ['create', 'retry', 'update'].includes(step.action) && draft[step.id])
    .map(step => [step.id, draft[step.id]!]));
}
export function missingIntegrationCredentials(plan: Plan, draft: Record<string, string>): boolean {
  return plan.steps.some(step => step.live?.requires_credential === true && !draft[step.id]);
}

export function contextOnlyConnection(source: Kind | undefined, target: Kind | undefined): boolean {
  return !((source === 'application' && (target === 'api' || target === 'role')) || (source === 'group' && target === 'role'));
}
