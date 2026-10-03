/** Tenant-local public task snapshots. Neither audit rows nor this model authorize issuance. */
export interface TaskIdentity {
  readonly task_id: string; readonly root_grant_id: string; readonly owner_user_id: string;
  readonly initiating_client_id: string; readonly approval_revision: number; readonly label: string;
  readonly approved_at: string; readonly expires_at: string; readonly revoked_at: string | null;
  readonly state: string;
}
export interface Ceiling {
  readonly scopes: readonly string[]; readonly resources: readonly string[];
  readonly actions: readonly { readonly resource: string; readonly actions: readonly string[] }[];
  readonly resource_ceilings: readonly { readonly resource: string; readonly scopes: readonly string[]; readonly maximum_token_ttl_seconds: number }[];
  readonly max_delegation_depth: number;
}
export interface TaskPage { readonly items: readonly TaskIdentity[]; readonly next_cursor: string | null; readonly observed_at: string }
export interface GrantNode {
  readonly grant_id: string; readonly parent_grant_id: string | null; readonly client_id: string;
  readonly depth: number; readonly ancestry: readonly string[]; readonly state: string;
  readonly expires_at: string | null; readonly revoked_at: string | null;
  readonly recorded_ceiling: Ceiling; readonly current_issuance_ceiling: Ceiling;
}
export interface TaskSnapshot {
  readonly task: TaskIdentity; readonly approved_ceiling: Ceiling; readonly current_issuance_ceiling: Ceiling;
  readonly current_grant_types: readonly string[]; readonly maximum_new_token_ttl_seconds: number;
  readonly observed_at: string; readonly lineage: readonly GrantNode[]; readonly next_cursor: string | null;
  readonly conditional_decision: 'not_evaluated';
}
export function taskPageQuery(cursor?: string): string {
  const query = new URLSearchParams({ limit: '25' });
  if (cursor !== undefined) query.set('cursor', cursor);
  return `?${query.toString()}`;
}
/** Even a valid old snapshot must be refreshed before treating it as current. */
export function snapshotAge(observedAt: string, now = Date.now()): string {
  const age = now - Date.parse(observedAt);
  return !Number.isFinite(age) || age < 0 || age > 30_000 ? 'Refresh required' : 'Observed recently';
}

export interface LineageTreeNode {
  readonly id: string;
  node?: GrantNode;
  readonly children: LineageTreeNode[];
}
/** Bounded recorded paths; an absent parent row remains visibly incomplete. */
export function lineageTree(nodes: readonly GrantNode[]): readonly LineageTreeNode[] {
  const roots: LineageTreeNode[] = [];
  for (const node of nodes.slice(0, 50)) {
    const path = node.ancestry;
    // A corrupt/incomplete path cannot create a recursive browser structure.
    const safe = path.length > 0 && path.length <= 10 && new Set(path).size === path.length && path[path.length - 1] === node.grant_id;
    const ids = safe ? path : [node.grant_id];
    let branch = roots;
    for (const id of ids) {
      let entry = branch.find(candidate => candidate.id === id);
      if (entry === undefined) { entry = { id, children: [] }; branch.push(entry); }
      if (id === node.grant_id) entry.node = node;
      branch = entry.children;
    }
  }
  return roots;
}
