export interface GroupRow {
  readonly id: string;
  readonly name: string;
  readonly display_name: string;
  readonly revision: number;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface GroupPage {
  readonly items: readonly GroupRow[];
  readonly next_cursor: string | null;
}

export interface GroupMember {
  readonly user_id: string;
}

export interface MemberPage {
  readonly items: readonly GroupMember[];
  readonly next_cursor: string | null;
}

export interface RoleSource {
  readonly type: 'direct' | 'group';
  readonly group_id?: string;
  readonly group_name?: string | null;
  readonly group_display_name?: string | null;
}

export interface EffectiveAssignment {
  readonly name: string;
  readonly client_id: string | null;
  readonly sources: readonly RoleSource[];
}

/** Invalidates an account's effective-role view after a membership mutation. */
export const GROUP_MEMBERSHIP_CHANGED_EVENT = 'asterius:group-membership-changed';

export function groupPath(id: string): string {
  return `groups/${encodeURIComponent(id)}`;
}

export function memberPath(groupId: string, userId: string): string {
  return `${groupPath(groupId)}/members/${encodeURIComponent(userId)}`;
}

export function groupRolesPath(groupId: string): string {
  return `${groupPath(groupId)}/app-roles`;
}

export function groupRoleWithdrawPath(
  groupId: string,
  role: string,
  clientId: string | null,
): string {
  const base = groupPath(groupId);
  const name = encodeURIComponent(role);
  return clientId === null
    ? `${base}/app-roles/${name}`
    : `${base}/clients/${encodeURIComponent(clientId)}/app-roles/${name}`;
}

export function sourceLabel(source: RoleSource): string {
  if (source.type === 'direct') return 'Direct';
  if (source.group_display_name && source.group_name) {
    return `${source.group_display_name} (${source.group_name})`;
  }
  return source.group_display_name ?? source.group_name ?? 'Managed group';
}

export function hasDirectSource(assignment: EffectiveAssignment): boolean {
  return assignment.sources.some((source) => source.type === 'direct');
}
