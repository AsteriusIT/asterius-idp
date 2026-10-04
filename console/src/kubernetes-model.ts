export interface ClusterProfile {
  cluster_id: string; namespace: string; group_ids: string[]; revision: number;
  client_id: string; issuer: string; audience: string; registration_compatible?: boolean;
  authentication_configuration: unknown; rbac_bindings: unknown[]; legacy_flags: string[];
}
export interface OnlineProfile { enabled: boolean; reviewer_client_id: string; revision: string }
export function profilePath(client: string): string { return `clients/${encodeURIComponent(client)}/kubernetes`; }
export function profileChange(profile: ClusterProfile | null, cluster: string, namespace: string, groups: readonly string[]) {
  return {cluster_id: profile?.cluster_id ?? cluster, namespace, group_ids: [...new Set(groups)], revision: profile?.revision ?? 0};
}
export function shellQuote(value: string): string { return `'${value.replaceAll("'", "'\\''")}'`; }
export function loginCommand(cluster: string, account: string): string {
  return `node tools/kubernetes-login/src/helper.mjs kubeconfig --config /etc/asterius/kube-helper.json --cluster ${shellQuote(cluster)} --account ${shellQuote(account)} > reviewed-kubeconfig.json\nkubectl --kubeconfig reviewed-kubeconfig.json get pods`;
}
export function authenticationLabel(online: OnlineProfile | null, jit: boolean): string {
  return jit ? 'Temporary identity' : online?.enabled ? 'Online checks enabled' : 'Signed tokens';
}
export async function mapBounded<T, R>(items: readonly T[], operation: (item: T) => Promise<R>): Promise<R[]> {
  const result = new Array<R>(items.length); let next = 0;
  await Promise.all(Array.from({length: Math.min(4, items.length)}, async () => {
    while (next < items.length) { const index = next++; result[index] = await operation(items[index]!); }
  }));
  return result;
}
