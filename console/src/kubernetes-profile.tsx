import { useEffect, useState } from 'react';
import type { JSX } from 'react';
import { ApiError, mutate, read, type Session } from './api';
import { YamlView } from './components/yaml-view';
import { Button, Field, Message, Panel } from './ui';

interface Profile {
  readonly cluster_id: string;
  readonly namespace: string;
  readonly group_ids: readonly string[];
  readonly revision: number;
  readonly registration_compatible?: boolean;
}

/** The saved audience owns this release policy; draft registration is never exported. */
export function KubernetesProfileSetup({ clientId, session, canWrite }: {
  readonly clientId: string; readonly session: Session; readonly canWrite: boolean;
}): JSX.Element {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [cluster, setCluster] = useState('');
  const [namespace, setNamespace] = useState('default');
  const [groups, setGroups] = useState('');
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const path = `clients/${encodeURIComponent(clientId)}/kubernetes`;
  useEffect(() => {
    let current = true;
    setBusy(true);
    setProfile(null);
    setError(null);
    setCluster('');
    setNamespace('default');
    setGroups('');
    read(path).then((value) => {
      if (!current) return;
      const saved = value as Profile;
      setProfile(saved); setCluster(saved.cluster_id); setNamespace(saved.namespace); setGroups(saved.group_ids.join('\n'));
    }).catch((failure: unknown) => {
      if (current && !(failure instanceof ApiError && failure.status === 404)) {
        setError(failure instanceof Error ? failure.message : 'The cluster profile could not be loaded.');
      }
    }).finally(() => { if (current) setBusy(false); });
    return () => { current = false; };
  }, [path]);

  async function save(): Promise<void> {
    setBusy(true); setError(null);
    try {
      const saved = await mutate(path, 'PUT', session, {
        cluster_id: cluster, namespace,
        group_ids: groups.split(/\s+/).filter(Boolean), revision: profile?.revision ?? 0,
      }) as Profile;
      setProfile(saved);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'The cluster profile could not be saved.');
    } finally { setBusy(false); }
  }

  return <Panel title="Kubernetes access">
    <p>Use one broker application per cluster. People sign in with a stable identity, and only the groups selected below are included in their cluster credentials.</p>
    {error !== null && <Message tone="error">{error}</Message>}
    {profile?.registration_compatible === false && <Message tone="error">The application registration no longer matches this cluster profile. Restore the broker security settings before issuing cluster credentials.</Message>}
    <Field label="Cluster identifier" hint="A unique lowercase DNS label in this workspace, fixed after creation. Use a separate application for another cluster.">{(props) => <input {...props} value={cluster} disabled={busy || !canWrite || profile !== null} onChange={(event) => setCluster(event.target.value)} />}</Field>
    <Field label="Example RBAC namespace">{(props) => <input {...props} value={namespace} disabled={busy || !canWrite} onChange={(event) => setNamespace(event.target.value)} />}</Field>
    <Field label="Released managed groups" hint="Stable managed-group UUIDs, one per line; at most 100. An empty list releases no group memberships.">{(props) => <textarea {...props} value={groups} disabled={busy || !canWrite} onChange={(event) => setGroups(event.target.value)} />}</Field>
    <Button disabled={busy || !canWrite} onClick={() => { void save(); }}>Save cluster profile</Button>
    {profile !== null && <>
      <p>Review these saved authentication and namespace-scoped read-only RBAC examples before applying. Trust the issuer CA explicitly. Group removal and logout affect new tokens; existing tokens remain usable until expiry.</p>
      <YamlView value={profile} label="Saved Kubernetes onboarding profile" />
    </>}
  </Panel>;
}
