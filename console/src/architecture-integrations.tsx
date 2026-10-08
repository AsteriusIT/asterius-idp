/** Typed, public integration drafts. Credentials belong only to apply review. */
import { useEffect, useState, type JSX } from 'react';
import { read } from './api';
import { Field, Button } from './ui';
import { FormSelect } from './components/ui/select';
import type { ArchitectureNode } from './architecture-model';

interface Peer { peer_client_id: string; state: string; expected_audience: string; allow_all_subjects: boolean }
export function IntegrationInspector({ node, disabled, onChange }: Readonly<{
  node: ArchitectureNode; disabled: boolean; onChange: (patch: Partial<ArchitectureNode>) => void;
}>): JSX.Element {
  const [peers, setPeers] = useState<Peer[]>([]);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (node.kind !== 'stream' || node.settings.integration !== true) return;
    let active = true;
    read('ssf/upstream/peers').then(value => { if (active) { setPeers((value as { items: Peer[] }).items); setError(null); } }, cause => {
      if (active) setError(cause instanceof Error ? cause.message : 'Configured peers could not be read.');
    });
    return () => { active = false; };
  }, [node.kind, node.settings.integration]);
  const settings = (patch: Record<string, unknown>): void => onChange({ settings: { ...node.settings, ...patch } });
  if (node.settings.integration !== true) return <>
    <p className="muted">This saved object is diagram context. Choose an integration to configure or reference it explicitly.</p>
    <Button disabled={disabled} onClick={() => settings(node.kind === 'identity_provider'
      ? { integration: true, issuer: '', client_id: '', enabled: false, allow_registration: false }
      : { integration: true })}>Configure integration</Button>
  </>;
  if (node.kind === 'identity_provider') return <>
    {node.mode === 'managed' && <>
      <Field label="OIDC issuer URL" required>{props => <input {...props} type="url" disabled={disabled} value={String(node.settings.issuer ?? '')} onChange={event => settings({ issuer: event.target.value })} />}</Field>
      <Field label="Upstream client ID" required>{props => <input {...props} disabled={disabled} value={String(node.settings.client_id ?? '')} onChange={event => settings({ client_id: event.target.value })} />}</Field>
      <Field label="Username claim (optional)" hint="Leave empty to generate a local username.">{props => <input {...props} disabled={disabled} value={String(node.settings.username_claim ?? '')} onChange={event => settings({ username_claim: event.target.value || null })} />}</Field>
      <label><input type="checkbox" disabled={disabled} checked={node.settings.enabled === true} onChange={event => settings({ enabled: event.target.checked })} /> Enable sign-in</label>
      <label><input type="checkbox" disabled={disabled} checked={node.settings.allow_registration === true} onChange={event => settings({ allow_registration: event.target.checked })} /> Allow first sign-in to create an account</label>
      <p className="muted">Register the callback shown in Sign-in providers at the upstream provider. Preview validates its discovery. Enter the client secret only in the apply review.</p>
    </>}
    {node.mode === 'reference' && <p className="muted">Enter the ID of a provider already configured in this tenant. Applying records a reference and keeps its settings and credential.</p>}
  </>;
  const peer = peers.find(peer => peer.peer_client_id === node.identifier);
  return <>
    {error && <p role="alert">{error}</p>}
    <Field label="Configured upstream transmitter" required hint="Peer credentials, audience and ALL-subject consent are configured by the server operator.">{props => <FormSelect {...props} disabled={disabled} value={node.identifier} options={[
      { value: '', label: 'Choose a configured peer' }, ...peers.map(peer => ({ value: peer.peer_client_id, label: `${peer.peer_client_id} · ${peer.state}` })),
    ]} onValueChange={value => {
      const next = peers.find(peer => peer.peer_client_id === value);
      if (next) onChange({ identifier: value, settings: { integration: true, expected_audience: next.expected_audience, allow_all_subjects: next.allow_all_subjects } });
    }} />}</Field>
    {peer && <>
      <p>Expected SET audience: <code>{peer.expected_audience}</code></p>
      <p>{peer.allow_all_subjects ? 'The operator allows ALL-subject delivery.' : 'ALL-subject delivery needs operator consent before this flow can apply.'}</p>
      {node.settings.expected_audience !== peer.expected_audience || node.settings.allow_all_subjects !== peer.allow_all_subjects ? <p role="alert">The configured audience or subject policy changed. Select the peer again and review the new contract.</p> : null}
    </>}
    <p className="muted">Sets up a poll stream or references an established one. EdDSA and ES256 are supported. Setup and configuration readback do not prove signed event delivery. Use Shared signals to request verification, poll or explicitly delete the recorded stream.</p>
  </>;
}
