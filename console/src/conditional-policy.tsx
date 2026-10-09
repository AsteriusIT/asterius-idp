import { useState, type JSX } from 'react';
import { conditionalScopes, stageMode } from './conditional-policy-model';
import { Actions, Badge, Button, DataTable, EmptyState, Message, Panel } from './ui';

export function ConditionalPolicy({ draft, savedDraft, revision, mayWrite, busy, onStage }: Readonly<{
  draft: string; savedDraft?: string; revision: string | null; mayWrite: boolean; busy: boolean; onStage: (text: string) => void;
}>): JSX.Element {
  const scopes = conditionalScopes(draft);
  const savedScopes = savedDraft === undefined ? null : conditionalScopes(savedDraft);
  const [failure, setFailure] = useState<string | null>(null);
  const stage = (id: string, mode: 'active' | 'report_only'): void => {
    try { onStage(stageMode(draft, id, mode)); setFailure(null); }
    catch { setFailure('Each scope must have a unique identifier before staging a mode change.'); }
  };
  return <Panel title="Conditional access rollout" description="Review the editor draft, simulate it, then publish the reviewed revision. Active scopes enforce restrictions. Report-only scopes record their result and cannot grant denied access.">
    <p>Stored revision: {revision ? <code>{revision}</code> : 'No stored document'}.</p>
    {scopes === null ? <Message tone="info">The draft is not ready for a structured preview. The server validates the policy when you publish.</Message> : <DataTable
      rows={scopes.map((scope, index) => ({ ...scope, previewKey: String(index) }))} rowKey={scope => scope.previewKey}
      empty={<EmptyState title="No conditional scopes" body="The document has no conditional rollout configured." />}
      columns={[
        { key: 'scope', header: 'Scope', cell: scope => <code>{scope.id}</code> },
        { key: 'published', header: 'Published mode', cell: scope => { const saved = savedScopes?.filter(item => item.id === scope.id); return saved?.length === 1 ? saved[0]?.mode === 'active' ? 'Active enforcement' : saved[0]?.mode === 'report_only' ? 'Report-only' : 'Unknown mode' : 'No uniquely matching saved scope'; } },
        { key: 'mode', header: 'Draft mode', cell: scope => <Badge tone={scope.mode === 'active' ? 'bad' : scope.mode === 'report_only' ? 'warn' : 'neutral'}>{scope.mode === 'active' ? 'Active enforcement' : scope.mode === 'report_only' ? 'Report-only' : 'Unknown mode'}</Badge> },
        { key: 'target', header: 'Selected applications and boundaries', cell: scope => <><p>{scope.clients.join(', ') || 'No applications selected'}</p><p>{scope.actions.join(', ') || 'No boundaries selected'}</p></> },
        { key: 'facts', header: 'Explicit required facts', cell: scope => scope.required_facts.join(', ') || 'Rule conditions may also require facts' },
        { key: 'rollout', header: 'Stage a change', cell: scope => mayWrite && (scope.mode === 'active' || scope.mode === 'report_only') ? <Actions>
          <Button disabled={busy || scope.mode === 'report_only'} onClick={() => stage(scope.id, 'report_only')}>Stage report-only</Button>
          <Button disabled={busy || scope.mode === 'active'} onClick={() => stage(scope.id, 'active')}>Stage active enforcement</Button>
        </Actions> : 'Read only' },
      ]} />}
    {failure && <Message tone="error">{failure}</Message>}
    <p className="muted">Staging changes only the editor draft. Publishing requires policy write access, confirmation and the current server revision. Missing required evidence still denies an active scope.</p>
  </Panel>;
}
