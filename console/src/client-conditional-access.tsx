import { useEffect, useState, type JSX } from 'react';
import { ApiError, mutate, read, type Session } from './api';
import { Actions, Button, ConfirmDialog, Field, LoadFailure, Message, Panel, Skeleton } from './ui';
import { FormSelect } from './components/ui/select';
type Sensitivity = 'standard' | 'sensitive' | 'critical';
interface Settings { sensitivity: Sensitivity | null; revision: string | null }
export function ClientConditionalAccess({ clientID, session }: Readonly<{clientID: string;session: Session}>): JSX.Element {
  const [current,setCurrent]=useState<Settings|null>(null);
  const [draft,setDraft]=useState<Sensitivity|''>('');
  const [error,setError]=useState<string|null>(null);
  const [busy,setBusy]=useState(false);
  const [confirm,setConfirm]=useState(false);
  const [retry,setRetry]=useState(0);
  const [stale,setStale]=useState(false);
  const mayWrite=session.scopes.includes('admin.clients:write');
  useEffect(()=>{let active=true;setCurrent(null);setError(null);setStale(false);setConfirm(false);
    void read(`clients/${encodeURIComponent(clientID)}/conditional-access`).then(value=>{if(active){const settings=value as Settings;setCurrent(settings);setDraft(settings.sensitivity??'');}},reason=>{if(active)setError(reason instanceof Error?reason.message:'Classification could not be read.');});
    return()=>{active=false;};},[clientID,retry]);
  const save=async()=>{if(!current||!mayWrite||stale)return;setBusy(true);setError(null);
    try{const value=await mutate(`clients/${encodeURIComponent(clientID)}/conditional-access`,'PUT',session,{sensitivity:draft||null,expected_revision:current.revision});setCurrent(value as Settings);setConfirm(false);}
    catch(reason){setError(reason instanceof Error?reason.message:'The classification was not changed.');if(reason instanceof ApiError&&reason.status===409)setStale(true);}
    finally{setBusy(false);}};
  return <Panel title="Conditional access classification" description="This administrator-owned classification is separate from application registration. Conditional rules can require it; an unclassified application has missing evidence.">
    {current===null&&!error&&<Skeleton rows={2} label="Reading application classification." />}
    {error&&current===null&&<LoadFailure message={error} onRetry={()=>setRetry(v=>v+1)} />}
    {current&&<><Field label="Application sensitivity">{props=><FormSelect {...props} value={draft} disabled={!mayWrite||busy||stale} onValueChange={value=>setDraft(value as Sensitivity|'')} options={[
        { value: '', label: 'Unclassified (absent)', description: 'No trusted application classification is stored.' },
        { value: 'standard', label: 'Standard' }, { value: 'sensitive', label: 'Sensitive' }, { value: 'critical', label: 'Critical' },
      ]} />}</Field>
      <p className="muted">Revision: {current.revision?<code>{current.revision}</code>:'No stored classification'}. Changes are audited.</p>
      {error&&<Message tone="error">{error}</Message>}
      {stale&&<Message tone="info">Another operator changed this classification. Reload the current revision and review your change before retrying.</Message>}
      <Actions>{mayWrite&&<Button variant="primary" disabled={busy||stale||(draft||null)===current.sensitivity} onClick={()=>setConfirm(true)}>Review classification change</Button>}<Button disabled={busy} onClick={()=>setRetry(v=>v+1)}>Reload classification</Button></Actions>
    </>}
    {confirm&&<ConfirmDialog title="Change application sensitivity?" body={<><p>This changes the trusted classification used by active conditional rules. Existing access restrictions can change immediately. The server checks the revision you reviewed.</p>{error&&<Message tone="error">{error}</Message>}</>} confirmLabel="Save reviewed classification" busy={busy} onCancel={()=>setConfirm(false)} onConfirm={()=>void save()} />}
  </Panel>;
}
