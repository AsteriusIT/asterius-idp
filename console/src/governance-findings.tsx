import {useCallback,useEffect,useRef,useState,type JSX} from 'react';
import {read,type Session} from './api';
import {FormSelect} from './components/ui/select';
import {Button,Field,Message,Panel,Screen,Skeleton} from './ui';

type Section='accounts'|'ownership'|'assignments'|'temporary_entitlements'|'administrative_roles';
interface Finding {key:string;reasons:string[];evidence:Record<string,unknown>;proposals:string[]}
interface Report {section:Section;observed_at:string;thresholds:{inactivity_days:number;membership_review_days:number;privilege_review_days:number};items:Finding[];next:string|null;scanned:number;read_only:true}
const sections=[{value:'accounts',label:'Accounts and provisioning'},{value:'ownership',label:'Owners and reviewers'},{value:'assignments',label:'Standing access and memberships'},{value:'temporary_entitlements',label:'Temporary privilege configuration'},{value:'administrative_roles',label:'Administrative privileges'}];
const reasons:Record<string,string>={missing_owner:'Owner no longer exists',inactive_owner:'Owner cannot currently sign in',owner_authority_unavailable:'Owner lacks current administration authority',reviewer_unavailable:'No eligible active reviewer remains',missing_ownership:'No explicit ownership configured',disconnected_source:'Recorded source is missing or disabled',upstream_deleted:'SCIM recorded an upstream deletion',upstream_absent:'LDAP recorded absence in a complete snapshot',inactive_account:'Local account is disabled or locked',no_recent_observed_activity:'Retained activity is older than the threshold',unknown_activity:'Complete activity history is unavailable',stale_membership:'Membership is old and lacks a current review',unreviewed_privilege:'Privilege lacks a recent current review',stale_review:'Recorded review context is no longer current',overdue_review:'An open review passed its deadline',unapplied_decision:'A recorded decision has not been applied',protected_recovery_account:'Preserve this possible local recovery account',source_health_unknown:'Complete source or review context is unavailable'};
const proposals:Record<string,string>={inspect_provisioning_source:'Inspect the provisioning source and its last complete run.',assign_current_owner:'Confirm a current owner and independent reviewers.',review_account_lifecycle:'Review the account or entitlement through its authorized lifecycle screen.',review_membership_source:'Confirm the membership with its owner or provisioning controller.',start_independent_review:'Start an independent access review for the current source.',inspect_review_application:'Inspect the recorded decision and its application result.',preserve_recovery_access:'Confirm another working recovery path before considering changes.'};
const label=(value:string,labels:Record<string,string>)=>labels[value]??value.replaceAll('_',' ');
function findingTitle(finding:Finding):string {
  const target=finding.evidence.target as Record<string,unknown>|undefined;
  const kind=typeof target?.kind==='string'?target.kind.replaceAll('_',' '):'Record';
  const id=finding.evidence.user_id??finding.evidence.ownership_id??finding.evidence.entitlement_id??finding.key;
  return `${kind} · ${String(id).slice(0,12)}`;
}

export function GovernanceFindings({session}:{session:Session}):JSX.Element {
  const [section,setSection]=useState<Section>('accounts');
  const [report,setReport]=useState<Report|null>(null);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState('');
  const sequence=useRef(0);
  const refresh=useCallback(async()=>{
    const request=++sequence.current;setBusy(true);setError('');setReport(null);
    try{const value=await read(`governance/findings?section=${section}&limit=25`) as Report;
      if(request===sequence.current){if(value.section!==section)throw new Error('Report section changed. Refresh the report.');setReport(value);}}
    catch(error){if(request===sequence.current)setError(error instanceof Error?error.message:'The report could not be read.');}
    finally{if(request===sequence.current)setBusy(false);}
  },[section,session.workspace]);
  useEffect(()=>{void refresh();return()=>{++sequence.current;};},[refresh]);
  async function more(){
    if(report?.next==null)return;const request=++sequence.current;const previous=report;setBusy(true);setError('');
    try{const value=await read(`governance/findings?section=${section}&limit=25&after=${encodeURIComponent(report.next)}`) as Report;
      if(request===sequence.current){if(value.section!==section)throw new Error('Report section changed. Refresh the report.');setReport({...value,items:[...previous.items,...value.items],scanned:previous.scanned+value.scanned});}}
    catch(error){if(request===sequence.current)setError(error instanceof Error?error.message:'The next page could not be read.');}
    finally{if(request===sequence.current)setBusy(false);}
  }
  return <Screen title="Governance findings" description="Inspect current evidence, confirm its context, then propose a human review." actions={<Button disabled={busy} onClick={()=>void refresh()}>Refresh</Button>}>
    <Panel title="Report scope" description="Each page observes the current tenant. These findings do not change accounts, memberships or privileges.">
      <Field label="Evidence category">{props=><FormSelect {...props} value={section} options={sections} disabled={busy} onValueChange={value=>setSection(value as Section)}/>}</Field>
      <p>Inactivity uses retained sessions, which are swept over time. Missing activity is uncertainty, not proof of upstream deletion. A recorded source registration does not prove that its feed is reachable.</p>
      <p>Local recovery accounts and managed memberships need explicit human confirmation. A historical retain decision cannot certify a changed source.</p>
      <a href="#/access-reviews">Open access reviews</a>
    </Panel>
    {error&&<Message tone="error">{error}</Message>}
    {busy&&report===null&&<Skeleton rows={4} label="Loading governance findings"/>}
    {report&&<>
      <p role="status">{report.items.length} findings shown from {report.scanned} inspected records. Last page observed {new Date(report.observed_at).toLocaleString()}.</p>
      <p className="muted">Activity threshold: {report.thresholds.inactivity_days} days. Membership review: {report.thresholds.membership_review_days} days. Privilege review: {report.thresholds.privilege_review_days} days. Pages can change while you inspect them.</p>
      {report.items.length===0&&<Message tone="info">{report.next?'No findings in this bounded scan. Continue to inspect the remaining records.':'No findings in this category at the observed time.'}</Message>}
      {report.items.map(finding=><Panel key={finding.key} title={findingTitle(finding)} description="Review proposal — no cleanup has been performed.">
        <ul>{finding.reasons.map(reason=><li key={reason}>{label(reason,reasons)}</li>)}</ul>
        {finding.reasons.includes('protected_recovery_account')&&<Message tone="info">Preserve recovery access. Old or missing session history can be expected for an emergency account.</Message>}
        <p>Proposed next steps</p><ul>{finding.proposals.map(proposal=><li key={proposal}>{label(proposal,proposals)}</li>)}</ul>
        <details><summary>Inspect source identifiers and evidence</summary><pre className="json-code" tabIndex={0} aria-label="Source evidence">{JSON.stringify(finding.evidence,null,2)}</pre></details>
      </Panel>)}
      {report.next&&report.items.length<250&&<Button disabled={busy} onClick={()=>void more()}>Continue bounded scan</Button>}
      {report.next&&report.items.length>=250&&<Message tone="info">This view reached 250 findings. Refresh or inspect another category before loading more.</Message>}
    </>}
  </Screen>;
}
