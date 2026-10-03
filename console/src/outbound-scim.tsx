import {useCallback,useEffect,useRef,useState,type JSX} from 'react';
import {mutate,read,type Session} from './api';
import {FormSelect} from './components/ui/select';
import {Actions,Button,ConfirmDialog,DataTable,Field,Message,Panel,Screen,Skeleton} from './ui';

interface Connector {id:string;revision:string;target_issuer:string;target_client:string;credential_ref:string;credential_generation:string;enabled:boolean;allow_reviewed_delete:boolean}
interface Credential {reference:string;generation:string;target_issuer:string;target_client:string}
interface Assignment {id:string;kind:'user'|'group';source:string;generation:string;selected:boolean;target:string|null;state:string;failure_code:string|null;dirty:boolean}
interface Page<T>{items:T[];next_cursor?:string|null}
interface Named {id:string;label:string}
const base='outbound-scim/connectors';
const failure=(error:unknown)=>error instanceof Error?error.message:'The provisioning operation failed.';
const options=(items:readonly Named[])=>[{value:'',label:'Choose…'},...items.map(item=>({value:item.id,label:item.label}))];
const diagnostic:Record<string,string>={paused:'Resume after previewing the current destination.',credential_unavailable:'The configured signing credential is unavailable.',credential_binding_mismatch:'The credential does not match this source and destination.',authentication_refused:'The destination refused client authentication.',target_unavailable:'The destination is unavailable; delivery can retry.',ownership_mismatch:'The destination object no longer matches this assignment owner.',target_absent:'The retained destination object is missing; inspect its lifecycle.',target_version_changed:'The destination version changed. Inspect drift before reconciling again.',source_protected:'This source belongs to another provisioning controller.',source_projection_invalid:'The source or destination attributes do not match the supported profile.',user_dependencies_pending:'Selected active group members need their own User mappings first.',snapshot_bound_exceeded:'The bounded assignment catalogue is full.',lease_superseded:'This delivery was superseded by a newer configuration or source change.'};

export function OutboundScim({session}:{session:Session}):JSX.Element {
  const write=session.tenant===session.workspace&&session.scopes.includes('admin.outbound_scim:write');
  const selectionRequest=useRef(0);
  const [connectors,setConnectors]=useState<Connector[]>([]);const [credentials,setCredentials]=useState<Credential[]>([]);
  const [selected,setSelected]=useState('');const [connector,setConnector]=useState<Connector|null>(null);
  const [assignments,setAssignments]=useState<Assignment[]>([]);const [moreConnectors,setMoreConnectors]=useState(false);const [moreAssignments,setMoreAssignments]=useState(false);
  const [users,setUsers]=useState<Named[]>([]);const [groups,setGroups]=useState<Named[]>([]);const [directoryCursor,setDirectoryCursor]=useState<{users:string|null;groups:string|null}>({users:null,groups:null});
  const [credential,setCredential]=useState('');const [rotation,setRotation]=useState('');const [kind,setKind]=useState<'user'|'group'>('user');const [source,setSource]=useState('');
  const [previewRevision,setPreviewRevision]=useState('');const [reconcileAfter,setReconcileAfter]=useState<string|null>(null);const [confirm,setConfirm]=useState<Assignment|null>(null);
  const [busy,setBusy]=useState(false);const [loading,setLoading]=useState(true);const [error,setError]=useState('');const [notice,setNotice]=useState('');
  const load=useCallback(async()=>{
    setLoading(true);setError('');
    try{const [page,refs]=await Promise.all([read(base) as Promise<Page<Connector>>,read('outbound-scim/credentials') as Promise<Page<Credential>>]);setConnectors(page.items);setMoreConnectors(page.items.length===50);setCredentials(refs.items);}
    catch(error){setError(failure(error));}finally{setLoading(false);}
  },[]);
  const loadSelection=useCallback(async(id:string)=>{
    const request=++selectionRequest.current;
    const [current,page]=await Promise.all([read(`${base}/${id}`) as Promise<Connector>,read(`${base}/${id}/assignments`) as Promise<Page<Assignment>>]);
    if(request!==selectionRequest.current)return;
    setConnector(current);setAssignments(page.items);setMoreAssignments(page.items.length===50);
    setConnectors(previous=>previous.some(item=>item.id===current.id)?previous.map(item=>item.id===current.id?current:item):[...previous,current]);
  },[]);
  useEffect(()=>{void load();},[load]);
  useEffect(()=>{let current=true;setConnector(null);setAssignments([]);setPreviewRevision('');setReconcileAfter(null);setSource('');setRotation('');if(selected)void loadSelection(selected).catch(error=>{if(current)setError(failure(error));});return()=>{current=false;selectionRequest.current+=1;};},[selected,loadSelection]);
  useEffect(()=>{
    if(!write)return;let current=true;
    Promise.all([read('users?limit=100') as Promise<Page<{user_id:string;username:string}>>,read('groups?limit=100') as Promise<Page<{id:string;display_name:string}>>]).then(([users,groups])=>{
      if(!current)return;setUsers(users.items.map(user=>({id:user.user_id,label:user.username})));setGroups(groups.items.map(group=>({id:group.id,label:group.display_name})));
      setDirectoryCursor({users:users.next_cursor??null,groups:groups.next_cursor??null});
    }).catch(error=>{if(current)setError(failure(error));});return()=>{current=false;};
  },[write]);
  async function action(command:()=>Promise<void>){setBusy(true);setError('');setNotice('');try{await command();}catch(error){setError(failure(error));}finally{setBusy(false);}}
  async function configure(enabled:boolean,ref?:Credential){if(!connector)return;await mutate(`${base}/${connector.id}`,'PUT',session,{expected_revision:connector.revision,target_issuer:connector.target_issuer,target_client:connector.target_client,credential_ref:ref?.reference??connector.credential_ref,credential_generation:ref?.generation??connector.credential_generation,enabled,allow_reviewed_delete:connector.allow_reviewed_delete});await loadSelection(connector.id);setReconcileAfter(null);setPreviewRevision('');}
  async function moreDirectory(resource:'users'|'groups'){
    const cursor=directoryCursor[resource];if(!cursor)return;
    await action(async()=>{const page=await read(`${resource}?limit=100&cursor=${encodeURIComponent(cursor)}`) as Page<Record<string,string>>;const named:Named[]=page.items.map(item=>{const id=resource==='users'?item.user_id:item.id;const label=resource==='users'?item.username:item.display_name;if(typeof id!=='string'||typeof label!=='string')throw new Error('Local directory response was incomplete.');return {id,label};});if(resource==='users')setUsers(previous=>[...previous,...named]);else setGroups(previous=>[...previous,...named]);setDirectoryCursor(previous=>({...previous,[resource]:page.next_cursor??null}));});
  }
  const names=new Map([...users,...groups].map(item=>[item.id,item.label]));
  const available=credentials.map((entry,index)=>({entry,index})).filter(({entry})=>connector!==null&&entry.target_issuer===connector.target_issuer&&entry.target_client===connector.target_client);
  return <Screen title="Outbound provisioning" description="Provision explicitly selected local accounts and groups into another Asterius workspace." actions={<Button disabled={busy||loading} onClick={()=>void action(async()=>{await load();if(selected)await loadSelection(selected);})}>Refresh</Button>}>
    {error&&<Message tone="error">{error}</Message>}{notice&&<Message tone="success">{notice}</Message>}
    {loading&&<Skeleton label="Loading provisioning connectors"/>}
    {!loading&&<Panel title="Destinations" description="Each connector starts paused. A successful authenticated preview is required before enabling it.">
      <Field label="Connector">{props=><FormSelect {...props} value={selected} onValueChange={setSelected} disabled={busy} options={options(connectors.map(item=>({id:item.id,label:`${item.target_issuer} · ${item.enabled?'Enabled':'Paused'}`})))}/>}</Field>
      {connectors.length===0&&<p>No outbound destinations are configured.</p>}
      {moreConnectors&&<Button disabled={busy} onClick={()=>void action(async()=>{const page=await read(`${base}?after=${connectors.at(-1)?.id}`) as Page<Connector>;setConnectors(previous=>[...previous,...page.items]);setMoreConnectors(page.items.length===50);})}>Load more connectors</Button>}
      {write&&<><Field label="Approved destination credential" hint="Only deployment credentials bound to this source workspace appear here.">{props=><FormSelect {...props} value={credential} onValueChange={setCredential} disabled={busy} options={[{value:'',label:'Choose…'},...credentials.map((item,index)=>({value:String(index),label:`${item.target_issuer} · ${item.target_client} · ${item.reference}`}))]}/>}</Field>
        {credentials.length===0&&<Message tone="info">An operator must configure a scoped destination signing credential before you can create a connector.</Message>}
        <Button disabled={busy||credential===''} onClick={()=>void action(async()=>{const ref=credentials[Number(credential)];if(!ref)return;const created=await mutate(base,'POST',session,{target_issuer:ref.target_issuer,target_client:ref.target_client,credential_ref:ref.reference,credential_generation:ref.generation,enabled:false,allow_reviewed_delete:false}) as Connector;setSelected(created.id);setConnectors(previous=>[...previous,created]);setCredential('');setNotice('Paused connector created. Preview its destination before enabling.');})}>Create paused connector</Button>
      </>}
    </Panel>}
    {connector&&<>
      <Panel title={connector.enabled?'Destination enabled':'Destination paused'} description={`${connector.target_issuer} · ${connector.target_client}`}>
        <p>Credential: {connector.credential_ref}. Pause stops new dispatches; a request already sent may still finish at the destination.</p>
        {write&&<Actions>
          <Button disabled={busy} onClick={()=>void action(async()=>{await mutate(`${base}/${connector.id}/preview`,'POST',session,{expected_revision:connector.revision});setPreviewRevision(connector.revision);setNotice('Authentication, SCIM filtering and versioned writes verified for this configuration. Preview is valid for five minutes.');})}>Preview destination</Button>
          <Button disabled={busy||!connector.enabled&&previewRevision!==connector.revision} onClick={()=>void action(async()=>{await configure(!connector.enabled);setNotice(connector.enabled?'Destination paused. Mapping evidence retained.':'Destination enabled. Bounded reconciliation queued.');})}>{connector.enabled?'Pause':'Enable'}</Button>
          <Button disabled={busy||!connector.enabled} onClick={()=>void action(async()=>{const result=await mutate(`${base}/${connector.id}/reconcile${reconcileAfter?`?after=${reconcileAfter}`:''}`,'POST',session,{expected_revision:connector.revision}) as {after:string|null};setReconcileAfter(result.after);await loadSelection(connector.id);setNotice(result.after?'This page was queued. Continue to reconcile the remaining assignments.':'Reconciliation queued for the final page. Inspect delivery results after refresh.');})}>{reconcileAfter?'Continue reconciliation':'Reconcile / retry'}</Button>
        </Actions>}
        {write&&!connector.enabled&&<><Field label="Replacement signing credential" hint="The destination issuer and client stay pinned while mapping evidence exists.">{props=><FormSelect {...props} value={rotation} onValueChange={setRotation} disabled={busy} options={[{value:'',label:'Choose…'},...available.map(({entry,index})=>({value:String(index),label:`${entry.reference} · ${entry.generation.slice(0,8)}`}))]}/>}</Field><Button disabled={busy||rotation===''} onClick={()=>void action(async()=>{const ref=credentials[Number(rotation)];if(!ref)return;await configure(false,ref);setRotation('');setNotice('Credential changed. Preview this configuration before enabling again.');})}>Rotate credential</Button></>}
      </Panel>
      {write&&<Panel title="Select a local source" description="Group members must have selected active User assignments. Local roles and authentication credentials are never exported.">
        <Field label="Source type">{props=><FormSelect {...props} value={kind} onValueChange={value=>{setKind(value as 'user'|'group');setSource('');}} disabled={busy} options={[{value:'user',label:'User'},{value:'group',label:'Group'}]}/>}</Field>
        <Field label={kind==='user'?'Local user':'Local group'}>{props=><FormSelect {...props} value={source} onValueChange={setSource} disabled={busy} options={options(kind==='user'?users:groups)}/>}</Field>
        {directoryCursor[kind==='user'?'users':'groups']&&<Button disabled={busy} onClick={()=>void moreDirectory(kind==='user'?'users':'groups')}>Load more local sources</Button>}
        <Button disabled={busy||source===''} onClick={()=>void action(async()=>{await mutate(`${base}/${connector.id}/assignments`,'POST',session,{expected_revision:connector.revision,kind,sources:[source]});await loadSelection(connector.id);setSource('');setPreviewRevision('');setNotice('Source selected. Refresh to inspect its delivery result.');})}>Select source</Button>
      </Panel>}
      <Panel title="Assignments" description="Unselecting disables an owned destination User or empties its Group. It preserves the object and mapping evidence.">
        <DataTable caption="Outbound assignment delivery" rows={assignments} rowKey={item=>item.id} empty="No sources have been selected." columns={[
          {key:'source',header:'Local source',cell:item=><>{names.get(item.source)??item.source}<span className="muted"> · {item.kind}</span></>},
          {key:'state',header:'Delivery',cell:item=><>{item.state.replaceAll('_',' ')}{item.failure_code&&<p className="muted">{diagnostic[item.failure_code]??'Inspect this delivery in the outbox.'}</p>}</>},
          {key:'selection',header:'Selection',cell:item=>item.selected?'Selected':'Deprovisioning / retained'},
          {key:'actions',header:'Actions',cell:item=>write&&item.selected?<Button disabled={busy} onClick={()=>setConfirm(item)}>Unselect</Button>:null},
        ]}/>
        {moreAssignments&&<Button disabled={busy} onClick={()=>void action(async()=>{const page=await read(`${base}/${connector.id}/assignments?after=${assignments.at(-1)?.id}`) as Page<Assignment>;setAssignments(previous=>[...previous,...page.items]);setMoreAssignments(page.items.length===50);})}>Load more assignments</Button>}
      </Panel>
      {confirm&&<ConfirmDialog busy={busy} title="Unselect this source?" body={`The owned destination ${confirm.kind==='user'?'User will be disabled':'Group will be emptied'}. Its mapping evidence will remain.`} confirmLabel="Unselect" onCancel={()=>setConfirm(null)} onConfirm={()=>{void action(async()=>{await mutate(`${base}/${connector.id}/assignments/${confirm.id}/unselect`,'POST',session,{expected_revision:connector.revision});await loadSelection(connector.id);setConfirm(null);setPreviewRevision('');setNotice('Deprovisioning queued. The destination object will be retained.');});}}/>}
    </>}
  </Screen>;
}
