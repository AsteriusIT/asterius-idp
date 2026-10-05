import {useCallback, useEffect, useRef, useState, type JSX} from 'react';
import {CheckIcon, ChevronsUpDownIcon, PlusIcon, RefreshCwIcon, TerminalIcon} from 'lucide-react';
import {ApiError, mutate, read, type Session} from './api';
import type {ClientRow} from './clients';
import type {GroupRow} from './groups-model';
import {Popover, PopoverContent, PopoverTrigger} from './components/ui/popover';
import {Command, CommandEmpty, CommandInput, CommandItem, CommandList} from './components/ui/command';
import {CopyValue} from './components/copy-value';
import {YamlView} from './components/yaml-view';
import {useUnsavedChanges} from './navigation-guard';
import {hrefOf} from './routes';
import {Actions, Badge, Button, DataTable, EmptyState, Field, LoadFailure, Message, Panel, Screen, Skeleton} from './ui';
import {authenticationLabel, loginCommand, mapBounded, profileChange, profilePath, shellQuote, type ClusterProfile, type OnlineProfile} from './kubernetes-model';

type Page<T> = {items:T[];next_cursor:string|null};
type Cluster = {client:ClientRow;profile:ClusterProfile|null;error?:string};
const failure = (e:unknown)=>e instanceof Error?e.message:'The Kubernetes configuration could not be read.';
async function optional<T>(path:string):Promise<T|null> {
  try { return await read(path) as T; } catch(e) { if(e instanceof ApiError && e.status===404) return null; throw e; }
}

export function KubernetesAccess({session}: {session:Session}):JSX.Element {
  const [rows,setRows]=useState<Cluster[]>([]); const [cursor,setCursor]=useState<string|null>(null);
  const [busy,setBusy]=useState(true); const [error,setError]=useState<string|null>(null);
  const [selected,setSelected]=useState<Cluster|null>(null); const [creating,setCreating]=useState(false);
  const [candidate,setCandidate]=useState(''); const generation=useRef(0);
  const load=useCallback(async(after:string|null=null)=>{
    const request=++generation.current;setBusy(true);setError(null);
    try {
      const page=await read(`clients?limit=20${after?`&cursor=${encodeURIComponent(after)}`:''}`) as Page<ClientRow>;
      const items=await mapBounded(page.items,async client=>{
        try {return {client,profile:await optional<ClusterProfile>(profilePath(client.client_id))};}
        catch(e){return {client,profile:null,error:failure(e)};}
      });
      if(request===generation.current){setRows(previous=>after?[...previous,...items]:items);setCursor(page.next_cursor);}
    }catch(e){if(request===generation.current)setError(failure(e));}
    finally{if(request===generation.current)setBusy(false);}
  },[]);
  useEffect(()=>{void load();return()=>{generation.current++;};},[load]);
  if(selected)return <ClusterDetail key={selected.client.client_id} session={session} cluster={selected} onBack={()=>{setSelected(null);void load();}}/>;
  const configured=rows.filter(row=>row.profile!==null);
  const candidates=rows.filter(row=>row.profile===null && !row.error);
  return <Screen title="Kubernetes access" description="Connect a cluster, choose the groups it trusts and review how people receive access."
    actions={<Actions><Button disabled={busy} variant="ghost" onClick={()=>void load()}><RefreshCwIcon aria-hidden="true"/>Refresh</Button>{session.scopes.includes('admin.clients:write')&&<Button variant="primary" onClick={()=>setCreating(!creating)}><PlusIcon aria-hidden="true"/>Add cluster</Button>}</Actions>}>
    <section className="kubernetes-clusters" aria-label="Connected clusters">
      <p className="muted">Saved authentication profiles in this workspace. Kubernetes RBAC determines what each identity can do.</p>
      {busy&&rows.length===0&&<Skeleton rows={3} label="Reading cluster applications."/>}
      {error&&<LoadFailure message={error} onRetry={()=>void load(cursor)}/>}
      <DataTable caption="Cluster profiles" rows={configured} rowKey={row=>row.client.client_id}
        empty={!busy?<EmptyState title="No cluster profiles found." body="Load more applications or add a profile to a dedicated cluster broker application."/>:undefined}
        columns={[
          {key:'cluster',header:'Cluster',cell:row=><><strong>{row.profile?.cluster_id}</strong><br/><span className="muted">{row.client.client_name||row.client.client_id}</span></>},
          {key:'namespace',header:'Example namespace',cell:row=>row.profile?.namespace},
          {key:'groups',header:'Released groups',cell:row=>row.profile?.group_ids.length},
          {key:'status',header:'Registration',cell:row=><Badge tone={row.profile?.registration_compatible===false?'bad':'neutral'}>{row.profile?.registration_compatible===false?'Needs attention':row.client.status}</Badge>},
          {key:'open',header:'Configuration',actions:true,cell:row=><Button small onClick={()=>setSelected(row)}>View <span className="visually-hidden">{row.profile?.cluster_id}</span></Button>},
        ]}/>
      {rows.some(row=>row.error)&&<Message tone="error">Some application profiles could not be read. Refresh before treating this list as complete.<ul>{rows.filter(row=>row.error).map(row=><li key={row.client.client_id}>{row.client.client_name||row.client.client_id}: {row.error}</li>)}</ul></Message>}
      {cursor&&<div className="kubernetes-table-footer"><Button disabled={busy} variant="secondary" onClick={()=>void load(cursor)}>Load more applications</Button></div>}
    </section>
    {creating&&<Panel title="Add a cluster profile" description="First register one confidential broker application per cluster, with issuer discovery, private_key_jwt, DPoP and ES256 public-subject ID tokens.">
      <div className="field"><label id="broker-application-label">Broker application</label><BrokerApplicationPicker value={candidate} onChange={setCandidate} candidates={candidates}/></div>
      <Actions><a href={hrefOf('clients')} className="identity-link">Manage applications</a><Button variant="primary" disabled={!candidates.some(row=>row.client.client_id===candidate)} onClick={()=>{const row=candidates.find(row=>row.client.client_id===candidate);if(row)setSelected(row);}}>Configure cluster</Button></Actions>
      <p className="muted">Only loaded applications without a saved profile are listed. Load more above if your broker is missing.</p>
    </Panel>}
  </Screen>;
}

function BrokerApplicationPicker({value,onChange,candidates}:{value:string;onChange:(value:string)=>void;candidates:Cluster[]}):JSX.Element {
  const [open,setOpen]=useState(false);
  const selected=candidates.find(row=>row.client.client_id===value);
  return <Popover open={open} onOpenChange={setOpen}>
    <PopoverTrigger asChild><Button variant="secondary" role="combobox" aria-labelledby="broker-application-label" aria-expanded={open} className="kubernetes-picker-trigger">
      <span>{selected?.client.client_name||selected?.client.client_id||'Choose an application'}</span><ChevronsUpDownIcon aria-hidden="true"/>
    </Button></PopoverTrigger>
    <PopoverContent align="start" className="kubernetes-picker-popover"><Command>
      <CommandInput placeholder="Search loaded applications…" aria-label="Search broker applications"/>
      <CommandList><CommandEmpty>No loaded application matches. Load more applications from the cluster list.</CommandEmpty>
        {candidates.map(row=><CommandItem key={row.client.client_id} value={`${row.client.client_name} ${row.client.client_id}`} onSelect={()=>{onChange(row.client.client_id);setOpen(false);}}>
          <span className="kubernetes-picker-option"><strong>{row.client.client_name||row.client.client_id}</strong><small>{row.client.client_id}</small></span>
          {value===row.client.client_id&&<CheckIcon className="ml-auto size-4" aria-hidden="true"/>}
        </CommandItem>)}
      </CommandList>
    </Command></PopoverContent>
  </Popover>;
}

function ManagedGroupPicker({groups,selected,term,onTerm,onSelect,disabled,loading,error,onRetry,hasPrevious,hasNext,onFirst,onNext}:{
  groups:GroupRow[];selected:string[];term:string;onTerm:(value:string)=>void;onSelect:(value:string[])=>void;
  disabled:boolean;loading:boolean;error:string|null;onRetry:()=>void;hasPrevious:boolean;hasNext:boolean;onFirst:()=>void;onNext:()=>void;
}):JSX.Element {
  const [open,setOpen]=useState(false);
  return <Popover open={open} onOpenChange={setOpen}>
    <PopoverTrigger asChild><Button variant="secondary" role="combobox" aria-labelledby="released-groups-label" aria-expanded={open} disabled={disabled} className="kubernetes-picker-trigger">
      <span>{selected.length===0?'Choose managed groups':`${selected.length} selected group${selected.length===1?'':'s'}`}</span><ChevronsUpDownIcon aria-hidden="true"/>
    </Button></PopoverTrigger>
    <PopoverContent align="start" className="kubernetes-picker-popover"><Command shouldFilter={false}>
      <CommandInput value={term} onValueChange={onTerm} placeholder="Search managed groups…" aria-label="Search managed groups"/>
      <CommandList>
        {loading&&<p className="kubernetes-picker-note" role="status">Searching groups…</p>}
        {error&&<div className="kubernetes-picker-note"><p>{error}</p><Button small onClick={onRetry}>Retry</Button></div>}
        {!loading&&!error&&groups.length===0&&<p className="kubernetes-picker-note">No matching groups on this page.</p>}
        {!error&&groups.map(group=>{
          const checked=selected.includes(group.id);
          return <CommandItem key={group.id} value={group.id} disabled={loading||(!checked&&selected.length>=100)} onSelect={()=>onSelect(checked?selected.filter(id=>id!==group.id):[...selected,group.id])}>
            <span className="kubernetes-picker-check" aria-hidden="true">{checked&&<CheckIcon className="size-4"/>}</span>
            <span className="kubernetes-picker-option"><strong>{group.display_name}</strong><small>{group.name}</small></span>
          </CommandItem>;
        })}
      </CommandList>
      {(hasPrevious||hasNext)&&<div className="kubernetes-picker-footer">{hasPrevious&&<Button small variant="ghost" disabled={loading} onClick={onFirst}>First page</Button>}{hasNext&&<Button small variant="ghost" disabled={loading} onClick={onNext}>Next page</Button>}</div>}
    </Command></PopoverContent>
  </Popover>;
}

function ClusterDetail({session,cluster,onBack}:{session:Session;cluster:Cluster;onBack:()=>void}):JSX.Element {
  const [saved,setSaved]=useState(cluster.profile);const [name,setName]=useState(cluster.profile?.cluster_id??'');
  const [namespace,setNamespace]=useState(cluster.profile?.namespace??'default');const [selected,setSelected]=useState<string[]>(cluster.profile?.group_ids??[]);
  const [groups,setGroups]=useState<GroupRow[]>([]);const [knownGroups,setKnownGroups]=useState<Record<string,string>>({});const [term,setTerm]=useState('');const [groupCursor,setGroupCursor]=useState<string|null>(null);const [groupPage,setGroupPage]=useState(false);
  const [groupError,setGroupError]=useState<string|null>(null);const [groupBusy,setGroupBusy]=useState(false);const groupGeneration=useRef(0);
  const [busy,setBusy]=useState(false);const [error,setError]=useState<string|null>(null);const [notice,setNotice]=useState('');
  const [online,setOnline]=useState<OnlineProfile|null>(null);const [modeError,setModeError]=useState<string|null>(null);const [modeBusy,setModeBusy]=useState(true);
  const [jit,setJit]=useState<boolean|null>(null);const [statusRefresh,setStatusRefresh]=useState(0); const writable=session.scopes.includes('admin.clients:write');const groupsReadable=session.scopes.includes('admin.groups:read');
  const path=profilePath(cluster.client.client_id);
  const dirty=namespace!==(saved?.namespace??'default')||name!==(saved?.cluster_id??'')||JSON.stringify([...selected].sort())!==JSON.stringify([...(saved?.group_ids??[])].sort());
  const leave=useUnsavedChanges(dirty);
  const loadGroups=useCallback(async(after:string|null=null)=>{
    if(!groupsReadable)return;const request=++groupGeneration.current;setGroupBusy(true);setGroupError(null);
    try{
      const page=await read(`groups?q=${encodeURIComponent(term)}${after?`&cursor=${encodeURIComponent(after)}`:''}`) as Page<GroupRow>;
      if(request===groupGeneration.current){setGroups(page.items);setGroupPage(after!==null);setKnownGroups(previous=>({...previous,...Object.fromEntries(page.items.map(g=>[g.id,`${g.display_name} (${g.name})`]))}));setGroupCursor(page.next_cursor);}
    }catch(e){if(request===groupGeneration.current)setGroupError(failure(e));}
    finally{if(request===groupGeneration.current)setGroupBusy(false);}
  },[groupsReadable,term]);
  useEffect(()=>{let current=true;if(groupsReadable){void mapBounded(cluster.profile?.group_ids??[],async id=>{try{const g=await read(`groups/${encodeURIComponent(id)}`) as GroupRow;return [id,`${g.display_name} (${g.name})`] as const;}catch{return [id,'Group details unavailable'] as const;}}).then(entries=>{if(current)setKnownGroups(previous=>({...previous,...Object.fromEntries(entries)}));});}return()=>{current=false;};},[cluster.profile,groupsReadable]);
  useEffect(()=>{const timer=setTimeout(()=>{void loadGroups();},200);return()=>{clearTimeout(timer);groupGeneration.current++;};},[loadGroups]);
  useEffect(()=>{let current=true;setModeBusy(true);optional<OnlineProfile>(`${path}/online`).then(value=>{if(current)setOnline(value);},e=>{if(current)setModeError(failure(e));}).finally(()=>{if(current)setModeBusy(false);});return()=>{current=false;};},[path,saved?.revision,statusRefresh]);
  async function save(){setBusy(true);setError(null);setNotice('');try{
    const value=await mutate(path,'PUT',session,profileChange(saved,name,namespace,selected)) as ClusterProfile;
    setSaved(value);setName(value.cluster_id);setNamespace(value.namespace);setSelected(value.group_ids);setNotice('Cluster profile saved. Onboarding below uses this saved revision.');
  }catch(e){setError(failure(e));}finally{setBusy(false);}}
  return <Screen title={saved?.cluster_id??'New cluster profile'} description={cluster.client.client_name||cluster.client.client_id} back={{label:'Clusters',onClick:()=>leave(onBack)}} actions={<Button disabled={busy} onClick={()=>setStatusRefresh(value=>value+1)}>Refresh status</Button>}>
    {notice&&<Message tone="success">{notice}</Message>}{error&&<Message tone="error">{error}<Button small disabled={busy} onClick={()=>leave(()=>{setBusy(true);read(path).then(value=>{const current=value as ClusterProfile;setSaved(current);setName(current.cluster_id);setNamespace(current.namespace);setSelected(current.group_ids);setError(null);},e=>setError(failure(e))).finally(()=>setBusy(false));})}>Reload saved profile</Button></Message>}
    <Panel title="Authentication" description="Configuration status from Asterius. This does not test the cluster’s API server or controller.">
      {modeBusy?<Skeleton rows={1} label="Reading authentication mode."/>:modeError?<Message tone="error">Authentication mode unavailable: {modeError}</Message>:<><Badge>{authenticationLabel(online,jit===true)}</Badge>{online?.enabled?<p>Reviewer: {online.reviewer_client_id}. Kubernetes caching can delay revocation by forty seconds plus scheduling and transport time.</p>:<p>Existing signed tokens remain usable until expiry after logout or group removal. Cluster tokens are capped at five minutes.</p>}</>}
      {jit===null&&saved&&<p className="muted">Temporary identity configuration is checked separately below when your permissions allow it.</p>}
      {saved?.registration_compatible===false&&<Message tone="error">The application no longer matches this cluster profile. Restore the broker security settings before issuing credentials.</Message>}
      <a href={hrefOf('clients')} className="identity-link">Manage broker and reviewer applications</a>
    </Panel>
    <Panel title="Cluster profile" description="Release only the managed groups this cluster needs. Empty selection releases no groups.">
      <Field label="Cluster identifier" hint="A unique lowercase DNS label, fixed after creation.">{props=><input {...props} value={name} disabled={!writable||busy||saved!==null} onChange={e=>setName(e.target.value)}/>}</Field>
      <Field label="Example RBAC namespace">{props=><input {...props} value={namespace} disabled={!writable||busy} onChange={e=>setNamespace(e.target.value)}/>}</Field>
      {!groupsReadable?<Message tone="info">You need group read permission to change released groups. The saved selection will be preserved.</Message>:<>
        {selected.length>0&&<><h3>Selected groups</h3><ul>{selected.map(id=><li key={id} className="flex items-center justify-between gap-3 py-1"><span>{knownGroups[id]??'Reading group name…'}</span><Button small variant="ghost" disabled={!writable||busy} onClick={()=>setSelected(previous=>previous.filter(value=>value!==id))}>Remove <span className="visually-hidden">{knownGroups[id]??'selected group'}</span></Button></li>)}</ul></>}
        <div className="field"><label id="released-groups-label">Released managed groups ({selected.length}/100)</label>
          <ManagedGroupPicker groups={groups} selected={selected} term={term} onTerm={setTerm} onSelect={setSelected} disabled={!writable||busy} loading={groupBusy} error={groupError} onRetry={()=>void loadGroups()} hasPrevious={groupPage} hasNext={groupCursor!==null} onFirst={()=>void loadGroups()} onNext={()=>void loadGroups(groupCursor)}/>
        </div>
        <p className="muted">Selections from other pages and searches are preserved.</p>
      </>}
      <Actions><Button disabled={busy||!dirty} variant="ghost" onClick={()=>{setName(saved?.cluster_id??'');setNamespace(saved?.namespace??'default');setSelected(saved?.group_ids??[]);}}>Discard changes</Button><Button variant="primary" disabled={!writable||busy||!dirty||!name.trim()||!namespace.trim()} onClick={()=>void save()}>{busy?'Saving…':'Save cluster profile'}</Button></Actions>
    </Panel>
    {saved&&<>
      <Onboarding profile={saved} username={session.username}/>
      <TemporaryAccess key={`${saved.revision}-${statusRefresh}`} session={session} client={cluster.client.client_id} onMode={setJit}/>
    </>}
  </Screen>;
}

function Onboarding({profile,username}:{profile:ClusterProfile;username:string}):JSX.Element {
  return <>
    <Panel title="Cluster authentication" description={`Saved revision ${profile.revision}. Review these examples before applying; unsaved edits are excluded.`}>
    <div className="kubernetes-facts"><div><span>Issuer</span><code>{profile.issuer}</code><CopyValue value={profile.issuer} label="Copy issuer" iconOnly/></div><div><span>Audience</span><code>{profile.audience}</code><CopyValue value={profile.audience} label="Copy audience" iconOnly/></div></div>
    <p>Use structured authentication configuration or legacy issuer flags. Configure trust in the issuer CA explicitly.</p>
    <YamlView label="Cluster authentication configuration" value={profile.authentication_configuration}/>
    <CopyValue value={profile.legacy_flags.map(shellQuote).join(' ')} label="Copy legacy API-server flags"/>
    <h3>Namespace access example</h3><p>These bindings grant read-only view access to the saved groups. Kubernetes RBAC remains the authority for cluster permissions.</p>
    <YamlView label="Namespace RBAC examples" value={profile.rbac_bindings} documents/>
    </Panel>
    <TerminalLogin cluster={profile.cluster_id} username={username}/>
  </>;
}

function TerminalLogin({cluster,username}:{cluster:string;username:string}):JSX.Element {
  const commands=loginCommand(cluster,username);
  return <section className="kubernetes-terminal" aria-labelledby="kubernetes-terminal-heading">
    <div className="kubernetes-terminal-heading"><span className="kubernetes-terminal-icon"><TerminalIcon aria-hidden="true"/></span><div><h3 id="kubernetes-terminal-heading">Terminal login</h3><p>Generate a kubeconfig, then verify access with kubectl.</p></div></div>
    <p>Install the helper and configure <code>/etc/asterius/kube-helper.json</code> with your broker, cluster API server and trusted CA pins. The account argument selects a local credential store.</p>
    <div className="kubernetes-terminal-code"><pre tabIndex={0} role="region" aria-label="Terminal login commands"><code>{commands}</code></pre><CopyValue value={commands} label="Copy terminal commands"/></div>
  </section>;
}

interface Entitlement {entitlement_id:string;client_id:string;role_name:string;enabled:boolean}
interface Binding {cluster_client_id:string;controller_client_id:string;namespace:string;enabled:boolean}
interface Activation {activation_id:string;expires_at:number;revoked_at:number|null;status:string}
interface Request {request_id:string;status:string;deadline:number}
function TemporaryAccess({session,client,onMode}:{session:Session;client:string;onMode:(enabled:boolean|null)=>void}):JSX.Element {
  const [items,setItems]=useState<{entitlement:Entitlement;binding:Binding;activations:Activation[];requests:Request[];authentication:unknown}[]>([]);
  const [busy,setBusy]=useState(true);const [error,setError]=useState<string|null>(null);const [retry,setRetry]=useState(0);
  const readable=session.scopes.includes('admin.app_roles:read');
  useEffect(()=>{let current=true;onMode(null);if(!readable){setBusy(false);return;}setBusy(true);setError(null);
    (async()=>{const page=await read('temporary-entitlements') as {items:Entitlement[]};
      const rows=await mapBounded(page.items.filter(item=>item.client_id===client),async entitlement=>{
        const path=`temporary-entitlements/${encodeURIComponent(entitlement.entitlement_id)}`;
        const detail=await read(`${path}/kubernetes-binding`) as {binding:Binding|null;authentication_configuration:unknown};
        if(!detail.binding||detail.binding.cluster_client_id!==client)return null;
        const [activations,requests]=await Promise.all([read(`${path}/activations`),read(`${path}/requests`)]);
        return {entitlement,binding:detail.binding,authentication:detail.authentication_configuration,activations:(activations as {items:Activation[]}).items,requests:(requests as {items:Request[]}).items};
      });if(current){const present=rows.filter(row=>row!==null);setItems(present);onMode(present.some(row=>row.binding.enabled));}
    })().catch(e=>{if(current)setError(failure(e));}).finally(()=>{if(current)setBusy(false);});return()=>{current=false;};
  },[client,readable,retry,onMode]);
  return <Panel title="Temporary access" description="Up to 100 entitlements owned by your account; requests and activations are bounded snapshots. Controller bindings are saved configuration; live RoleBindings are not inspected.">
    {!readable?<Message tone="info">Temporary access requires application-role read permission.</Message>:busy?<Skeleton rows={2} label="Reading temporary access."/>:error?<LoadFailure message={error} onRetry={()=>setRetry(value=>value+1)}/>:items.length===0?<p>No owned Kubernetes temporary access bindings are configured for this application.</p>:items.map(item=><section key={item.entitlement.entitlement_id}>
      <h3>{item.entitlement.role_name} <Badge>{item.binding.enabled&&item.entitlement.enabled?'Enabled':'Disabled'}</Badge></h3>
      <p>Namespace: {item.binding.namespace}. Controller: {item.binding.controller_client_id}.</p>
      <DataTable caption={`Activations for ${item.entitlement.role_name}`} rows={item.activations} rowKey={a=>a.activation_id} empty={<p>No activations.</p>} columns={[
        {key:'status',header:'Status',cell:a=>a.revoked_at!==null?'Revoked':a.expires_at<=Date.now()/1000?'Expired':a.status},
        {key:'expiry',header:'Expiry',cell:a=>new Date(a.expires_at*1000).toLocaleString()},
      ]}/>
      <DataTable caption={`Requests for ${item.entitlement.role_name}`} rows={item.requests} rowKey={r=>r.request_id} empty={<p>No requests.</p>} columns={[
        {key:'status',header:'Approval',cell:r=>r.status},{key:'deadline',header:'Deadline',cell:r=>new Date(r.deadline*1000).toLocaleString()},
      ]}/>
      {item.authentication!=null&&<><p>Use this temporary identity configuration when this binding is enabled. The ordinary signed-token example above does not include temporary identities.</p><YamlView label="Temporary identity authentication" value={item.authentication}/></>}
    </section>)}
    {readable&&<Button disabled={busy} variant="ghost" onClick={()=>setRetry(value=>value+1)}>Refresh temporary access</Button>}
    <a href={hrefOf('temporary-privileges')} className="identity-link">Manage approvals and temporary privileges</a>
  </Panel>;
}
