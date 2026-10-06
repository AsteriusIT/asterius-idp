import { Checkbox } from './components/ui/checkbox';
import { Accordion, AccordionItem, AccordionTrigger, AccordionContent } from './components/ui/accordion';
import { SelectionBar } from './components/selection-bar';
import { CharacterCountTextarea } from './components/character-count-textarea';
import { ReviewState } from './components/review-state';
import {useCallback,useEffect,useState,type JSX} from 'react';
import {mutate,read,type Session} from './api';
import {FormSelect} from './components/ui/select';
import {Actions,Badge,Button,ConfirmDialog,DataTable,EmptyState,Field,Message,Panel,Screen,Skeleton,Timestamp} from './ui';
import {applicationResult,mayApply,mayDecide,sourceLabel,targetSubject,type Ownership,type Reviewer,type Review,type ReviewItem,type ReviewTarget} from './access-reviews-model';
import {clientCatalogue,TENANT_CATALOGUE,type Catalogue} from './appRoles';

interface Named {id:string;label:string}
interface Page<T>{items:T[];next_cursor?:string|null}
const failure=(error:unknown)=>error instanceof Error?error.message:'The review operation failed.';
const options=(values:readonly Named[],selected='')=>[{value:'',label:'Choose…'},...values.map(value=>({value:value.id,label:value.label})),...(selected!==''&&!values.some(value=>value.id===selected)?[{value:selected,label:selected}]:[])];
function localTomorrow():string {const date=new Date(Date.now()+86_400_000);return new Date(date.getTime()-date.getTimezoneOffset()*60_000).toISOString().slice(0,16);}

function ItemCard({session,item,review,closed,onChanged,names}:{session:Session;item:ReviewItem;review:string;closed:boolean;onChanged:()=>void;names:ReadonlyMap<string,string>}):JSX.Element{
  const [reason,setReason]=useState('');const [busy,setBusy]=useState(false);const [error,setError]=useState('');const [confirm,setConfirm]=useState(false);
  const write=session.scopes.includes('admin.governance:write')&&!closed;
  async function command(action:'decision'|'apply',decision?:'retain'|'remove'){
    setBusy(true);setError('');
    try{await mutate(`governance/reviews/${review}/items/${item.id}/${action}`,action==='decision'?'PUT':'POST',session,action==='decision'?{decision,reason}:{});setConfirm(false);onChanged();}
    catch(error){setError(failure(error));}finally{setBusy(false);}
  }
  return <Panel title={`${sourceLabel(item.target)} · ${targetSubject(item.target,names)}`} description={`Snapshot observed ${new Date(item.snapshot.observed_at).toLocaleString()} — ${item.snapshot.affected_users.length} affected ${item.snapshot.affected_users.length === 1 ? 'account' : 'accounts'}`}>
    {error&&<Message tone="error">{error}</Message>}
    {item.snapshot.protected&&<Message tone="info">This source is managed. A removal decision proposes a change to its controller.</Message>}
    {item.snapshot.affected_users.length===0&&<p>No current group members were affected at snapshot time.</p>}
    <Accordion className="review-evidence" multiple defaultValue={item.snapshot.affected_users.map(user => user.user_id)}>{item.snapshot.affected_users.map(user=><AccordionItem key={user.user_id} value={user.user_id}>
      <AccordionTrigger aria-label={`Snapshot access for ${user.username}`}><span className="review-evidence-summary">{user.username}<span className="review-evidence-counts">{user.standing_sources.length} standing {user.standing_sources.length === 1 ? 'source' : 'sources'} · {user.temporary_sources.entries.length} temporary {user.temporary_sources.entries.length === 1 ? 'activation' : 'activations'}</span></span><Badge tone={user.account_status === 'active' ? 'ok' : 'neutral'}>{user.account_status}</Badge></AccordionTrigger>
      <AccordionContent><div className="stack">
      {user.account_status!=='active'&&<p>Account {user.account_status}: retained assignments do not imply currently usable access.</p>}
      <p>Standing application-role sources</p>
      <ul>{user.standing_sources.map((source,index)=><li key={index}>{source.name}{source.client_id?` · ${source.client_id}`:' · tenant'} — {source.group_id?`group ${names.get(source.group_id)??source.group_id}`:'direct assignment'}</li>)}</ul>
      {user.standing_sources.length===0&&<p className="muted">No standing application roles.</p>}
      {user.temporary_sources.entries.length>0&&<><p>Independent temporary activations (lifecycle evidence; token authority requires its own checks)</p><ul>{user.temporary_sources.entries.map(source=><li key={source.activation_id}>{source.role_name} · {source.client} · {source.resource} · expires {new Date(source.expires_at).toLocaleString()}<span className="muted"> ({source.permissions.join(', ')})</span></li>)}</ul></>}
    </div></AccordionContent></AccordionItem>)}</Accordion>
    <p className="muted">Only the selected standing source changes. Every independent direct/group source and temporary activation remains; removing membership withdraws that group’s contribution.</p>
    {item.decision!==null&&<p>Recorded decision: <strong>{item.decision}</strong> — {item.reason}</p>}
    <p role="status">{applicationResult(item.apply_status)}</p>
    {mayDecide(item,session.user,write)&&<form onSubmit={event=>{event.preventDefault();void command('decision','retain');}}>
      <Field label="Decision reason" required>{props=><CharacterCountTextarea {...props} value={reason} maxLength={1000} onChange={event=>setReason(event.target.value)} disabled={busy}/>}</Field>
      <Actions><Button type="submit" disabled={busy||reason.trim()===''}>Record retain</Button><Button type="button" disabled={busy||reason.trim()===''} onClick={()=>void command('decision','remove')}>Record remove</Button></Actions>
    </form>}
    {mayApply(item,session.user,write)&&<Button disabled={busy} onClick={()=>setConfirm(true)}>Apply recorded decision</Button>}
    {confirm&&<ConfirmDialog title="Apply this recorded decision?" body={<><p>{item.decision==='remove'?'The server rechecks current ownership and source revisions, then removes only this source. Changed or managed access is refused.':'Access stays as it is; the server records application of the retain decision.'}</p>{error&&<Message tone="error">{error}</Message>}</>} confirmLabel="Apply decision" busy={busy} onCancel={()=>setConfirm(false)} onConfirm={()=>void command('apply')}/>}
  </Panel>;
}

export function AccessReviews({session}:{session:Session}):JSX.Element{
  const [ownerships,setOwnerships]=useState<Ownership[]>([]);const [reviews,setReviews]=useState<Review[]>([]);const [reviewers,setReviewers]=useState<Reviewer[]>([]);
  const [directoryCursors,setDirectoryCursors]=useState<Record<'users'|'groups'|'clients',string|null>>({users:null,groups:null,clients:null});const [reviewersMore,setReviewersMore]=useState(false);
  const [users,setUsers]=useState<Named[]>([]);const [groups,setGroups]=useState<Named[]>([]);const [clients,setClients]=useState<Named[]>([]);const [roles,setRoles]=useState<Named[]>([]);
  const [kind,setKind]=useState<ReviewTarget['kind']>('membership');const [user,setUser]=useState('');const [group,setGroup]=useState('');const [client,setClient]=useState('');const [role,setRole]=useState('');
  const [owner,setOwner]=useState('');const [reviewer,setReviewer]=useState('');const [editing,setEditing]=useState<Ownership|null>(null);
  const [selected,setSelected]=useState<string[]>([]);const [due,setDue]=useState(localTomorrow);const [active,setActive]=useState<Review|null>(null);const [items,setItems]=useState<ReviewItem[]>([]);
  const [hasMore,setHasMore]=useState({ownership:false,reviews:false,items:false});
  const [loading,setLoading]=useState(true);const [busy,setBusy]=useState(false);const [error,setError]=useState('');const [notice,setNotice]=useState('');
  const write=session.scopes.includes('admin.governance:write')&&session.tenant===session.workspace;
  const names=new Map([...users,...groups,...reviewers.map(value=>({id:value.user_id,label:value.username}))].map(value=>[value.id,value.label]));
  const reload=useCallback(async()=>{
    setLoading(true);setError('');
    try{const [owners,history,eligible]=await Promise.all([read('governance/ownership?limit=50'),read('governance/reviews?limit=50'),read('governance/reviewers?limit=100')]);setOwnerships((owners as Page<Ownership>).items);setReviews((history as Page<Review>).items);setReviewers((eligible as Page<Reviewer>).items);setReviewersMore((eligible as Page<Reviewer>).items.length===100);setHasMore(previous=>({...previous,ownership:(owners as Page<Ownership>).items.length===50,reviews:(history as Page<Review>).items.length===50}));}
    catch(error){setError(failure(error));}finally{setLoading(false);}
  },[]);
  useEffect(()=>{void reload();},[reload]);
  useEffect(()=>{
    if(!write)return;
    let current=true;
    Promise.all([read('users?limit=100'),read('groups?limit=100'),read('clients?limit=100')]).then(([users,groups,clients])=>{
      if(!current)return;
      setDirectoryCursors({users:(users as Page<unknown>).next_cursor??null,groups:(groups as Page<unknown>).next_cursor??null,clients:(clients as Page<unknown>).next_cursor??null});
      setUsers((users as Page<{user_id:string;username:string}>).items.map(value=>({id:value.user_id,label:value.username})));
      setGroups((groups as Page<{id:string;display_name:string}>).items.map(value=>({id:value.id,label:value.display_name})));
      setClients((clients as Page<{client_id:string;client_name:string|null}>).items.map(value=>({id:value.client_id,label:value.client_name??value.client_id})));
    }).catch(error=>{if(current)setError(failure(error));});return()=>{current=false;};
  },[write]);
  useEffect(()=>{
    if(!write||kind==='membership'){setRoles([]);return;}
    let current=true;
    if(kind.includes('client')&&client===''){setRoles([]);return;}
    read(kind.includes('client')?clientCatalogue(client):TENANT_CATALOGUE).then(value=>{if(current)setRoles((value as Catalogue).roles.map(role=>({id:role.name,label:role.name})));}).catch(error=>{if(current)setError(failure(error));});
    return()=>{current=false;};
  },[kind,client,write]);
  async function action(command:()=>Promise<void>){setBusy(true);setError('');setNotice('');try{await command();}catch(error){setError(failure(error));}finally{setBusy(false);}}
  async function moreDirectory(resource:'users'|'groups'|'clients'){
    const cursor=directoryCursors[resource];if(!cursor)return;
    await action(async()=>{const page=await read(`${resource}?limit=100&cursor=${encodeURIComponent(cursor)}`) as Page<Record<string,string>>;
      const named:Named[]=page.items.map(value=>{const id=resource==='groups'?value.id:resource==='users'?value.user_id:value.client_id;const label=resource==='groups'?value.display_name:resource==='users'?value.username:value.client_name??value.client_id;if(typeof id!=='string'||typeof label!=='string')throw new Error('Directory response was incomplete.');return {id,label};});
      if(resource==='users')setUsers(previous=>[...previous,...named]);else if(resource==='groups')setGroups(previous=>[...previous,...named]);else setClients(previous=>[...previous,...named]);
      setDirectoryCursors(previous=>({...previous,[resource]:page.next_cursor??null}));
    });
  }
  async function moreReviewers(){const last=reviewers.at(-1);if(!last)return;await action(async()=>{const page=await read(`governance/reviewers?limit=100&after=${encodeURIComponent(last.user_id)}`) as Page<Reviewer>;setReviewers(previous=>[...previous,...page.items]);setReviewersMore(page.items.length===100);});}
  function target():ReviewTarget{
    switch(kind){case 'membership':return {kind,group_id:group,user_id:user};case 'user_tenant_role':return {kind,user_id:user,name:role};case 'user_client_role':return {kind,user_id:user,client_id:client,name:role};case 'group_tenant_role':return {kind,group_id:group,name:role};case 'group_client_role':return {kind,group_id:group,client_id:client,name:role};}
  }
  function edit(value:Ownership){setEditing(value);setKind(value.target.kind);setUser('user_id' in value.target?value.target.user_id:'');setGroup('group_id' in value.target?value.target.group_id:'');setClient('client_id' in value.target?value.target.client_id:'');setRole('name' in value.target?value.target.name:'');setOwner(value.owner??'');setReviewer(value.reviewers[0]??'');}
  async function open(review:Review){setActive(review);setItems([]);await action(async()=>{const [current,page]=await Promise.all([read(`governance/reviews/${review.id}`),read(`governance/reviews/${review.id}/items?limit=100`)]);setActive(current as Review);setItems((page as Page<ReviewItem>).items);setHasMore(previous=>({...previous,items:(page as Page<ReviewItem>).items.length===100}));});}
  async function more(resource:'ownership'|'reviews'){
    const rows=resource==='ownership'?ownerships:reviews;const last=rows.at(-1);if(!last)return;
    await action(async()=>{const value=await read(`governance/${resource}?limit=50&after=${encodeURIComponent(last.id)}`);setHasMore(previous=>({...previous,[resource]:(value as Page<unknown>).items.length===50}));if(resource==='ownership')setOwnerships(previous=>[...previous,...(value as Page<Ownership>).items]);else setReviews(previous=>[...previous,...(value as Page<Review>).items]);});
  }
  const selectionReady=owner!==''&&reviewer!==''&&(kind==='membership'?(user!==''&&group!==''):role!==''&&(kind.startsWith('user')?user!=='':group!=='')&&(!kind.includes('client')||client!==''));
  return <Screen title="Access reviews" description="Review explicit standing sources, record a decision, then apply it after current authority and provenance checks." actions={<Button disabled={busy||loading} onClick={()=>void reload()}>Refresh</Button>}>
    {error&&<Message tone="error">{error}</Message>}{notice&&<Message tone="success">{notice}</Message>}
    {loading&&<Skeleton label="Reading ownership and review history."/>}
    {write&&<Panel title={editing?'Edit ownership':'Assign an owner'} description="Owners and reviewers must remain active tenant administrators. Changing ownership invalidates old snapshots.">
      <form onSubmit={event=>{event.preventDefault();void action(async()=>{await mutate('governance/ownership','PUT',session,{target:target(),owner_user_id:owner,reviewers:[reviewer],enabled:true,expected_revision:editing?.revision??null});setEditing(null);await reload();setNotice('Ownership saved.');});}}><fieldset disabled={busy}>
        <Field label="Standing source">{props=><FormSelect {...props} disabled={editing!==null} value={kind} onValueChange={value=>{setKind(value as ReviewTarget['kind']);setRole('');}} options={[{value:'membership',label:'Group membership'},{value:'user_tenant_role',label:'User tenant role'},{value:'user_client_role',label:'User application role'},{value:'group_tenant_role',label:'Group tenant role'},{value:'group_client_role',label:'Group application role'}]}/>}</Field>
        {(kind==='membership'||kind.startsWith('user'))&&<Field label="User">{props=><FormSelect {...props} disabled={editing!==null} value={user} onValueChange={setUser} options={options(users,user)}/>}</Field>}
        {(kind==='membership'||kind.startsWith('group'))&&<Field label="Group">{props=><FormSelect {...props} disabled={editing!==null} value={group} onValueChange={setGroup} options={options(groups,group)}/>}</Field>}
        {kind.includes('client')&&<Field label="Application">{props=><FormSelect {...props} disabled={editing!==null} value={client} onValueChange={value=>{setClient(value);setRole('');}} options={options(clients,client)}/>}</Field>}
        {kind!=='membership'&&<Field label="Role">{props=><FormSelect {...props} disabled={editing!==null} value={role} onValueChange={setRole} options={options(roles,role)}/>}</Field>}
        <Field label="Owner">{props=><FormSelect {...props} value={owner} onValueChange={setOwner} options={options(reviewers.map(value=>({id:value.user_id,label:value.username})),owner)}/>}</Field>
        <Field label="Reviewer">{props=><FormSelect {...props} value={reviewer} onValueChange={setReviewer} options={options(reviewers.map(value=>({id:value.user_id,label:value.username})),reviewer)}/>}</Field>
        <Actions>{Object.entries(directoryCursors).filter(([,cursor])=>cursor!==null).map(([resource])=><Button key={resource} type="button" disabled={busy} onClick={()=>void moreDirectory(resource as 'users'|'groups'|'clients')}>Load more {resource}</Button>)}{reviewersMore&&<Button type="button" disabled={busy} onClick={()=>void moreReviewers()}>Load more eligible reviewers</Button>}</Actions>
        <p className="muted">Directory choices load in bounded pages. The server confirms the selected source exists.</p>
        <Actions><Button type="submit" disabled={!selectionReady||busy}>Save ownership</Button>{editing&&<Button type="button" onClick={()=>setEditing(null)}>Cancel edit</Button>}</Actions>
      </fieldset></form>
    </Panel>}
    <Panel title="Current ownership" description="Select existing ownership records for a bounded review. A review never grants access.">
      {!loading && <DataTable caption="Owned standing assignments" rows={ownerships} rowKey={value => value.id}
        columnPreferences={{ key: 'review-ownership', required: ['selection', 'source', 'subject', 'state'] }}
        empty={<EmptyState title="No owned standing assignments." body="Assign an owner to an existing standing source before creating a review." />}
        columns={[
          { key: 'selection', header: 'Select', cell: value => <Checkbox aria-label={`Select ${sourceLabel(value.target)} for ${targetSubject(value.target,names)}`} disabled={!write || busy || !value.enabled} checked={selected.includes(value.id)} onCheckedChange={checked => setSelected(previous => checked ? [...new Set([...previous,value.id])] : previous.filter(id => id !== value.id))} /> },
          { key: 'source', header: 'Standing source', sortBy: value => sourceLabel(value.target), cell: value => sourceLabel(value.target) },
          { key: 'subject', header: 'Subject', sortBy: value => targetSubject(value.target,names), cell: value => targetSubject(value.target,names) },
          { key: 'owner', header: 'Owner', sortBy: value => value.owner ? names.get(value.owner) ?? value.owner : '', cell: value => value.owner ? names.get(value.owner) ?? value.owner : 'Removed' },
          { key: 'state', header: 'State', cell: value => <Badge tone={value.enabled ? 'ok' : 'neutral'}>{value.enabled ? 'Enabled' : 'Disabled'}</Badge> },
          { key: 'actions', header: 'Actions', actions: true, cell: value => write && <Button small disabled={busy} onClick={() => edit(value)}>Edit ownership</Button> },
        ]} />}
      {write && <SelectionBar count={selected.length} disabled={busy} onClear={() => setSelected([])} />}

      {hasMore.ownership&&<Button disabled={busy} onClick={()=>void more('ownership')}>Load more ownership</Button>}
      {write&&<form onSubmit={event=>{event.preventDefault();void action(async()=>{const review=await mutate('governance/reviews','POST',session,{ownership_ids:selected,reviewer_id:reviewer,due_at:new Date(due).toISOString()}) as Review;setSelected([]);await reload();await open(review);setNotice('Review snapshot created.');});}}>
        <Field label="Assigned reviewer">{props=><FormSelect {...props} value={reviewer} onValueChange={setReviewer} options={options(reviewers.map(value=>({id:value.user_id,label:value.username})),reviewer)}/>}</Field>
        <Field label="Review deadline" required>{props=><input {...props} type="datetime-local" value={due} onChange={event=>setDue(event.target.value)}/>}</Field>
        <Button type="submit" disabled={busy||selected.length===0||selected.length>200||reviewer===''||due===''}>Create review ({selected.length} selected)</Button>
      </form>}
    </Panel>
    <Panel title="Review history">
      {!loading && <DataTable caption="Access review history" rows={reviews} rowKey={value => value.id}
        columnPreferences={{ key: 'review-history', required: ['created', 'state'] }}
        empty={<EmptyState title="No reviews have been created." body="Select owned standing assignments and create a review snapshot." />}
        columns={[
          { key: 'created', header: 'Created', sortBy: value => value.created_at, cell: value => <Timestamp value={value.created_at} /> },
          { key: 'due', header: 'Deadline', sortBy: value => value.due_at, cell: value => <Timestamp value={value.due_at} /> },
          { key: 'state', header: 'State', cell: value => <ReviewState review={value} /> },
          { key: 'actions', header: 'Actions', actions: true, cell: value => <Button small disabled={busy} onClick={() => void open(value)}>Open review</Button> },
        ]} />}
      {hasMore.reviews&&<Button disabled={busy} onClick={()=>void more('reviews')}>Load more reviews</Button>}
    </Panel>
    {active&&<><Panel title="Selected review" description={`Due ${new Date(active.due_at).toLocaleString()}`}>
      {write&&active.created_by===session.user&&!active.cancelled_at&&!active.completed_at&&<Button disabled={busy} onClick={()=>void action(async()=>{await mutate(`governance/reviews/${active.id}/cancel`,'POST',session,{});await reload();await open(active);})}>Cancel review</Button>}
      {hasMore.items&&<Button disabled={busy} onClick={()=>void action(async()=>{const last=items.at(-1);if(!last)return;const page=await read(`governance/reviews/${active.id}/items?limit=100&after=${encodeURIComponent(last?.id??'')}`) as Page<ReviewItem>;setItems(previous=>[...previous,...page.items]);setHasMore(previous=>({...previous,items:page.items.length===100}));})}>Load more review items</Button>}
    </Panel>{items.map(item=><ItemCard key={item.id} session={session} item={item} review={active.id} closed={Boolean(active.completed_at||active.cancelled_at)||Date.now()>=new Date(active.due_at).getTime()} names={names} onChanged={()=>void open(active)}/>)}</>}
  </Screen>;
}
