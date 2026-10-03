/** Standing sources stay separate from effective access and temporary activations. */
export type ReviewTarget =
  | {kind:'membership';group_id:string;user_id:string}
  | {kind:'user_tenant_role';user_id:string;name:string}
  | {kind:'user_client_role';user_id:string;client_id:string;name:string}
  | {kind:'group_tenant_role';group_id:string;name:string}
  | {kind:'group_client_role';group_id:string;client_id:string;name:string};
export interface Reviewer {user_id:string;username:string}
export interface Ownership {id:string;target:ReviewTarget;owner:string|null;reviewers:string[];revision:string;enabled:boolean}
export interface Review {id:string;created_by:string;created_at:string;due_at:string;completed_at:string|null;cancelled_at:string|null}
export interface ReviewItem {
  id:string;ownership_id:string;ownership_revision:string;target:ReviewTarget;assignment_generation:string;assigned_reviewer:string;
  snapshot:{observed_at:string;protected:boolean;affected_users:readonly {
    user_id:string;username:string;account_status:string;standing_sources:readonly {client_id:string|null;name:string;group_id:string|null}[];
    temporary_sources:{entries:readonly {activation_id:string;client:string;resource:string;role_name:string;permissions:readonly string[];expires_at:string}[]};
  }[]};
  decision:'retain'|'remove'|null;reason:string|null;apply_status:'pending'|'retained'|'removed'|'absent'|'conflict'|'protected';
}
export function sourceLabel(target:ReviewTarget):string {
  if(target.kind==='membership')return 'Group membership';
  return `${target.kind.startsWith('group')?'Group':'User'} ${target.kind.includes('client')?'application':'tenant'} role: ${target.name}`;
}
export function mayDecide(item:ReviewItem,user:string,write:boolean):boolean {
  return write&&item.assigned_reviewer===user&&item.decision===null&&item.apply_status==='pending';
}
export function mayApply(item:ReviewItem,user:string,write:boolean):boolean {
  return write&&item.assigned_reviewer===user&&item.decision!==null&&item.apply_status==='pending';
}
export function applicationResult(status:ReviewItem['apply_status']):string {
  switch(status){
    case 'pending':return 'Decision has not been applied';
    case 'retained':return 'Retained; access was not changed';
    case 'removed':return 'Only this standing source was removed';
    case 'absent':return 'Source was already absent';
    case 'conflict':return 'Source or ownership changed; create a new review';
    case 'protected':return 'Managed source protected; request removal through its controller';
  }
}

export function targetSubject(target:ReviewTarget,names:ReadonlyMap<string,string>):string {
  if(target.kind==='membership')return `${names.get(target.user_id)??target.user_id} in ${names.get(target.group_id)??target.group_id}`;
  const id='user_id' in target?target.user_id:target.group_id;
  return names.get(id)??id;
}
