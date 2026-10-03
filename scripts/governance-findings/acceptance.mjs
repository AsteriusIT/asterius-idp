import assert from 'node:assert/strict';
import {createServer} from 'node:https';
import {readFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {createHash,randomBytes,randomUUID} from 'node:crypto';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
const dependencies=process.env.ASTERIUS_E2E_NODE_MODULES??new URL('../../e2e/node_modules/',import.meta.url).pathname;
const {chromium}=await import(pathToFileURL(join(dependencies,'playwright-core/index.mjs')).href);

const input=JSON.parse(await readFile(process.argv[2],'utf8'));
assert(input.database.startsWith('ast_product_'));
const actor='3f1d5c2a-0000-4000-8000-000000000001';
const callbackUrl='https://localhost:9481/callback';
const checks=[];
let stage='bootstrap',callback;
const quote=value=>"'"+value.replaceAll("'","''")+"'";
function sql(body){return execFileSync('docker',['exec','-i',input.db_container,'psql','-U','asterius','-d',input.database,'-X','-At','-v','ON_ERROR_STOP=1'],{input:body,encoding:'utf8',stdio:['pipe','pipe','pipe']}).trim();}
const callbackServer=createServer({key:await readFile(input.tls_key),cert:await readFile(input.tls_certificate)},(request,response)=>{
  callback=new URL(request.url,callbackUrl);response.writeHead(200,{'Content-Type':'text/html'});response.end('<!doctype html><title>Controlled callback</title><p>Callback received</p>');
});
await new Promise((resolve,reject)=>{callbackServer.once('error',reject);callbackServer.listen(9481,'127.0.0.1',resolve);});
const browser=await chromium.launch({headless:true,args:['--no-sandbox','--host-resolver-rules=MAP localhost 127.0.0.1']});
try {
  const context=await browser.newContext({ignoreHTTPSErrors:true});
  const page=await context.newPage();page.setDefaultTimeout(15000);
  stage='actual password console login';
  const verifier=randomBytes(32).toString('base64url'),state=randomBytes(24).toString('base64url');
  const params=new URLSearchParams({response_type:'code',client_id:input.client_id,redirect_uri:callbackUrl,scope:'openid email',state,nonce:randomBytes(24).toString('base64url'),code_challenge_method:'S256',code_challenge:createHash('sha256').update(verifier).digest('base64url')});
  await page.goto(input.issuer+'/authorize?'+params);
  await page.locator('input[name="username"]').fill('sweep@example.test');
  await page.locator('input[name="password"]').fill('correct horse battery staple');
  await page.getByRole('button',{name:'Sign in',exact:true}).click();
  const allow=page.getByRole('button',{name:'Allow',exact:true});
  await Promise.race([allow.waitFor({state:'visible'}),page.waitForURL(url=>url.port==='9481')]);
  if(await allow.isVisible())await allow.click();
  await page.waitForURL(url=>url.port==='9481');
  assert(callback.searchParams.has('code'));assert.equal(callback.searchParams.get('state'),state);
  const api=input.issuer+'/admin/api/v1/';
  assert.equal((await context.request.get(api+'session')).status(),200);
  checks.push('actual_password_console_cookie_login');
  const old=uuid=>`insert into users(tenant_id,user_id,username,created_at) values('e2e',${quote(uuid)},${quote('fixture-'+uuid)},clock_timestamp()-interval '400 days');`;
  const recovery=randomUUID(),scim=randomUUID(),ldap=randomUUID(),deleted=randomUUID(),recent=randomUUID(),otherTenantUser=randomUUID();
  stage='controlled provenance seed';
  sql(`insert into tenants(tenant_id,issuer,display_name,default_resource) values('other-findings','https://other.example.test/findings','Other findings','https://other.example.test/api');insert into users(tenant_id,user_id,username,status,created_at) values('other-findings',${quote(otherTenantUser)},'other-tenant-only','disabled',clock_timestamp()-interval '400 days');`);
  sql(old(recovery)+old(scim)+old(ldap)+old(deleted)+old(recent)+`
    insert into user_roles(tenant_id,user_id,role,tenant_is_reserved) values('e2e',${quote(recovery)},'tenant_admin',false);
    insert into scim_user_external_ids(tenant_id,client_id,user_id) values('e2e','missing-source',${quote(scim)});
    insert into scim_user_external_ids(tenant_id,client_id,user_id,deleted_at) values('e2e',${quote(input.client_id)},${quote(deleted)},clock_timestamp());
    insert into ldap_user_owners(tenant_id,source_key,user_id,external_id,missing_since) values('e2e',repeat('a',64),${quote(ldap)},'controlled-vendor-id',clock_timestamp()-interval '8 days');
    insert into sessions(tenant_id,session_id,public_sid,user_id,authenticated_at,last_seen_at,expires_at,idle_expires_at)
      values('e2e',repeat('b',64),'controlled-recent',${quote(recent)},clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '1 hour');
  `);
  sql(Array.from({length:105},(_,index)=>{
    const id='00000000-0000-4000-8000-'+index.toString(16).padStart(12,'0');
    return `insert into users(tenant_id,user_id,username) values('e2e',${quote(id)},${quote('recent-empty-scan-'+index)});`;
  }).join(''));
  async function report(section,after,limit=25){
    const query=new URLSearchParams({section,limit:String(limit)});if(after)query.set('after',after);
    const response=await context.request.get(api+'governance/findings?'+query);
    assert.equal(response.status(),200);assert(response.headers()['cache-control'].includes('no-store'));
    const value=await response.json();assert.equal(value.read_only,true);assert.equal(value.section,section);
    assert(value.scanned<=100);assert(value.items.length<=limit);return value;
  }
  async function all(section,limit=25){
    const findings=[];const cursors=new Set();let next;
    for(let count=0;count<100;count++){
      const value=await report(section,next,limit);findings.push(...value.items);
      if(value.next===null)return findings;
      assert(!cursors.has(value.next));cursors.add(value.next);next=value.next;
    }
    throw new Error('bounded fixture continuation did not terminate');
  }
  stage='source distinctions and recovery';
  const empty=await report('accounts');assert.equal(empty.items.length,0);assert.equal(empty.scanned,100);assert(empty.next);
  checks.push('empty_bounded_scan_still_exposes_continuation');
  const accounts=await all('accounts',2),byUser=new Map(accounts.map(item=>[item.evidence.user_id,item]));
  assert(byUser.get(recovery).reasons.includes('protected_recovery_account'));
  assert(byUser.get(recovery).reasons.includes('unknown_activity'));
  assert(!byUser.get(recovery).reasons.includes('disconnected_source'));
  assert(byUser.get(scim).reasons.includes('disconnected_source'));
  assert(!byUser.get(scim).reasons.includes('upstream_deleted'));
  assert(byUser.get(deleted).reasons.includes('upstream_deleted'));
  assert(byUser.get(ldap).reasons.includes('upstream_absent'));
  assert(byUser.get(ldap).reasons.includes('disconnected_source'));
  assert(!byUser.has(recent));assert(!byUser.has(otherTenantUser));
  checks.push('actual_other_tenant_disabled_account_never_selected');
  assert(!JSON.stringify(accounts).includes('controlled-vendor-id'));
  assert.equal(new Set(accounts.map(item=>item.key)).size,accounts.length);
  checks.push('disconnection_upstream_deletion_ldap_absence_and_unknown_activity_distinct','local_recovery_preserved_and_recent_activity_not_flagged','opaque_pagination_no_duplicates_or_vendor_identifiers');
  stage='query and cursor denial';
  for(const query of ['limit=0','limit=51','section=accounts&section=accounts','tenant=other','after=invalid']){
    assert.equal((await context.request.get(api+'governance/findings?'+query)).status(),400);
  }
  const cursor=(await report('accounts',undefined,1)).next;assert(cursor);
  assert.equal((await context.request.get(api+'governance/findings?section=ownership&after='+encodeURIComponent(cursor))).status(),400);
  const forged=JSON.parse(Buffer.from(cursor,'base64url').toString());forged.tenant='other';
  assert.equal((await context.request.get(api+'governance/findings?after='+Buffer.from(JSON.stringify(forged)).toString('base64url'))).status(),400);
  checks.push('unknown_duplicate_bounds_and_cross_tenant_section_cursors_refused');
  stage='source generation and current review context';
  const ownership=randomUUID(),review=randomUUID(),item=randomUUID();
  sql(`insert into tenant_roles(tenant_id,name) values('e2e','findings-review');
    insert into user_tenant_roles(tenant_id,user_id,name,granted_at) values('e2e',${quote(recent)},'findings-review',clock_timestamp()-interval '400 days');
    insert into governance_ownerships(tenant_id,ownership_id,target_kind,target_keys,owner_user_id,reviewers)
      values('e2e',${quote(ownership)},'user_tenant_role',jsonb_build_array(${quote(recent)},'findings-review'),${quote(actor)},array[${quote(actor)}::uuid]);
    insert into governance_reviews(tenant_id,review_id,created_by,created_at,due_at,completed_at)
      values('e2e',${quote(review)},${quote(actor)},clock_timestamp()-interval '10 days',clock_timestamp()-interval '9 days',clock_timestamp()-interval '9 days');
    insert into governance_review_items(tenant_id,review_id,item_id,ownership_id,ownership_revision,target_kind,target_keys,assignment_generation,assigned_reviewer,snapshot,decision,decided_by,decided_at,reason,apply_status,applied_by,applied_at)
      select 'e2e',${quote(review)},${quote(item)},o.ownership_id,o.revision,o.target_kind,o.target_keys,a.governance_generation,${quote(actor)},
        jsonb_build_object('context',jsonb_build_object('group',null,'catalogue',jsonb_build_object('name',r.name,'description',r.description,'created_at',r.created_at),'accounts',jsonb_build_object('status',u.status,'updated_at',u.updated_at))),
        'retain',${quote(actor)},clock_timestamp()-interval '9 days','Controlled historical review','retained',${quote(actor)},clock_timestamp()-interval '9 days'
      from governance_ownerships o join user_tenant_roles a on a.tenant_id=o.tenant_id and a.user_id=${quote(recent)} and a.name='findings-review'
        join tenant_roles r on r.tenant_id=a.tenant_id and r.name=a.name join users u on u.tenant_id=a.tenant_id and u.user_id=a.user_id
      where o.tenant_id='e2e' and o.ownership_id=${quote(ownership)};
  `);
  const sourceKey=(await all('assignments')).find(value=>value.evidence.target?.name==='findings-review');assert.equal(sourceKey,undefined);
  sql(`update users set status='disabled' where tenant_id='e2e' and user_id=${quote(recent)};update users set status='active' where tenant_id='e2e' and user_id=${quote(recent)};`);
  let changed=(await all('assignments')).find(value=>value.evidence.target?.name==='findings-review');
  assert(changed.reasons.includes('stale_review'));assert(changed.reasons.includes('unreviewed_privilege'));
  sql(`delete from user_tenant_roles where tenant_id='e2e' and user_id=${quote(recent)} and name='findings-review';insert into user_tenant_roles(tenant_id,user_id,name,granted_at) values('e2e',${quote(recent)},'findings-review',clock_timestamp()-interval '400 days');`);
  changed=(await all('assignments')).find(value=>value.evidence.target?.name==='findings-review');
  assert(changed.reasons.includes('unreviewed_privilege'));assert.equal(changed.evidence.last_applied_retain_at,null);
  checks.push('exact_current_applied_retain_covers_source','account_status_aba_invalidates_context','assignment_delete_recreate_never_inherits_old_review');
  stage='managed stale membership and missing owner';
  const group=randomUUID(),missingOwner=randomUUID();
  sql(`insert into managed_groups(tenant_id,group_id,name,display_name,created_at,updated_at) values('e2e',${quote(group)},'findings-managed','Controlled managed group',clock_timestamp(),clock_timestamp());
    insert into group_memberships(tenant_id,group_id,user_id,created_at) values('e2e',${quote(group)},${quote(recent)},clock_timestamp()-interval '400 days');
    insert into ldap_group_owners(tenant_id,source_key,group_id,external_id,missing_since) values('e2e',repeat('a',64),${quote(group)},'hidden-upstream-group',clock_timestamp());
    insert into governance_ownerships(tenant_id,ownership_id,target_kind,target_keys,owner_user_id,reviewers) values('e2e',${quote(missingOwner)},'membership',jsonb_build_array(${quote(group)},${quote(recent)}),null,array[${quote(randomUUID())}::uuid]);`);
  stage='managed membership report';
  const member=(await all('assignments')).find(value=>value.evidence.target?.group_id===group);
  stage='managed membership age and owner';
  assert(member.reasons.includes('stale_membership'));assert(member.reasons.includes('missing_owner'));
  stage='managed membership disconnected absence';
  assert(member.reasons.includes('disconnected_source'));assert(member.reasons.includes('upstream_absent'));
  assert.equal(member.evidence.managed_provenance.ldap,true);assert(!JSON.stringify(member).includes('hidden-upstream-group'));
  stage='missing owner report';
  const missing=(await all('ownership')).find(value=>value.evidence.ownership_id===missingOwner);
  assert(missing.reasons.includes('missing_owner'));assert(missing.reasons.includes('reviewer_unavailable'));
  checks.push('old_managed_membership_keeps_provenance_and_requires_review','missing_owner_and_unavailable_reviewers_reported');
  stage='orphaned temporary entitlement';
  const temporary=randomUUID();
  sql(`insert into temporary_entitlements(tenant_id,entitlement_id,client_id,resource,role_name,permissions,owner_user_id,editor_user_id,requester_acr,approver_acr)
    values('e2e',${quote(temporary)},'removed-application','https://removed.example.test','removed-role',array['documents:read'],${quote(randomUUID())},${quote(actor)},'urn:controlled:uv','urn:controlled:uv');`);
  const orphanedTemporary=(await all('temporary_entitlements')).find(value=>value.evidence.entitlement_id===temporary);
  assert(orphanedTemporary.reasons.includes('missing_owner'));assert(orphanedTemporary.reasons.includes('disconnected_source'));
  assert.equal(orphanedTemporary.evidence.standing_review_coverage,false);
  checks.push('temporary_owner_and_source_tombstones_separate_from_standing_review');
  stage='orphaned ownership and readonly authority';
  sql(`delete from user_tenant_roles where tenant_id='e2e' and user_id=${quote(recent)} and name='findings-review';`);
  const orphan=(await all('ownership')).find(value=>value.evidence.ownership_id===ownership);
  assert(orphan.reasons.includes('disconnected_source'));
  const before=sql("select (select count(*) from users where tenant_id='e2e')||':'||(select count(*) from user_roles where tenant_id='e2e')||':'||(select count(*) from governance_review_items where tenant_id='e2e');");
  for(const section of ['accounts','ownership','assignments','temporary_entitlements','administrative_roles'])await all(section);
  assert.equal(sql("select (select count(*) from users where tenant_id='e2e')||':'||(select count(*) from user_roles where tenant_id='e2e')||':'||(select count(*) from governance_review_items where tenant_id='e2e');"),before);
  checks.push('disappeared_standing_source_reported','all_five_categories_leave_authority_and_review_rows_unchanged');
  stage='actual findings console';
  await page.goto(input.issuer+'/admin/#/governance-findings');
  await page.getByRole('heading',{name:'Governance findings',exact:true}).waitFor();
  await page.getByRole('status').filter({hasText:'findings shown'}).waitFor();
  await page.getByRole('button',{name:'Continue bounded scan',exact:true}).click();
  await page.getByText('Preserve this possible local recovery account',{exact:true}).waitFor();
  assert(await page.getByText('Preserve this possible local recovery account',{exact:true}).isVisible());
  assert.equal(await page.getByRole('button',{name:/delete|remove|apply|cleanup/i}).count(),0);
  await page.setViewportSize({width:390,height:844});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  await page.addScriptTag({path:join(dependencies,'axe-core/axe.min.js')});
  const accessibility=await page.evaluate(()=>window.axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}}));assert.equal(accessibility.violations.length,0);
  checks.push('actual_readonly_console_recovery_explanation_mobile_and_accessibility');
  stage='readonly auditor and support boundaries';
  sql(`delete from user_roles where tenant_id='e2e' and user_id=${quote(actor)} and role='tenant_admin';insert into user_roles(tenant_id,user_id,role,tenant_is_reserved) values('e2e',${quote(actor)},'security_auditor',false);`);
  assert.equal((await context.request.get(api+'governance/findings')).status(),200);
  sql(`delete from user_roles where tenant_id='e2e' and user_id=${quote(actor)} and role='security_auditor';insert into user_roles(tenant_id,user_id,role,tenant_is_reserved) values('e2e',${quote(actor)},'user_support',false);`);
  assert([403,404].includes((await context.request.get(api+'governance/findings')).status()));
  sql(`delete from user_roles where tenant_id='e2e' and user_id=${quote(actor)} and role='user_support';insert into user_roles(tenant_id,user_id,role,tenant_is_reserved) values('e2e',${quote(actor)},'tenant_admin',false);`);
  checks.push('security_auditor_read_only_allowed_support_denied');
  stage='live actor withdrawal';
  sql(`delete from user_roles where tenant_id='e2e' and user_id=${quote(actor)} and role='tenant_admin';`);
  assert([403,404].includes((await context.request.get(api+'governance/findings')).status()));
  checks.push('current_administrator_authority_required');
  console.log(JSON.stringify({checks,passed:checks.length,real_password_console_login:true,
    controlled_provenance_and_historical_review_seeds:true,live_scim_ldap_feed:false,
    no_mutation_or_notification:true,owned_database_only:true}));
  await context.close();
} catch {
  console.error('GOVERNANCE_FINDINGS_STAGE='+stage);process.exitCode=1;
} finally {
  await browser.close();await new Promise(resolve=>callbackServer.close(resolve));
}
