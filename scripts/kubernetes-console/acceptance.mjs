import {createRequire} from 'node:module';
import {readFile,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import assert from 'node:assert/strict';
const {chromium}=createRequire(import.meta.url)('playwright');
const root=resolve(new URL('../..',import.meta.url).pathname);
const manifest=JSON.parse(await readFile(root+'/console/dist/.vite/manifest.json','utf8'));
const js=Object.values(manifest).find(item=>item.isEntry).file;
const css=Object.values(manifest).find(item=>item.file.endsWith('.css')).file;
const browser=await chromium.launch({headless:true});
const checks=[];let activePage;
const g1='11111111-1111-4111-8111-111111111111',g2='22222222-2222-4222-8222-222222222222';
const profile={cluster_id:'production',namespace:'tools',group_ids:[g2],revision:7,client_id:'broker',audience:'broker',issuer:'https://identity.test/t/team',registration_compatible:true,authentication_configuration:{kind:'AuthenticationConfiguration'},rbac_bindings:[],legacy_flags:['--oidc-client-id=broker']};
const client={client_id:'broker',client_name:'Production broker',status:'active'};
async function fixture(scopes=['admin.session:read','admin.clients:read','admin.clients:write','admin.groups:read','admin.app_roles:read']) {
 const context=await browser.newContext({viewport:{width:1280,height:900}});const page=await context.newPage();activePage=page;
 const errors=[];const writes=[];let conflict=false;let saved={...profile};
 page.on('pageerror',e=>errors.push(e.message));
 await page.route('https://kubernetes-console.test/**',async route=>{
  const url=new URL(route.request().url()); const path=url.pathname.split('/api/v1/')[1];
  const json=(value,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)});
  if(path!==undefined){
   if(path==='session')return json({tenant:'team',workspace:'team',user:'owner',username:'alice',roles:['tenant_admin'],scopes,deployment_scopes:[],csrf_token:'fixture'});
   if(path==='clients')return json({items:url.searchParams.has('cursor')?[{...client,client_id:'second',client_name:'Other broker'}]:[client],next_cursor:url.searchParams.has('cursor')?null:'next'});
   if(path==='clients/broker/kubernetes'&&route.request().method()==='PUT'){
    const body=route.request().postDataJSON();writes.push(body);if(conflict)return json({error:{message:'Profile changed; reload before saving.'}},409);
    assert.equal(body.revision,saved.revision);saved={...saved,...body,revision:saved.revision+1};return json(saved);
   }
   if(path==='clients/broker/kubernetes')return json(saved);
   if(path==='clients/second/kubernetes')return json({error:{message:'Backend unavailable'}},503);
   if(path==='clients/broker/kubernetes/online')return json({enabled:saved.revision===7,reviewer_client_id:'reviewer',revision:'online-revision'});
   if(path==='groups')return json({items:url.searchParams.has('cursor')?[{id:g2,name:'operators',display_name:'Operators'}]:[{id:g1,name:'developers',display_name:'Developers'}],next_cursor:url.searchParams.has('cursor')?null:'group-next'});
   if(path===`groups/${g2}`)return json({id:g2,name:'operators',display_name:'Operators'});
   if(path==='temporary-entitlements')return json({items:[{entitlement_id:'owned',client_id:'broker',role_name:'cluster-view',enabled:true}]});
   if(path==='temporary-entitlements/owned/kubernetes-binding')return json({binding:{cluster_client_id:'broker',controller_client_id:'controller',namespace:'tools',enabled:false},authentication_configuration:null});
   if(path==='temporary-entitlements/owned/activations')return json({items:[{activation_id:'active',status:'active',expires_at:Math.floor(Date.now()/1000)+300,revoked_at:null}]});
   if(path==='temporary-entitlements/owned/requests')return json({items:[{request_id:'request',status:'pending',deadline:Math.floor(Date.now()/1000)+300}]});
   return json({error:{message:'Fixture route absent'}},404);
  }
  if(url.pathname.includes('/assets/')){const file=url.pathname.split('/assets/')[1];return route.fulfill({body:await readFile(root+'/console/dist/assets/'+file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'font/woff2'});}
  return route.fulfill({contentType:'text/html',body:`<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/t/team/admin/${css}"></head><body><div id="console"></div><script type="module" src="/t/team/admin/${js}"></script></body></html>`});
 });
 await page.goto('https://kubernetes-console.test/t/team/admin/#/kubernetes');
 return {context,page,errors,writes,conflict:()=>{conflict=true;}};
}
try {
 const f=await fixture();const {page}=f;
 await page.getByRole('button',{name:'View production'}).waitFor();checks.push('cluster_directory_saved_profile');
 await page.getByRole('button',{name:'Load more applications'}).click();await page.getByText('Other broker: Backend unavailable').waitFor();checks.push('partial_catalogue_failure_is_visible');
 await page.getByRole('button',{name:'View production'}).click();
 await page.getByText('Online checks enabled',{exact:true}).waitFor();await page.getByText('Operators (operators)',{exact:true}).first().waitFor();
 await page.getByText('pending',{exact:true}).waitFor();checks.push('group_names_authentication_and_owned_approval_status');
 await page.getByRole('button',{name:'Next group page'}).click();await page.getByLabel('Operators (operators)').waitFor();await page.getByRole('button',{name:'First group page'}).click();await page.getByLabel('Developers (developers)').waitFor();checks.push('group_pagination_returns_to_first_page_without_losing_selection');
 await page.getByLabel('Developers (developers)').check();await page.getByRole('button',{name:'Save cluster profile'}).click();
 await page.getByText('Cluster profile saved. Onboarding below uses this saved revision.').waitFor();
 assert.deepEqual(new Set(f.writes[0].group_ids),new Set([g1,g2]));assert.equal(f.writes[0].revision,7);await page.getByText('Signed tokens',{exact:true}).waitFor();checks.push('authentication_refreshes_after_profile_save');checks.push('save_preserves_offpage_group_and_exact_revision');
 await page.getByLabel('Example RBAC namespace').fill('draft');f.conflict();await page.getByRole('button',{name:'Save cluster profile'}).click();
 await page.getByText('Profile changed; reload before saving.').waitFor();await page.getByText('Saved revision 8.',{exact:false}).waitFor();checks.push('concurrent_conflict_retains_saved_onboarding');
 await page.getByRole('button',{name:'Discard changes'}).click();
 await page.screenshot({path:'/tmp/ast-1r9t-kubernetes-desktop.png',fullPage:true});
 await page.setViewportSize({width:390,height:844});
 assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1));
 await page.screenshot({path:'/tmp/ast-1r9t-kubernetes-mobile.png',fullPage:true});checks.push('mobile_no_horizontal_overflow');
 assert.deepEqual(f.errors,[]);await f.context.close();
 const readOnly=await fixture(['admin.session:read','admin.clients:read']);await readOnly.page.getByRole('button',{name:'View production'}).click();
 await readOnly.page.getByText('You need group read permission',{exact:false}).waitFor();assert.ok(await readOnly.page.getByRole('button',{name:'Save cluster profile'}).isDisabled());
 await readOnly.page.getByText('Temporary access requires application-role read permission.').waitFor();assert.equal(readOnly.writes.length,0);assert.deepEqual(readOnly.errors,[]);checks.push('read_only_permissions_preserve_groups_and_hide_temporary_data');await readOnly.context.close();
 const evidence={status:'pass',fixture:'built console in Chromium with controlled tenant-scoped API responses; no live credentials used',checks,passed:checks.length};
 await writeFile('/tmp/ast-1r9t-kubernetes-browser.json',JSON.stringify(evidence,null,2)+'\n');process.stdout.write(JSON.stringify(evidence)+'\n');
}catch(e){if(activePage){await activePage.screenshot({path:'/tmp/ast-1r9t-browser-failure.png',fullPage:true});await writeFile('/tmp/ast-1r9t-browser-failure.txt',await activePage.locator('body').innerText());}throw e;}finally{await browser.close();}
