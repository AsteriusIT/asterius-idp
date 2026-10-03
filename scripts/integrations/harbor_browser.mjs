// Native Harbor OIDC, session and project authorization controls; no credential output.
import { chromium } from '../../e2e/node_modules/playwright-core/index.mjs';
import { readFile,writeFile } from 'node:fs/promises';
const file=process.argv[2];const input=JSON.parse(await readFile(file,'utf8'));
const browser=await chromium.launch({headless:true,args:['--host-resolver-rules=MAP host.docker.internal '+input.bridge]});
const cases=[];let stage='start';
function check(label,status,expected){if(!expected.includes(status)){console.error('SAFE_CHILD_DIAGNOSTIC=native_status_'+status);throw new Error('unexpected native result');}cases.push({case:label,status});}
async function login(context,email){
  const page=await context.newPage();page.setDefaultTimeout(15000);
  const authorization=page.waitForRequest(r=>r.url().startsWith(input.issuer+'/authorize?'));
  await page.goto(input.application+'/c/oidc/login?redirect_url='+encodeURIComponent('/harbor/projects'));
  const query=new URL((await authorization).url()).searchParams;
  if(query.get('code_challenge_method')!=='S256'||!query.get('code_challenge')||!query.get('state'))throw new Error('native PKCE/state absent');
  // Record nonce support accurately; do not fabricate a native feature.
  input.nativeNonce=Boolean(query.get('nonce'));
  await page.locator('input[name="username"]').fill(email);
  await page.locator('input[name="password"]').fill('correct horse battery staple');
  const callback=page.waitForResponse(r=>r.url().startsWith(input.application+'/c/oidc/callback?')).catch(()=>null);
  await page.getByRole('button',{name:'Sign in',exact:true}).click();
  await Promise.race([page.getByRole('button',{name:'Allow',exact:true}).waitFor().catch(()=>null),page.waitForURL(input.application+'/**').catch(()=>null)]);
  if(await page.getByRole('button',{name:'Allow',exact:true}).isVisible())await page.getByRole('button',{name:'Allow',exact:true}).click();
  const response=await callback;if(!response)throw new Error('native callback missing');
  return {page,status:response.status()};
}
try{
 const context=await browser.newContext({ignoreHTTPSErrors:true});const privateProject=input.application+'/api/v2.0/projects/'+input.project;
 const admin=await browser.newContext({ignoreHTTPSErrors:true,extraHTTPHeaders:{Authorization:'Basic '+Buffer.from('admin:'+input.adminPassword).toString('base64')}});
 stage='anonymous';check('anonymous private project denied',(await context.request.get(privateProject)).status(),[401,403,404]);
 check('forged identity and groups cannot authenticate',(await context.request.get(input.application+'/api/v2.0/users/current',{headers:{'X-Forwarded-User':'admin','X-Forwarded-Groups':'admin'}})).status(),[401]);
 stage='approved login';check('native approved callback',(await login(context,'sweep@example.test')).status,[302,303]);
 const identityResponse=await context.request.get(input.application+'/api/v2.0/users/current');check('native stable user',identityResponse.status(),[200]);
 const csrf=identityResponse.headers()['x-harbor-csrf-token'];if(!csrf)throw new Error('native mutation CSRF token missing');
 const mutationHeaders={'X-Harbor-CSRF-Token':csrf,Origin:input.application,Referer:input.application+'/harbor/projects'};
 async function deniedMutation(label,response){const body=await response.text();if(/csrf|cross.site|referer|origin/i.test(body))throw new Error('mutation failed before authorization');check(label,response.status(),[403]);}
 const runtimeResponse=await context.request.get(input.application+'/api/v2.0/systeminfo');check('authenticated native runtime version',runtimeResponse.status(),[200]);
 const runtimeVersion=(await runtimeResponse.json()).harbor_version;if(typeof runtimeVersion!=='string'||!/^v?2\.15\.2(?:[-+]|$)/.test(runtimeVersion))throw new Error('native runtime version differs from pinned product');
 const identity=await identityResponse.json();if(identity.username!==input.approvedSub||identity.sysadmin_flag)throw new Error('native identity/admin mapping failed');
 check('authenticated subject without project assignment denied',(await context.request.get(privateProject)).status(),[403,404]);
 stage='own guest assignment';check('fixture assigns only this native user Guest',(await admin.request.post(privateProject+'/members',{data:{role_id:3,member_user:{user_id:identity.user_id}}})).status(),[201]);
 check('assigned Guest reads private project',(await context.request.get(privateProject)).status(),[200]);
 await deniedMutation('Guest cannot delete project',await context.request.delete(privateProject,{headers:mutationHeaders}));
 await deniedMutation('Guest cannot create another project',await context.request.post(input.application+'/api/v2.0/projects',{data:{project_name:'forbidden-native-project'},headers:mutationHeaders}));
 await deniedMutation('forged administrator header cannot delete',await context.request.delete(privateProject,{headers:{...mutationHeaders,'X-Forwarded-Groups':'admin','X-Harbor-User':'admin'}}));
 stage='source logout';const logout=await context.newPage();await logout.goto(input.issuer+'/logout');await logout.getByRole('button',{name:'Log out',exact:true}).click();
 check('source logout retains separate native session',(await context.request.get(privateProject)).status(),[200]);
 const cookies=await context.cookies(input.application);const session=cookies.find(c=>c.name==='sid');if(!session?.secure||!session.httpOnly)throw new Error('native session cookie flags failed');
 stage='native logout';check('native local logout',(await context.request.get(input.application+'/c/oidc/logout',{maxRedirects:0})).status(),[302,303]);
 check('native logout denies next private read',(await context.request.get(privateProject)).status(),[401,403,404]);
 const replay=await browser.newContext({ignoreHTTPSErrors:true});await replay.addCookies(cookies);check('logged out session replay denied',(await replay.request.get(privateProject)).status(),[401,403,404]);await replay.close();
 stage='unassigned';const denied=await browser.newContext({ignoreHTTPSErrors:true});check('unassigned subject authenticates without project role',(await login(denied,'denied@example.test')).status,[302,303]);
 check('unassigned subject cannot read private project',(await denied.request.get(privateProject)).status(),[403,404]);
 const deniedUser=await (await denied.request.get(input.application+'/api/v2.0/users/current')).json();if(deniedUser.sysadmin_flag)throw new Error('unassigned identity gained administrator');await denied.close();await admin.close();
 await writeFile(file,JSON.stringify({cases,runtimeVersion,nativeNonce:input.nativeNonce,cookie:{secure:session.secure,httpOnly:session.httpOnly,sameSite:session.sameSite},role:'Explicit local private-project Guest assignment to stable issuer subject; no OIDC admin/group mapping',sourceLogoutImmediatelyRevokes:false}));
} catch(error){console.error('PRODUCT_BROWSER_STAGE='+stage);process.exitCode=1;}finally{await browser.close();}
