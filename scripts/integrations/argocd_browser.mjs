// Native Argo CD OIDC, server session and authorization controls; no credential output.
import { chromium } from '../../e2e/node_modules/playwright-core/index.mjs';
import { readFile,writeFile } from 'node:fs/promises';
const file=process.argv[2];const input=JSON.parse(await readFile(file,'utf8'));
const browser=await chromium.launch({headless:true,args:['--host-resolver-rules=MAP host.docker.internal '+input.bridge]});
const cases=[];let stage='start';
function check(label,status,expected){if(!expected.includes(status)){stage+=' check='+label+' status='+status;throw new Error('unexpected native result');}cases.push({case:label,status});}
async function deniedApplication(label,response,action){
 check(label,response.status(),[403]);
 const body=await response.json();
 if(body.code!==7||!/permission denied/i.test(body.message??'')){
  stage='native RBAC evidence action='+action+' code='+String(body.code)+' permissionDenied='+String(/permission denied/i.test(body.message??''));throw new Error('denial did not reach bounded application RBAC');
 }
}
async function login(context,email){
  const page=await context.newPage();page.setDefaultTimeout(15000);
  const authorization=page.waitForRequest(r=>r.url().startsWith(input.issuer+'/authorize?'));
  stage='native authorize redirect';await page.goto(input.application+'/auth/login?return_url='+encodeURIComponent(input.application+'/applications'));
  stage='native authorization request';const query=new URL((await authorization).url()).searchParams;
  if(query.get('code_challenge_method')!=='S256'||!query.get('code_challenge')||!query.get('state'))throw new Error('native PKCE/state absent');
  // Record nonce support accurately; do not fabricate a native feature.
  input.nativeNonce=Boolean(query.get('nonce'));
  stage='source credentials';await page.locator('input[name="username"]').fill(email);
  await page.locator('input[name="password"]').fill('correct horse battery staple');
  const callback=page.waitForResponse(r=>r.url().startsWith(input.application+'/auth/callback?')).catch(()=>null);
  await page.getByRole('button',{name:'Sign in',exact:true}).click();
  await Promise.race([page.getByRole('button',{name:'Allow',exact:true}).waitFor().catch(()=>null),page.waitForURL(input.application+'/**').catch(()=>null)]);
  if(await page.getByRole('button',{name:'Allow',exact:true}).isVisible())await page.getByRole('button',{name:'Allow',exact:true}).click();
  stage='native callback';const response=await callback;if(!response)throw new Error('native callback missing');
  return {page,status:response.status()};
}
try{
 const context=await browser.newContext({ignoreHTTPSErrors:true});
 const appApi=input.application+'/api/v1/applications/'+input.applicationName;
 stage='anonymous';check('anonymous application API denied',(await context.request.get(appApi)).status(),[401]);
 check('forged identity headers do not authenticate',(await context.request.get(appApi,{headers:{'X-Forwarded-User':'admin','X-Forwarded-Groups':'admin'}})).status(),[401]);
 stage='approved login';check('native approved callback',(await login(context,'sweep@example.test')).status,[302,303]);
 stage='native identity';const user=await (await context.request.get(input.application+'/api/v1/session/userinfo')).json();
 if(!user.loggedIn||user.username!==input.approvedSub)throw new Error('native identity differs from exact issuer subject');
 check('observer reads own application',(await context.request.get(appApi)).status(),[200]);
 await deniedApplication('observer cannot synchronize application',await context.request.post(appApi+'/sync',{data:{}}),'sync');
 await deniedApplication('observer cannot delete application',await context.request.delete(appApi,{data:{}}),'delete');
 await deniedApplication('forged admin group header retains observer',await context.request.post(appApi+'/sync',{data:{},headers:{'X-Forwarded-Groups':'admin'}}),'sync');
 const cookies=await context.cookies(input.application);const session=cookies.find(c=>c.name==='argocd.token');if(!session?.secure||!session.httpOnly)throw new Error('native auth cookie flags failed');
 stage='source logout';const logout=await context.newPage();await logout.goto(input.issuer+'/logout');await logout.getByRole('button',{name:'Log out',exact:true}).click();
 check('source logout retains separate application session',(await context.request.get(appApi)).status(),[200]);
 stage='native logout';check('legacy session DELETE does not revoke',(await context.request.delete(input.application+'/api/v1/session',{data:{}})).status(),[200]);
 check('legacy session DELETE leaves native access active',(await context.request.get(appApi)).status(),[200]);
 check('native logout endpoint',(await context.request.get(input.application+'/auth/logout',{maxRedirects:0})).status(),[303]);
 // A captured native cookie is private to this fixture and never printed or exported.
 const replay=await browser.newContext({ignoreHTTPSErrors:true});await replay.addCookies(cookies);
 check('native logout clears browser cookie',(await context.request.get(appApi)).status(),[401]);
 check('captured OIDC cookie cannot replay after native logout',(await replay.request.get(appApi)).status(),[401]);await replay.close();
 stage='unassigned';const denied=await browser.newContext({ignoreHTTPSErrors:true});check('unassigned subject authenticates without role',(await login(denied,'denied@example.test')).status,[302,303]);
 await deniedApplication('unassigned subject cannot read private application',await denied.request.get(appApi),'get');
 await deniedApplication('unassigned subject cannot synchronize',await denied.request.post(appApi+'/sync',{data:{}}),'sync');await denied.close();
 await writeFile(file,JSON.stringify({cases,nativeNonce:input.nativeNonce,cookie:{secure:true,httpOnly:true,sameSite:session.sameSite},role:'Exact issuer subject observer; no group/admin mapping',roleDenials:'native PermissionDenied code7 on real bounded application actions',sourceLogoutImmediatelyRevokes:false,nativeLogoutImmediatelyRevokesCapturedToken:true,idTokenLifetimeSeconds:(()=>{const claims=JSON.parse(Buffer.from(decodeURIComponent(session.value).split('.')[1],'base64url').toString());const lifetime=claims.exp-claims.iat;if(!Number.isFinite(lifetime)||lifetime<=0)throw new Error('invalid native token lifetime');return lifetime;})()}));
} catch(error){console.error('PRODUCT_BROWSER_STAGE='+stage+' error='+error.name+' assertion='+(['native callback missing','unexpected native result','native identity differs from exact issuer subject','native PKCE/state absent','native auth cookie flags failed'].includes(error.message)?error.message:'browser operation'));process.exitCode=1;}finally{await browser.close();}
