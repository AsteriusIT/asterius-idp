// Native Grafana OIDC, server session and authorization controls; no credential output.
import { chromium } from '../../e2e/node_modules/playwright-core/index.mjs';
import { readFile,writeFile } from 'node:fs/promises';
const file=process.argv[2];const input=JSON.parse(await readFile(file,'utf8'));
const browser=await chromium.launch({headless:true,args:['--host-resolver-rules=MAP host.docker.internal '+input.bridge]});
const cases=[];let stage='start';
function check(label,status,expected){if(!expected.includes(status)){stage+=' check='+label+' status='+status;throw new Error('unexpected native result');}cases.push({case:label,status});}
async function login(context,email){
  const page=await context.newPage();page.setDefaultTimeout(15000);
  const authorization=page.waitForRequest(r=>r.url().startsWith(input.issuer+'/authorize?'));
  stage='native authorize redirect';await page.goto(input.application+'/login/generic_oauth');
  stage='native authorization request';const query=new URL((await authorization).url()).searchParams;
  if(query.get('code_challenge_method')!=='S256'||!query.get('code_challenge')||!query.get('state'))throw new Error('native PKCE/state absent');
  // Record nonce support accurately; do not fabricate a native feature.
  input.nativeNonce=Boolean(query.get('nonce'));
  stage='source credentials form';await page.locator('input[name="username"]').fill(email);
  await page.locator('input[name="password"]').fill('correct horse battery staple');
  const callback=page.waitForResponse(r=>{const url=new URL(r.url());return url.origin===input.application&&url.pathname==='/login/generic_oauth'&&(r.request().method()==='POST'||url.searchParams.has('code')||url.searchParams.has('error'));}).catch(()=>null);
  stage='source sign in';await page.getByRole('button',{name:'Sign in',exact:true}).click();
  await Promise.race([page.getByRole('button',{name:'Allow',exact:true}).waitFor().catch(()=>null),page.waitForURL(input.application+'/**').catch(()=>null)]);
  if(await page.getByRole('button',{name:'Allow',exact:true}).isVisible())await page.getByRole('button',{name:'Allow',exact:true}).click();
  stage='native callback response';const response=await callback;if(!response){stage+=' location='+(new URL(page.url()).origin===input.application?'product':'source')+' allow='+await page.getByRole('button',{name:'Allow',exact:true}).isVisible()+' signin='+await page.getByRole('button',{name:'Sign in',exact:true}).isVisible();throw new Error('native callback missing');}
  return {page,status:response.status()};
}
try{
 const context=await browser.newContext({ignoreHTTPSErrors:true});
 stage='anonymous';check('anonymous user API denied',(await context.request.get(input.application+'/api/user')).status(),[401]);
 check('forged identity headers do not authenticate',(await context.request.get(input.application+'/api/user',{headers:{'X-WEBAUTH-USER':'admin','X-Forwarded-User':'admin',Authorization:'Bearer forged'}})).status(),[401]);
 stage='approved login';const approved=await login(context,'sweep@example.test');check('native approved callback',approved.status,[302,303]);
 stage='native identity';const userResponse=await context.request.get(input.application+'/api/user');check('native authenticated user',userResponse.status(),[200]);
 const user=await userResponse.json();if(user.login!==input.approvedSub.toLowerCase()||user.email!=='sweep@example.test'||user.isGrafanaAdmin){stage+=' subjectMatches='+String(user.login===input.approvedSub.toLowerCase())+' emailMatches='+String(user.email==='sweep@example.test')+' admin='+String(user.isGrafanaAdmin);throw new Error('unexpected stable identity or admin authority');}
 stage='native Viewer role';const orgs=await (await context.request.get(input.application+'/api/user/orgs')).json();if(!orgs.length||orgs.some(o=>o.role!=='Viewer'))throw new Error('unexpected native organization role');
 check('viewer reads folders',(await context.request.get(input.application+'/api/folders')).status(),[200]);
 const mutation=await context.request.post(input.application+'/api/folders',{data:{title:'Forbidden disposable mutation',uid:'forbidden'},headers:{Origin:input.application,Referer:input.application+'/'}});if(/csrf|cross.site|origin not allowed/i.test(await mutation.text()))throw new Error('mutation denied before native role check');check('viewer cannot create folder',mutation.status(),[403]);
 const spoof=await context.request.get(input.application+'/api/user',{headers:{'X-WEBAUTH-USER':'admin','X-Forwarded-Groups':'admin'}});check('authenticated forged headers retain viewer',spoof.status(),[200]);if((await spoof.json()).isGrafanaAdmin)throw new Error('header privilege escalation');
 stage='native cookie flags';const saved=await context.cookies(input.application);const session=saved.find(c=>c.name==='grafana_session');if(!session?.secure||!session.httpOnly||session.sameSite!=='Lax')throw new Error('native session cookie flags failed');
 stage='source logout';const logout=await context.newPage();await logout.goto(input.issuer+'/logout');await logout.getByRole('button',{name:'Log out',exact:true}).click();
 check('source logout retains separate native session',(await context.request.get(input.application+'/api/user')).status(),[200]);
 stage='native expiry';await new Promise(resolve=>setTimeout(resolve,31000));check('native thirty second session bound',(await context.request.get(input.application+'/api/user')).status(),[401]);
 stage='reauthentication';check('native reauthentication callback',(await login(context,'sweep@example.test')).status,[302,303]);
 const beforeLogout=await context.cookies(input.application);
 check('native logout',(await context.request.get(input.application+'/logout',{maxRedirects:0})).status(),[302,303]);
 check('native logout denies next user API',(await context.request.get(input.application+'/api/user')).status(),[401]);
 const replay=await browser.newContext({ignoreHTTPSErrors:true});await replay.addCookies(beforeLogout);check('logged out server session cannot be replayed',(await replay.request.get(input.application+'/api/user')).status(),[401]);await replay.close();
 stage='unassigned';const denied=await browser.newContext({ignoreHTTPSErrors:true});await login(denied,'denied@example.test');check('unassigned subject has no native session',(await denied.request.get(input.application+'/api/user')).status(),[401]);await denied.close();
 await writeFile(file,JSON.stringify({cases,nativeNonce:input.nativeNonce,cookie:{secure:true,httpOnly:true,sameSite:'Lax'},role:'Viewer bound to exact issuer subject; no admin/group mapping',sessionLimitSeconds:30,displayLogin:'native lower-case normalization; role matches original verified subject'}));
} catch(error){console.error('PRODUCT_BROWSER_STAGE='+stage+' error='+error.name+' assertion='+(['native callback missing','unexpected native result','unexpected stable identity or admin authority','unexpected native organization role','native session cookie flags failed','native PKCE/state absent','mutation denied before native role check','header privilege escalation'].includes(error.message)?error.message:'browser operation'));process.exitCode=1;}finally{await browser.close();}
