// Genuine OIDC and cookie/header controls; credential values never leave the fixture.
import { chromium } from '../../e2e/node_modules/playwright-core/index.mjs';
import { readFile, writeFile } from 'node:fs/promises';
const file=process.argv[2];
const input=JSON.parse(await readFile(file,'utf8'));
const browser=await chromium.launch({headless:true,args:['--host-resolver-rules=MAP host.docker.internal '+input.bridge]});
let stage='bootstrap';
const cases=[];
function check(label,status,expected) {
  if (!expected.includes(status)) { console.error('GATEWAY_CHECK='+label+' status='+status); throw new Error('unexpected fixed check status'); }
  cases.push({case:label,status});
}
try {
  const context=await browser.newContext({ignoreHTTPSErrors:true,javaScriptEnabled:true});
  let page=await context.newPage();page.setDefaultTimeout(15000);
  const api=input.gateway+'/api/protected';
  const forged={'X-Forwarded-User':'forged-admin','X-Forwarded-Email':'forged@example.invalid',
    'X-Forwarded-Groups':'admin','X-Auth-Request-User':'forged-admin','Authorization':'Bearer forged',
    'X-Forwarded-Host':'attacker.example.invalid','X-Forwarded-Proto':'http','X-Forwarded-Uri':'/oauth2/ping',
    'X-Real-IP':'127.0.0.1','X-Forwarded-For':'127.0.0.1'};
  check('anonymous API denied',(await context.request.get(api)).status(),[401]);
  check('anonymous forged headers denied',(await context.request.get(api,{headers:forged})).status(),[401]);
  const challenge=await context.request.get(input.gateway+'/oauth2/start?rd=/',{maxRedirects:0});
  const nativeState=new URL(challenge.headers().location).searchParams.get('state');
  const noCookie=await browser.newContext({ignoreHTTPSErrors:true});
  check('callback without CSRF cookie denied',(await noCookie.request.get(input.gateway+'/oauth2/callback?'+new URLSearchParams({state:nativeState,code:'forged'}))).status(),[403]);
  await noCookie.close();
  async function login(target,username) {
    stage='native login '+username.split('@')[0];
    const authorized=target.waitForRequest(r=>new URL(r.url()).pathname.endsWith('/authorize')).catch(()=>null);
    const callback=target.waitForResponse(r=>new URL(r.url()).pathname==='/oauth2/callback').catch(()=>null);
    await target.goto(input.gateway+'/oauth2/start?rd=/');
    const authorization=new URL((await authorized).url());
    if (authorization.searchParams.get('code_challenge_method')!=='S256' || !authorization.searchParams.has('nonce')) throw new Error('native PKCE/nonce absent');
    stage='username '+username.split('@')[0];
    await target.locator('input[name="username"]').fill(username);
    await target.locator('input[name="password"]').fill('correct horse battery staple');
    await target.evaluate(()=>{window.__fixtureSubmitSeen=false;document.addEventListener('submit',()=>{window.__fixtureSubmitSeen=true;},true);});
    let postedStatus='none',blockedForm=false,failedRequest='none';
    target.on('console',message=>{if(message.type()==='error' && message.text().includes('form-action')) blockedForm=true;});
    target.on('requestfailed',request=>{if(request.method()==='POST') failedRequest=request.failure()?.errorText || 'failed';});
    const track=response=>{if(response.request().method()==='POST') postedStatus=response.status();};
    target.on('response',track);
    stage='sign in '+username.split('@')[0];
    await target.getByRole('button',{name:'Sign in',exact:true}).click();
    stage='consent '+username.split('@')[0];
    const allow=target.getByRole('button',{name:'Allow',exact:true});
    await Promise.race([allow.waitFor({state:'visible',timeout:5000}).catch(()=>null),target.waitForURL(url=>url.hostname==='127.0.0.1',{timeout:5000}).catch(()=>null)]);
    if (await allow.isVisible()) await allow.click();
    stage='callback navigation '+username.split('@')[0];
    try {await target.waitForURL(url=>url.hostname==='127.0.0.1',{timeout:5000});} catch {
      console.error('GATEWAY_CHECK=callback absent title='+await target.title()+' loginPOST='+postedStatus+' blockedForm='+blockedForm+' failedRequest='+failedRequest+' form='+JSON.stringify(await target.locator('form.password-form').evaluate(form=>({method:form.method,origin:new URL(form.action).origin,valid:form.checkValidity(),submitSeen:window.__fixtureSubmitSeen}))));
      throw new Error('callback navigation absent');
    }
    target.off('response',track);
    const completed=await callback;if(!completed) throw new Error('callback absent');
    return completed.status();
  }
  check('native approved OIDC callback',await login(page,'sweep@example.test'),[302,303]);
  stage='authenticated controls';
  const cookie=(await context.cookies()).find(c=>c.name==='__Host-asterius_gateway');
  if (!cookie || !cookie.secure || !cookie.httpOnly || cookie.sameSite!=='Lax' || cookie.path!=='/' || cookie.domain!=='127.0.0.1') throw new Error('cookie contract failed');
  let result=await context.request.get(api);check('native login allows backend',result.status(),[200]);
  const original=await result.json();
  if (original.email!=='sweep@example.test' || !original.user || original.authorization_present || original.access_token_present) throw new Error('identity/credential forwarding failed');
  result=await context.request.get(api,{headers:forged});check('authenticated forged headers sanitized',result.status(),[200]);
  const received=await result.json();
  if (received.user!==original.user || received.email!==original.email || received.groups?.includes('admin') || received.auth_request_user || received.authorization_present || received.access_token_present) throw new Error('forwarded-header authority bypass');
  // Real browser cross-site POST: Lax session cookie is withheld.
  stage='cross-site POST';
  const crossContext=await browser.newContext({ignoreHTTPSErrors:true});
  await crossContext.addCookies([cookie]);
  const crossPage=await crossContext.newPage();
  await crossPage.goto(input.issuer+'/nonexistent-fixture-origin');
  const denied=crossPage.waitForResponse(r=>r.url()===api && r.request().method()==='POST');
  await crossPage.evaluate(url=>{ const form=document.createElement('form');form.method='POST';form.action=url;document.body.append(form);form.submit(); },api);
  check('cross-site POST without gateway cookie denied',(await denied).status(),[401]);
  await crossContext.close();
  stage='source logout';
  stage='source logout navigation';
  const logoutPage=await context.newPage();logoutPage.setDefaultTimeout(15000);
  await logoutPage.goto(input.issuer+'/logout',{waitUntil:'domcontentloaded'});
  stage='source logout button';
  await logoutPage.getByRole('button',{name:'Log out',exact:true}).click();
  stage='source logout cookie check';
  if ((await context.cookies()).some(c=>c.name==='__Host-asterius_session' && c.domain==='host.docker.internal')) throw new Error('source logout failed');
  check('source logout does not instantly revoke gateway cookie',(await context.request.get(api)).status(),[200]);
  stage='session tamper';
  const tampered=await browser.newContext({ignoreHTTPSErrors:true});
  await tampered.addCookies([{...cookie,value:'forged-session'}]);
  check('tampered session denied',(await tampered.request.get(api)).status(),[401]);await tampered.close();
  stage='cookie expiry';
  await new Promise(resolve=>setTimeout(resolve,Math.max(0,Math.ceil(cookie.expires-Date.now()/1000)+1)*1000));
  check('gateway cookie TTL bounds retained access',(await context.request.get(api)).status(),[401]);
  // Login again, then gateway logout clears only its session cookie.
  page=await context.newPage();page.setDefaultTimeout(15000);
  check('native reauthentication after source logout and expiry',await login(page,'sweep@example.test'),[302,303]);
  stage='gateway logout';
  check('gateway logout',(await context.request.get(input.gateway+'/oauth2/sign_out?rd=/oauth2/sign_in',{maxRedirects:0})).status(),[200,302]);
  check('gateway logout denies next API request',(await context.request.get(api)).status(),[401]);
  const other=await browser.newContext({ignoreHTTPSErrors:true});const otherPage=await other.newPage();otherPage.setDefaultTimeout(15000);
  check('native unassigned identity callback denied',await login(otherPage,'denied@example.test'),[403]);
  check('authenticated unassigned user denied',(await otherPage.request.get(api)).status(),[401,403]);
  await other.close();
  await writeFile(file,JSON.stringify({cases,cookie:{secure:true,httpOnly:true,sameSite:'Lax',hostPrefix:true,ttlSeconds:30},
    identityForwarding:'verified user/email only; forged groups removed; no OAuth access/ID tokens forwarded',
    backendGatewayCookiePresent:original.gateway_cookie_present}),{mode:0o600});
} catch (error) {
  console.error('GATEWAY_BROWSER_STAGE='+stage);process.exitCode=1;
} finally {await browser.close();}
