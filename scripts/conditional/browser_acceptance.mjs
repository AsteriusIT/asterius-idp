import assert from 'node:assert/strict';
import {createServer} from 'node:https';
import {readFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {createHash,randomBytes} from 'node:crypto';
import {chromium} from '../../e2e/node_modules/playwright-core/index.mjs';
import {decodeProtectedHeader,importJWK,jwtVerify} from '../../e2e/node_modules/jose/dist/webapi/index.js';
const input=JSON.parse(await readFile(process.argv[2],'utf8'));
const browser=await chromium.launch({headless:true,args:['--no-sandbox','--host-resolver-rules=MAP localhost 127.0.0.1']});
let callback;
const callbackServer=createServer({key:await readFile(input.tls_key),cert:await readFile(input.tls_certificate)},(request,response)=>{callback=new URL(request.url,'https://localhost:9457');response.writeHead(200,{'Content-Type':'text/html'});response.end('<!doctype html><title>Controlled callback</title><p>Callback received</p>');});
await new Promise((resolve,reject)=>{callbackServer.once('error',reject);callbackServer.listen(9457,'127.0.0.1',resolve);});
const checks=[];let stage='password login';
function sql(body) {
  return execFileSync('docker',['exec','-i',input.db_container,'psql','-U','asterius','-d',input.database,'-X','-At','-v','ON_ERROR_STOP=1'],{input:body,encoding:'utf8',stdio:['pipe','pipe','pipe']});
}
const quote=value=>"'"+value.replaceAll("'","''")+"'";
function publish(condition,mode='active',remedy=null) {
  const policy={version:1,rules:[],conditional_scopes:[{id:'browser-bound',mode,clients:[input.client_id],actions:['authorize','authorization_code'],assurance_remedy:remedy,rules:[{id:'fresh-human',effect:'permit',subject_type:'user',when:condition}]}]};
  sql(`insert into tenant_policies(tenant_id,document,updated_at) values('e2e',${quote(JSON.stringify(policy))}::jsonb,now()) on conflict(tenant_id) do update set document=excluded.document,updated_at=excluded.updated_at;`);
}
try {
 const context=await browser.newContext({ignoreHTTPSErrors:true});
 const page=await context.newPage();page.setDefaultTimeout(15000);
 const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
 const {authenticatorId}=await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 function flow(extra={}) {
   callback=undefined;
   const verifier=randomBytes(32).toString('base64url');
   const params=new URLSearchParams({response_type:'code',client_id:input.client_id,redirect_uri:'https://localhost:9457/callback',scope:'openid email',state:randomBytes(24).toString('base64url'),nonce:randomBytes(24).toString('base64url'),code_challenge_method:'S256',code_challenge:createHash('sha256').update(verifier).digest('base64url'),...extra});
   return {url:input.issuer+'/authorize?'+params,verifier,state:params.get('state')};
 }
 async function complete() {
   const allow=page.getByRole('button',{name:'Allow',exact:true});
   await Promise.race([allow.waitFor({state:'visible'}),page.waitForURL(url=>url.port==='9457')]);
   if(await allow.isVisible()) await allow.click();
   await page.waitForURL(url=>url.port==='9457');
 }
 const initial=flow();const initialResponse=await page.goto(initial.url);
 stage='initial password form status='+initialResponse.status();
 await page.locator('input[name="username"]').fill('sweep@example.test');
 await page.locator('input[name="password"]').fill('correct horse battery staple');
 stage='initial password submit';await page.getByRole('button',{name:'Sign in',exact:true}).click();stage='initial consent/callback';await complete();stage='initial callback code';
 assert(callback.searchParams.has('code'));assert.equal(callback.searchParams.get('state'),initial.state);
 checks.push('real_password_authorization_baseline');
 stage='resident passkey enrollment';await page.goto(input.issuer+'/passkeys');
 await page.getByRole('button',{name:'Create a passkey',exact:true}).click();
 await page.waitForFunction(()=>location.pathname.endsWith('/account') || document.querySelector('#passkey-status')?.textContent?.includes('created'),{},{timeout:15000}).catch(()=>null);
 const {credentials}=await cdp.send('WebAuthn.getCredentials',{authenticatorId});assert.equal(credentials.length,1);assert.equal(credentials[0].rpId,'localhost');
 checks.push('real_resident_user_verified_passkey_enrollment');
 stage='bound conditional publication';publish({all:[{acr_at_least:'phr'},{authentication_age_at_most:300}]},'active','phr');
 stage='silent weak-session refusal';const silent=flow({prompt:'none'});await page.goto(silent.url);await page.waitForURL(url=>url.port==='9457');
 assert(callback.searchParams.has('error'));assert(!callback.searchParams.has('code'));assert.equal(callback.searchParams.get('state'),silent.state);
 checks.push('prompt_none_cannot_bypass_conditional_stepup');
 stage='verified conditional stepup';const strong=flow();
 await page.goto(strong.url);stage='conditional assertion request';
 stage='conditional consent/callback';await complete();
 assert(callback.searchParams.has('code'));assert.equal(callback.searchParams.get('state'),strong.state);
 const code=callback.searchParams.get('code');
 stage='conditional authorization-code issuance';
 const result=await context.request.post(input.issuer+'/token',{headers:{Authorization:'Basic '+Buffer.from(input.client_id+':'+input.secret).toString('base64'),'Content-Type':'application/x-www-form-urlencoded'},data:new URLSearchParams({grant_type:'authorization_code',code,redirect_uri:'https://localhost:9457/callback',code_verifier:strong.verifier}).toString()});
 assert.equal(result.status(),200);const issued=await result.json();
 const keys=await (await context.request.get(input.issuer+'/jwks')).json();const header=decodeProtectedHeader(issued.id_token);
 const key=await importJWK(keys.keys.find(key=>key.kid===header.kid),header.alg);
 const {payload}=await jwtVerify(issued.id_token,key,{issuer:input.issuer,audience:input.client_id});
 assert(['phr','urn:asterius:acr:passkey','urn:asterius:acr:passkey-uv'].includes(payload.acr));assert(payload.amr.includes('pop'));assert(payload.auth_time<=Date.now()/1000);
 checks.push('verified_stepup_and_signed_code_token_assurance');
 stage='device hard denial';publish({all:[{acr_at_least:'phr'},{device_compliance:'compliant'}]},'active','phr');
 const hard=flow();await page.goto(hard.url);await page.waitForURL(url=>url.port==='9457');
 assert(callback.searchParams.has('error'));assert(!callback.searchParams.has('code'));assert.equal(callback.searchParams.get('state'),hard.state);
 checks.push('device_hard_denial_has_no_authentication_bypass');
 console.log(JSON.stringify({fixture:'real_chromium_webauthn',status:'pass',checks}));
} catch(error) {console.error('CONDITIONAL_BROWSER_STAGE='+stage+' error='+error.constructor.name);process.exitCode=1;} finally {await browser.close();await new Promise(resolve=>callbackServer.close(resolve));}
