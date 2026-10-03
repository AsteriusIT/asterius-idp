// Real Chromium password/PAR/PKCE flow; software device key and owned DB only.
import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {createHash,randomBytes,randomUUID} from 'node:crypto';
import https from 'node:https';
import {pathToFileURL} from 'node:url';
const input=JSON.parse(await readFile(process.argv[2],'utf8'));
const moduleUrl=name=>pathToFileURL(input.node_modules+'/'+name).href;
const {chromium}=await import(moduleUrl('playwright-core/index.mjs'));
const {SignJWT,importPKCS8,generateKeyPair,exportJWK,calculateJwkThumbprint,decodeProtectedHeader,importJWK,jwtVerify}=await import(moduleUrl('jose/dist/webapi/index.js'));
const privateKey=await importPKCS8(await readFile(input.client_key,'utf8'),'ES256');
const dpop=await generateKeyPair('ES256');
const jwk=await exportJWK(dpop.publicKey);
const jkt=await calculateJwkThumbprint(jwk,'sha256');
const random=()=>randomBytes(24).toString('base64url');
let nonce='',callback,stage='bootstrap';
const checks=[];
const ca=await readFile(input.ca);
async function request(method,url,body,headers={}){
 return new Promise((resolve,reject)=>{
  const u=new URL(url);const req=https.request({hostname:'127.0.0.1',servername:'localhost',port:u.port,path:u.pathname+u.search,
   method,ca,rejectUnauthorized:true,headers:{Host:u.host,...headers}},response=>{
   let data='';response.setEncoding('utf8');response.on('data',chunk=>{data+=chunk;if(data.length>65536)response.destroy();});
   response.on('end',()=>resolve({status:response.statusCode,headers:response.headers,body:data?JSON.parse(data):{}}));
  });req.on('error',reject);req.setTimeout(15000,()=>req.destroy());req.end(body);
 });
}
async function authenticated(path,form){
 const url=input.issuer+path;
 for(let attempt=0;attempt<2;attempt++){
  const now=Math.floor(Date.now()/1000);
  const assertion=await new SignJWT({iss:'device-app',sub:'device-app',aud:input.issuer,iat:now,exp:now+60,jti:random()})
   .setProtectedHeader({alg:'ES256',typ:'JWT',kid:'managed-device-fixture'}).sign(privateKey);
  const proof=await new SignJWT({jti:random(),htm:'POST',htu:url,iat:now,...(nonce?{nonce}:{})})
   .setProtectedHeader({alg:'ES256',typ:'dpop+jwt',jwk}).sign(dpop.privateKey);
  const result=await request('POST',url,new URLSearchParams({client_id:'device-app',client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:assertion,...form}).toString(),
   {'Content-Type':'application/x-www-form-urlencoded',DPoP:proof});
  if([400,401].includes(result.status)&&result.headers['dpop-nonce']&&attempt===0){nonce=result.headers['dpop-nonce'];continue;}
  return result;
 }
 throw new Error('DEVICE_BROWSER_NONCE');
}
const callbackServer=https.createServer({key:await readFile(input.edge_key),cert:await readFile(input.edge_cert)},(req,res)=>{
 callback=new URL(req.url,'https://localhost:9527');res.writeHead(200,{'Content-Type':'text/html'});res.end('<!doctype html><title>Controlled device callback</title><p>Callback received</p>');
});
await new Promise((resolve,reject)=>{callbackServer.once('error',reject);callbackServer.listen(9527,'127.0.0.1',resolve);});
let browser;
try{
 browser=await chromium.launch({headless:true,args:['--no-sandbox','--host-resolver-rules=MAP localhost 127.0.0.1']});
 const context=await browser.newContext({ignoreHTTPSErrors:true,clientCertificates:[{origin:'https://localhost:9525',certPath:input.device_cert,keyPath:input.device_key}]});
 const page=await context.newPage();page.setDefaultTimeout(15000);
 const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
 const {authenticatorId}=await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 stage='real FAPI PAR';
 const verifier=randomBytes(32).toString('base64url'),state=random(),oidcNonce=random();
 const pushed=await authenticated('/par',{response_type:'code',redirect_uri:'https://localhost:9527/callback',scope:'openid device.read',resource:input.resource,state,nonce:oidcNonce,
  code_challenge_method:'S256',code_challenge:createHash('sha256').update(verifier).digest('base64url'),dpop_jkt:jkt});
 assert.equal(pushed.status,201);
 stage='actual password login with device TLS possession';
 await page.goto(input.issuer+'/authorize?'+new URLSearchParams({client_id:'device-app',request_uri:pushed.body.request_uri}));
 await page.locator('input[name="username"]').fill('controlled-device-owner');
 await page.locator('input[name="password"]').fill('correct horse battery staple');
 await page.getByRole('button',{name:'Sign in',exact:true}).click();
 stage='device-bound consent completion';
 const allow=page.getByRole('button',{name:'Allow',exact:true});
 await Promise.race([allow.waitFor({state:'visible'}),page.waitForURL(u=>u.port==='9527')]);
 if(await allow.isVisible())await allow.click();
 await page.waitForURL(u=>u.port==='9527');
 assert.equal(callback.searchParams.get('state'),state);assert(callback.searchParams.has('code'));
 checks.push('real_browser_device_tls_password_par_pkce_completion');
 stage='original code proof without token-endpoint device TLS';
 // The request helper has no device certificate. A code may use only its
 // private transferred original interaction proof, not current/session state.
 const form={grant_type:'authorization_code',code:callback.searchParams.get('code'),redirect_uri:'https://localhost:9527/callback',code_verifier:verifier};
 const issued=await authenticated('/token',form);assert.equal(issued.status,200);assert.equal(issued.body.token_type,'DPoP');
 const keys=(await request('GET',input.issuer+'/jwks')).body.keys;
 const header=decodeProtectedHeader(issued.body.id_token);
 const key=await importJWK(keys.find(k=>k.kid===header.kid),header.alg);
 const {payload}=await jwtVerify(issued.body.id_token,key,{issuer:input.issuer,audience:'device-app'});
 assert.equal(payload.nonce,oidcNonce);assert(payload.amr.includes('pwd'));
 assert(!Object.keys(payload).some(name=>name.includes('device')||name.includes('leaf')));
 checks.push('exact_original_interaction_proof_transferred_to_code_and_final_signed_identity');
 stage='winning code one spend';assert.equal((await authenticated('/token',form)).status,400);
 checks.push('spent_authorization_code_and_private_proof_cannot_be_replayed');
 stage='local tenant administrator source registration';
 const api=input.issuer+'/admin/api/v1/';
 const sessionResult=await context.request.get(api+'session');
 stage+=':session'+sessionResult.status();assert.equal(sessionResult.status(),200);
 let identity=await sessionResult.json();assert.equal(typeof identity.csrf_token,'string');
 const admin=(method,path,data,csrf=true)=>context.request.fetch(api+path,{method,headers:{Origin:new URL(input.issuer).origin,'Content-Type':'application/json',...(method==='POST'?{'Idempotency-Key':randomUUID()}:{}),...(csrf?{'X-CSRF-Token':identity.csrf_token}:{})},...(data===undefined?{}:{data})});
 const weak=await admin('POST','device-sources',{client_id:'device-relay-secondary'});
 stage+=':'+weak.status();
 const createdSource=await weak.json();
 assert.equal(weak.status(),201);assert.equal(createdSource.enabled,false);
 checks.push('local_tenant_administrator_creates_source_disabled_by_default');
 stage='real admin user verified passkey';
 await page.goto(input.issuer+'/passkeys');await page.getByRole('button',{name:'Create a passkey',exact:true}).click();
 await page.waitForFunction(()=>location.pathname.endsWith('/account')||document.querySelector('#passkey-status')?.textContent?.toLowerCase().includes('created'),{},{timeout:15000}).catch(()=>null);
 const {credentials}=await cdp.send('WebAuthn.getCredentials',{authenticatorId});assert.equal(credentials.length,1);
 callback=undefined;
 const freshVerifier=randomBytes(32).toString('base64url'),freshState=random();
 const freshPar=await authenticated('/par',{response_type:'code',redirect_uri:'https://localhost:9527/callback',scope:'openid device.read',resource:input.resource,state:freshState,nonce:random(),max_age:'0',
  code_challenge_method:'S256',code_challenge:createHash('sha256').update(freshVerifier).digest('base64url'),dpop_jkt:jkt});
 assert.equal(freshPar.status,201);
 await page.goto(input.issuer+'/authorize?'+new URLSearchParams({client_id:'device-app',request_uri:freshPar.body.request_uri}));
 await Promise.race([allow.waitFor({state:'visible'}),page.waitForURL(u=>u.port==='9527')]);if(await allow.isVisible())await allow.click();
 await page.waitForURL(u=>u.port==='9527');assert(callback.searchParams.has('code'));assert.equal(callback.searchParams.get('state'),freshState);
 const strong=await authenticated('/token',{grant_type:'authorization_code',code:callback.searchParams.get('code'),redirect_uri:'https://localhost:9527/callback',code_verifier:freshVerifier});
 assert.equal(strong.status,200);
 const strongHeader=decodeProtectedHeader(strong.body.id_token);
 const strongKey=await importJWK(keys.find(k=>k.kid===strongHeader.kid),strongHeader.alg);
 const {payload:strongClaims}=await jwtVerify(strong.body.id_token,strongKey,{issuer:input.issuer,audience:'device-app'});
 assert(strongClaims.amr.includes('pop'));assert(strongClaims.amr.includes('user'));assert(Date.now()/1000-strongClaims.auth_time<120);
 identity=await (await context.request.get(api+'session')).json();
 stage='fresh human source creation and incarnation updates';
 assert.equal((await admin('POST','device-sources',{client_id:'device-relay-secondary'},false)).status(),403);
 const source=createdSource;
 const enabled=await admin('PUT','device-sources/'+source.id,{client_id:'device-relay-secondary',enabled:true,expected_revision:source.revision});assert.equal(enabled.status(),200);
 const active=await enabled.json();assert(active.enabled);assert.notEqual(active.generation,source.generation);assert.notEqual(active.revision,source.revision);
 assert.equal((await admin('PUT','device-sources/'+source.id,{client_id:'device-relay-secondary',enabled:false,expected_revision:source.revision})).status(),409);
 const disabled=await admin('PUT','device-sources/'+source.id,{client_id:'device-relay-secondary',enabled:false,expected_revision:active.revision});assert.equal(disabled.status(),200);assert.equal((await disabled.json()).enabled,false);
 assert.equal((await admin('GET','device-sources')).status(),200);assert.equal((await admin('GET','devices?limit=1')).status(),200);
 checks.push('real_fresh_uv_webauthn_human_source_default_disabled_enable_cas_disable_and_inspection');
 await writeFile(input.cookie_file,JSON.stringify(await context.cookies()),{mode:0o600});
 console.log(JSON.stringify({checks,passed:checks.length,real_browser_password:true,real_device_tls:true,original_interaction_code_transfer:true,software_pki:true}));
 await context.close();
}catch{console.error('DEVICE_BROWSER_STAGE='+stage);process.exitCode=1;}
finally{if(browser)await browser.close();callbackServer.closeAllConnections();await new Promise(resolve=>callbackServer.close(resolve));}
