// Native SPIRE agent-attested JWT-SVIDs cross real HTTPS OAuth and DPoP API paths.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, verify, sign, randomUUID, createPublicKey, createHash } from 'node:crypto';
import https from 'node:https';

const required=name=>{assert(process.env[name],`Missing ${name}`);return process.env[name];};
const database=required('ACCEPTANCE_DATABASE_URL');
assert.equal(new URL(database).hostname,'127.0.0.1');
assert.match(new URL(database).pathname,/^\/ast_dd1y_spire_[a-f0-9]+$/);
const issuer=required('ACCEPTANCE_ISSUER');
const server=required('SPIRE_SERVER'),agent=required('SPIRE_AGENT');
assert.match(server,/^ast-dd1y-spire-[a-f0-9]+-server$/);
assert.match(agent,/^ast-dd1y-spire-[a-f0-9]+-agent$/);
const socket='/run/spire/server/private/api.sock';
const directory=mkdtempSync(join(tmpdir(),'spire-controlled-'));
const resource='https://localhost:9450/data/',client='spire-client';
const audience='urn:asterius:workload:workload:spire-fixture';
function command(args,input){const r=spawnSync(args[0],args.slice(1),{input,encoding:'utf8'});assert.equal(r.status,0,'Owned command failed; raw credentials withheld');return r.stdout;}
const sql=statement=>command(['psql',database,'-X','-At','-v','ON_ERROR_STOP=1'],statement);
const literal=value=>`'${String(value).replaceAll("'","''")}'`;
const cli=(...args)=>command(['docker','exec',server,'/opt/spire/bin/spire-server',...args,'-socketPath',socket]);
const bundle=()=>JSON.parse(cli('bundle','show','-format','spiffe'));
function token(aud=audience,id='spiffe://asterius-dd1y.test/inventory'){
  const document=JSON.parse(command(['docker','exec','--user','1000',agent,'/opt/spire/bin/spire-agent','api','fetch','jwt','-socketPath','/run/spire/agent/public/api.sock','-audience',aud,'-spiffeID',id,'-output','json']));
  const response=Array.isArray(document)?document.find(item=>item.svids):document;
  const svid=response?.svids?.[0]?.svid || response?.svids?.[0]?.token;
  assert.equal(typeof svid,'string','Expected native SPIRE SVID');return svid;
}
const decode=token=>JSON.parse(Buffer.from(token.split('.')[1],'base64url'));
const {privateKey:clientKey,publicKey:clientPublic}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const clientFile=join(directory,'client.pem');writeFileSync(clientFile,clientKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});
const clientJwk={...clientPublic.export({format:'jwk'}),kid:'client',alg:'ES256',use:'sig'};
const initialBundle=bundle();
const config={issuer:'https://spire-dd1y.example.test',audience,subject:'spiffe://asterius-dd1y.test/inventory',provider:'spiffe',principal:'workload:spire-inventory',clients:[client],scopes:['ledger.read'],resources:[resource],actions:['read'],required_claims:{},algorithms:['ES256'],keys:{kind:'spiffe_bundle',trust_domain:'asterius-dd1y.test',bundle:JSON.stringify(initialBundle)},enabled:true};
const schema=JSON.parse(readFileSync(new URL('../../examples/kubernetes/workload-exchange/actions-schema.json',import.meta.url)));
sql(`insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,scopes,resources,jwks,authorization_details_types) values('workload',${literal(client)},'SPIRE workload','private_key_jwt',array['urn:ietf:params:oauth:grant-type:token-exchange'],array[]::text[],array['ledger.read','ledger.write'],array[${literal(resource)}],${literal(JSON.stringify({keys:[clientJwk]}))}::jsonb,array['urn:asterius:workload-actions']);
insert into resource_servers(tenant_id,identifier,scopes) values('workload',${literal(resource)},array['ledger.read','ledger.write']);
insert into authorization_details_types(tenant_id,type_name,schema) values('workload','urn:asterius:workload-actions',${literal(JSON.stringify(schema))}::jsonb);
insert into workload_trusts(tenant_id,trust_id,config) values('workload','spire-fixture',${literal(JSON.stringify(config))}::jsonb);`);
// Controlled operator state updates test live verification; registry CAS/sequence
// admission is covered separately by the actual PgWorkloadTrusts CI regression.
function changeTrust(value){sql(`update workload_trusts set config=${literal(JSON.stringify(value))}::jsonb,version=nextval('workload_trust_versions') where tenant_id='workload' and trust_id='spire-fixture';`);}
const originalFetch=globalThis.fetch;
const localKeys=(await(await originalFetch(`${issuer}/jwks`,{redirect:'error'})).json()).keys;
function verified(token,keys){
 const [h,p,s]=token.split('.'),header=JSON.parse(Buffer.from(h,'base64url'));
 const jwk=keys.find(k=>k.kid===header.kid);assert(jwk);
 assert(['EdDSA','ES256','RS256'].includes(header.alg));
 const key=createPublicKey({key:jwk,format:'jwk'});
 assert(verify(header.alg==='EdDSA'?null:'sha256',Buffer.from(`${h}.${p}`),header.alg==='ES256'?{key,dsaEncoding:'ieee-p1363'}:key,Buffer.from(s,'base64url')));
 return JSON.parse(Buffer.from(p,'base64url'));
}
const thumbprint=key=>createHash('sha256').update(JSON.stringify({crv:key.crv,kty:key.kty,x:key.x,y:key.y})).digest('base64url');
let activeToken,override={},captured,mints=0,apiCalls=0;
const checks=[];
const endpoint=`${issuer}/token`;
const {privateKey:proofKey,publicKey:proofPublic}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const proofJwk=proofPublic.export({format:'jwk'});
function jwt(header,claims,key){const input=[header,claims].map(value=>Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');return `${input}.${sign('sha256',Buffer.from(input),{key,dsaEncoding:'ieee-p1363'}).toString('base64url')}`;}
function proof(method,url,accessToken,nonce){
 const claims={htm:method,htu:url,iat:Math.floor(Date.now()/1000),jti:randomUUID()};
 if(accessToken)claims.ath=createHash('sha256').update(accessToken).digest('base64url');
 if(nonce)claims.nonce=nonce;
 return jwt({typ:'dpop+jwt',alg:'ES256',jwk:proofJwk},claims,proofKey);
}
async function apiCall(){
 let nonce;
 for(let attempt=0;attempt<2;attempt++){
  const now=Math.floor(Date.now()/1000);
  const auth=jwt({typ:'JWT',alg:'ES256',kid:'client'},{iss:client,sub:client,aud:issuer,iat:now,exp:now+60,jti:randomUUID()},clientKey);
  const form=new URLSearchParams({grant_type:'urn:ietf:params:oauth:grant-type:token-exchange',subject_token_type:'urn:ietf:params:oauth:token-type:jwt',subject_token:activeToken,resource,scope:'ledger.read',client_id:client,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:auth,authorization_details:JSON.stringify([{type:'urn:asterius:workload-actions',actions:['read'],locations:[resource]}])});
  for(const [name,value] of Object.entries(override))form.set(name,value==='subject'?activeToken:value);
  const response=await originalFetch(endpoint,{method:'POST',redirect:'error',headers:{DPoP:proof('POST',endpoint,undefined,nonce)},body:form,signal:AbortSignal.timeout(5000)});
  captured=await response.json();
  if(!response.ok){
   if(captured.error==='use_dpop_nonce'&&attempt===0){nonce=response.headers.get('DPoP-Nonce');continue;}
   throw new Error(`Exchange HTTP ${response.status}: ${captured.error}`);
  }
  mints++;assert.equal(captured.token_type,'DPoP');assert(captured.expires_in<=300&&captured.expires_in>0);assert(!('refresh_token' in captured));
  const call=()=>originalFetch(resource,{redirect:'error',headers:{Authorization:`DPoP ${captured.access_token}`,DPoP:proof('GET',resource,captured.access_token)},signal:AbortSignal.timeout(5000)});
  const api=await call();if(!api.ok)throw new Error(`API HTTP ${api.status}`);return api;
 }
 throw new Error('Nonce exchange failed');
}
const proofIds=new Set();
const api=https.createServer({key:readFileSync(required('ACCEPTANCE_TLS_KEY')),cert:readFileSync(required('ACCEPTANCE_CERTIFICATE'))},(request,response)=>{
 try{
  assert.equal(request.url,'/data/');const accessToken=request.headers.authorization.replace(/^DPoP /,'');
  const access=verified(accessToken,localKeys),raw=request.headers.dpop;
  const header=JSON.parse(Buffer.from(raw.split('.')[0],'base64url')),proof=verified(raw,[{...header.jwk,kid:header.kid}]);
  assert.equal(access.sub,config.principal);assert.equal(access.aud,resource);assert.equal(access.scope,'ledger.read');
  assert(access.exp<=decode(activeToken).exp);assert(access.exp>Math.floor(Date.now()/1000));assert.equal(access.act.client_id,client);
  assert.deepEqual(access.authorization_details,[{type:'urn:asterius:workload-actions',actions:['read'],locations:[resource]}]);
  assert.equal(thumbprint(header.jwk),access.cnf.jkt);assert.equal(proof.htu,resource);assert.equal(proof.htm,'GET');
  assert.equal(proof.ath,createHash('sha256').update(accessToken).digest('base64url'));assert(Math.abs(proof.iat-Math.floor(Date.now()/1000))<=30);
  assert(!proofIds.has(proof.jti));proofIds.add(proof.jti);apiCalls++;response.writeHead(200);response.end('permitted');
 }catch(error){console.error('API verification failure:',error.message.split('\n')[0]);response.writeHead(401);response.end('refused');}
});
await new Promise(resolve=>api.listen(9450,'127.0.0.1',resolve));
try{
 const deny=async(name,error='invalid_grant')=>{await assert.rejects(apiCall);assert.equal(captured.error,error,name);checks.push(name);};
 activeToken=token();const native=decode(activeToken);
 assert.equal(native.iss,config.issuer);assert.equal(native.sub,config.subject);assert(native.exp-native.iat<=300);
 assert.equal((await apiCall()).status,200);checks.push('native_uid1000_attested_svid_independent_client_dpop_api');
 await deny('native_assertion_replay');
 for(const [field,value] of [['issuer','https://other.example'],['subject','spiffe://asterius-dd1y.test/other']]){
  changeTrust({...config,[field]:value});activeToken=token();await deny(`wrong_${field}`);
 }
 changeTrust({...config,subject:'spiffe://other.test/inventory',keys:{...config.keys,trust_domain:'other.test'}});
 activeToken=token();await deny('wrong_trust_domain');changeTrust(config);
 activeToken=token('wrong-audience');await deny('wrong_audience');
 activeToken=token();override={client_assertion:'subject'};await deny('svid_cannot_authenticate_oauth_client','invalid_client');
 override={client_id:'unregistered-client'};await deny('unregistered_client','invalid_client');
 override={scope:'ledger.write'};await deny('scope_widening','invalid_scope');
 override={resource:'https://other.example/'};await deny('resource_widening','invalid_target');
 override={authorization_details:JSON.stringify([{type:'urn:asterius:workload-actions',actions:['write'],locations:[resource]}])};await deny('action_widening','invalid_authorization_details');override={};
 changeTrust({...config,enabled:false});activeToken=token();await deny('disabled_trust');
 changeTrust({...config,keys:{...config.keys,bundle:'{"keys":[]}'}});await deny('empty_bundle_revokes_issuance');
 changeTrust(config);
 const expiredId='spiffe://asterius-dd1y.test/short-lived';
 cli('entry','create','-parentID','spiffe://asterius-dd1y.test/agent','-spiffeID',expiredId,'-selector','unix:uid:1000','-jwtSVIDTTL','1');
 // The agent asynchronously receives registration updates; retry native fetch
 // without altering the JWT or consulting a privileged mint endpoint.
 for(let attempt=0;;attempt++){
  try{activeToken=token(audience,expiredId);break;}catch(error){if(attempt>=30)throw error;await new Promise(resolve=>setTimeout(resolve,500));}
 }
 changeTrust({...config,subject:expiredId});
 await new Promise(resolve=>setTimeout(resolve,1500));
 assert(decode(activeToken).exp<=Math.floor(Date.now()/1000));await deny('native_expired_svid');changeTrust(config);
 command(['docker','restart',agent]);
 let oldUnused;
 for(let attempt=0;;attempt++){try{oldUnused=token();break;}catch(error){if(attempt>=30)throw error;await new Promise(resolve=>setTimeout(resolve,500));}}
 const before=JSON.parse(cli('localauthority','jwt','show','-output','json'));
 const prepared=JSON.parse(cli('localauthority','jwt','prepare','-output','json'));
 const authority=prepared.prepared_authority?.authority_id;
 assert.equal(typeof authority,'string','Native prepared authority ID');
 cli('localauthority','jwt','activate','-authorityID',authority);
 const rotatedBundle=bundle();config.keys.bundle=JSON.stringify(rotatedBundle);changeTrust(config);
 command(['docker','restart',agent]);
 for(let attempt=0;;attempt++){
  try{activeToken=token();if(JSON.parse(Buffer.from(activeToken.split('.')[0],'base64url')).kid===authority)break;}catch(error){if(attempt>=30)throw error;}
  assert(attempt<30,'New native authority must reach the restarted agent');await new Promise(resolve=>setTimeout(resolve,500));
 }
 assert.equal((await apiCall()).status,200);checks.push('native_spire_key_rotation');
 const kid=JSON.parse(Buffer.from(activeToken.split('.')[0],'base64url')).kid;
 const previous=before.active?.authority_id || before.active?.id;
 assert.equal(typeof previous,'string','Native active authority ID');
 cli('localauthority','jwt','taint','-authorityID',previous);
 cli('localauthority','jwt','revoke','-authorityID',previous);
 const retired=bundle();
 assert(!retired.keys.some(key=>key.use==='jwt-svid'&&key.kid===previous));
 checks.push('native_spire_retired_authority_revocation');
 changeTrust({...config,keys:{...config.keys,bundle:JSON.stringify(retired)}});
 activeToken=oldUnused;await deny('unused_old_svid_after_key_removal');
 // A fresh unused SVID from the old signing authority must be refused by current installed keys.
 const oldKid=initialBundle.keys.find(key=>key.use==='jwt-svid')?.kid;
 assert.notEqual(oldKid,kid);checks.push('native_rotated_key_is_distinct');
 changeTrust({...config,keys:{...config.keys,bundle:JSON.stringify(initialBundle)}});
 activeToken=token();await deny('new_svid_with_retired_bundle');
 const provenance=JSON.parse(sql("select coalesce(json_agg(json_build_object('provider',provider,'source_subject',source_subject,'trust_domain',trust_domain)),'[]') from workload_grant_bindings where tenant_id='workload';"));
 assert.equal(provenance.length,mints);assert(provenance.every(row=>row.provider==='spiffe'&&row.source_subject===config.subject&&row.trust_domain===config.keys.trust_domain));checks.push('durable_spiffe_domain_id_provenance');
 const evidence={status:'pass',spire_version:'1.15.3',checks,passed:checks.length,mints,apiCalls,native_claims:['iss','sub','aud','iat','exp'],svid_lifetime_seconds:native.exp-native.iat,transport:'real_verified_https_private_key_jwt_and_dpop',bundle_authorities:'native_spiffe_json_operator_installed',limits:['Direct owned SQL seeds exercise verifier and mint; administrative CAS and upstream sequence admission remain actual repository CI regression coverage.','Static upstream bundle delivery has no automatic freshness bound.','Native agent caches same-audience assertions; fixture restarts the owned agent to obtain fresh unspent native SVIDs for authority rotation.','Full ignored PostgreSQL suite was not run locally.'],local_authority_output_shape:Object.keys(before)};
 writeFileSync(required('ACCEPTANCE_EVIDENCE'),JSON.stringify(evidence,null,2)+'\n');console.log(JSON.stringify(evidence));
}finally{globalThis.fetch=originalFetch;await new Promise(resolve=>api.close(resolve));rmSync(directory,{recursive:true,force:true});}
