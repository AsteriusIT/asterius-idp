// Controlled CI provider fixture, NOT a live GitHub Actions job or GitHub-signed JWT.
// Uses an isolated pre-migrated local Asterius database/binary and the real sample client.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, sign, verify, createPublicKey, createHash, randomUUID } from 'node:crypto';
import https from 'node:https';

const required=name=>{assert(process.env[name],`Missing ${name}`);return process.env[name];};
const database=required('ACCEPTANCE_DATABASE_URL');
assert.equal(new URL(database).hostname,'127.0.0.1');
assert.match(new URL(database).pathname,/^\/ast_dd1y[0-9]+$/,'Isolated fixture database required');
const issuer=required('ACCEPTANCE_ISSUER');assert.equal(new URL(issuer).hostname,'localhost');
const certificate=readFileSync(required('ACCEPTANCE_CERTIFICATE'));
const tlsKey=readFileSync(required('ACCEPTANCE_TLS_KEY'));
const directory=mkdtempSync(join(tmpdir(),'github-controlled-ci-'));
const resource='https://localhost:9450/data/',client='workflow-client';
const audience='urn:asterius:workload:workload:github-fixture';
function sql(statement){const result=spawnSync('psql',[database,'-X','-At','-v','ON_ERROR_STOP=1'],{input:statement,encoding:'utf8'});assert.equal(result.status,0,result.stderr);return result.stdout;}
const literal=value=>`'${String(value).replaceAll("'","''")}'`;
const {privateKey:fixtureKey,publicKey:fixturePublic}=generateKeyPairSync('rsa',{modulusLength:2048});
const {privateKey:clientKey,publicKey:clientPublic}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const clientFile=join(directory,'client.pem');writeFileSync(clientFile,clientKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});
const fixtureJwk={...fixturePublic.export({format:'jwk'}),kid:'controlled-github',alg:'RS256',use:'sig'};
const clientJwk={...clientPublic.export({format:'jwk'}),kid:'client',alg:'ES256',use:'sig'};
const pins={'/repository_id':'123','/repository_owner_id':'456','/environment':'production','/ref':'refs/heads/main','/event_name':'workflow_dispatch','/workflow_ref':'org/repo/.github/workflows/deploy.yml@refs/heads/main','/workflow_sha':'1111111111111111111111111111111111111111'};
const config={issuer:'https://token.actions.githubusercontent.com',audience,subject:'repo:org@456/repo@123:environment:production',provider:'github',principal:'workload:github-deploy',clients:[client],scopes:['ledger.read'],resources:[resource],actions:['read'],required_claims:pins,algorithms:['RS256'],keys:{kind:'inline',jwks:{keys:[fixtureJwk]}},enabled:true};
const schema=JSON.parse(readFileSync(new URL('../../kubernetes/workload-exchange/actions-schema.json',import.meta.url)));
const initialGrants=Number(sql("select count(*) from workload_grant_bindings where tenant_id='workload' and provider='github';").trim());
sql(`insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,scopes,resources,jwks,authorization_details_types) values('workload',${literal(client)},'Controlled CI','private_key_jwt',array['urn:ietf:params:oauth:grant-type:token-exchange'],array[]::text[],array['ledger.read','ledger.write'],array[${literal(resource)}],${literal(JSON.stringify({keys:[clientJwk]}))}::jsonb,array['urn:asterius:workload-actions']) on conflict(tenant_id,client_id) do update set jwks=excluded.jwks;
insert into resource_servers(tenant_id,identifier,scopes) values('workload',${literal(resource)},array['ledger.read','ledger.write']) on conflict do nothing;
insert into authorization_details_types(tenant_id,type_name,schema) values('workload','urn:asterius:workload-actions',${literal(JSON.stringify(schema))}::jsonb) on conflict do nothing;
insert into workload_trusts(tenant_id,trust_id,config) values('workload','github-fixture',${literal(JSON.stringify(config))}::jsonb) on conflict(tenant_id,trust_id) do update set config=excluded.config,version=nextval('workload_trust_versions');`);
function changeTrust(value){sql(`update workload_trusts set config=${literal(JSON.stringify(value))}::jsonb,version=nextval('workload_trust_versions') where tenant_id='workload' and trust_id='github-fixture';`);}
const originalFetch=globalThis.fetch;
const localKeys=(await(await originalFetch(`${issuer}/jwks`,{redirect:'error'})).json()).keys;
function claims(){const now=Math.floor(Date.now()/1000);return {iss:config.issuer,sub:config.subject,aud:audience,iat:now,nbf:now,exp:now+600,jti:randomUUID(),...Object.fromEntries(Object.entries(pins).map(([name,value])=>[name.slice(1),value]))};}
function assertion(value){const input=[{typ:'JWT',alg:'RS256',kid:'controlled-github',x5t:Buffer.alloc(20).toString('base64url')},value].map(v=>Buffer.from(JSON.stringify(v)).toString('base64url')).join('.');return `${input}.${sign('sha256',Buffer.from(input),fixtureKey).toString('base64url')}`;}
function verified(token,keys){const [header,payload,signature]=token.split('.');const metadata=JSON.parse(Buffer.from(header,'base64url'));const key=keys.find(key=>key.kid===metadata.kid);assert(key);const publicKey=createPublicKey({key,format:'jwk'});assert(['EdDSA','ES256','RS256'].includes(metadata.alg));assert(verify(metadata.alg==='EdDSA'?null:'sha256',Buffer.from(`${header}.${payload}`),metadata.alg==='ES256'?{key:publicKey,dsaEncoding:'ieee-p1363'}:publicKey,Buffer.from(signature,'base64url')));return JSON.parse(Buffer.from(payload,'base64url'));}
const thumbprint=key=>createHash('sha256').update(JSON.stringify({crv:key.crv,kty:key.kty,x:key.x,y:key.y})).digest('base64url');
let activeClaims,activeOverride={},captured,subject,mints=0,apiCalls=0;
Object.assign(process.env,{ASTERIUS_ISSUER:issuer,ASTERIUS_RESOURCE:resource,ASTERIUS_API_URL:resource,ASTERIUS_CLIENT_ID:client,ASTERIUS_CLIENT_KID:'client',ASTERIUS_CLIENT_KEY_FILE:clientFile,ASTERIUS_WORKLOAD_AUDIENCE:audience,ASTERIUS_SCOPE:'ledger.read',ASTERIUS_ACTIONS:'read',ACTIONS_ID_TOKEN_REQUEST_URL:'https://run-actions.githubusercontent.com/controlled-fixture',ACTIONS_ID_TOKEN_REQUEST_TOKEN:'controlled-fixture-runtime'});
globalThis.fetch=async(url,options)=>{
  if(String(url).startsWith('https://run-actions.githubusercontent.com/')){
    assert.equal(new URL(url).searchParams.get('audience'),audience);
    subject=assertion({...activeClaims||claims(),jti:randomUUID()});
    return new Response(JSON.stringify({value:subject}));
  }
  if(String(url)===`${issuer}/token`){
    for(const [name,value] of Object.entries(activeOverride))options.body.set(name,value==='subject'?subject:value);
    const auth=options.body.get('client_assertion');if(!activeOverride.client_assertion)assert.equal(verified(auth,[clientJwk]).sub,client);
    const response=await originalFetch(url,options);captured=await response.clone().json();
    if(response.ok){mints++;assert.equal(captured.token_type,'DPoP');assert(captured.expires_in<=300&&captured.expires_in>0);assert(!('refresh_token' in captured));}
    return response;
  }
  return originalFetch(url,options);
};
const proofIds=new Set();
const api=https.createServer({key:tlsKey,cert:certificate},(request,response)=>{
  try{
    assert.equal(request.url,'/data/');
    const token=request.headers.authorization.replace(/^DPoP /,'');const access=verified(token,localKeys);
    assert.equal(access.aud,resource);assert.equal(access.sub,'workload:github-deploy');assert.equal(access.scope,'ledger.read');assert(access.exp>Math.floor(Date.now()/1000));assert(access.exp-access.iat<=300);
    assert.deepEqual(access.authorization_details,[{type:'urn:asterius:workload-actions',actions:['read'],locations:[resource]}]);
    const raw=request.headers.dpop,header=JSON.parse(Buffer.from(raw.split('.')[0],'base64url'));const proof=verified(raw,[{...header.jwk,kid:header.kid}]);
    assert.equal(thumbprint(header.jwk),access.cnf.jkt);assert.equal(proof.htu,resource);assert.equal(proof.htm,'GET');assert.equal(proof.ath,createHash('sha256').update(token).digest('base64url'));assert(Math.abs(proof.iat-Math.floor(Date.now()/1000))<=30);assert(!proofIds.has(proof.jti));proofIds.add(proof.jti);
    apiCalls++;response.writeHead(200);response.end('permitted');
  }catch{response.writeHead(401);response.end('refused');}
});
await new Promise(resolve=>api.listen(9450,'127.0.0.1',resolve));
try{
  const {apiCall}=await import('./client.mjs');
  activeClaims=claims();assert.equal((await apiCall()).status,200);
  const first=subject;
  for(const [name,value] of [['repository_id','999'],['repository_owner_id','999'],['repository_id',123],['environment','staging'],['ref','refs/heads/untrusted'],['event_name','pull_request'],['event_name','pull_request_target'],['event_name','dynamic'],['workflow_ref','org/repo/.github/workflows/untrusted.yml@refs/heads/main'],['workflow_sha','2222222222222222222222222222222222222222'],['aud','https://github.com/org'],['sub','repo:org@456/renamed@123:environment:production'],['job_workflow_ref','org/evil/.github/workflows/evil.yml@refs/heads/main']]){
    activeClaims={...claims(),[name]:value};await assert.rejects(apiCall);assert.equal(captured.error,'invalid_grant',name);
  }
  activeClaims={...claims(),iat:Math.floor(Date.now()/1000)-301,exp:Math.floor(Date.now()/1000)+200};await assert.rejects(apiCall);assert.equal(captured.error,'invalid_grant');
  activeClaims={...claims(),exp:Math.floor(Date.now()/1000)-1};await assert.rejects(apiCall);assert.equal(captured.error,'invalid_grant');
  activeClaims=claims();activeOverride={subject_token:first};await assert.rejects(apiCall);assert.equal(captured.error,'invalid_grant','Replay denied');
  activeOverride={client_assertion:'subject'};await assert.rejects(apiCall);assert.equal(captured.error,'invalid_client','External assertion cannot authenticate client');
  activeOverride={scope:'ledger.write'};await assert.rejects(apiCall);assert.equal(captured.error,'invalid_scope');
  activeOverride={resource:'https://other.example/'};await assert.rejects(apiCall);assert.equal(captured.error,'invalid_target');
  activeOverride={authorization_details:JSON.stringify([{type:'urn:asterius:workload-actions',actions:['write'],locations:[resource]}])};await assert.rejects(apiCall);assert.equal(captured.error,'invalid_authorization_details');
  activeOverride={};
  const callee='/job_workflow_ref',sha='/job_workflow_sha';
  config.required_claims={...pins,[callee]:'org/automation/.github/workflows/deploy.yml@1111111111111111111111111111111111111111',[sha]:'1111111111111111111111111111111111111111'};changeTrust(config);
  activeClaims=claims();await assert.rejects(apiCall);assert.equal(captured.error,'invalid_grant','Missing reusable callee denied');
  activeClaims={...claims(),job_workflow_ref:config.required_claims[callee],job_workflow_sha:config.required_claims[sha]};assert.equal((await apiCall()).status,200);
  activeClaims={...activeClaims,jti:randomUUID(),job_workflow_sha:'2222222222222222222222222222222222222222'};await assert.rejects(apiCall);assert.equal(captured.error,'invalid_grant','Wrong reusable callee denied');
  changeTrust({...config,enabled:false});activeClaims={...claims(),job_workflow_ref:config.required_claims[callee],job_workflow_sha:config.required_claims[sha]};await assert.rejects(apiCall);assert.equal(captured.error,'invalid_grant','Disabled trust denied');
  assert.equal(mints,2);assert.equal(apiCalls,2);assert.equal(Number(sql("select count(*) from workload_grant_bindings where tenant_id='workload' and provider='github';").trim()),initialGrants+2);
  const evidence={kind:'controlled-ci-fixture-not-live-github',signer:'local-RS256',apiCalls,mints,ttlCeiling:300,immutableIDs:'enforced',forkIDs:'denied',pullRequestEvents:'denied',refEnvironmentWorkflowAudience:'denied',rename:'fail-closed',reusableCallee:'exact-pins',replay:'denied',expiredStale:'denied',clientBootstrap:'denied',scopeResourceActions:'denied',disable:'denied',provenance:2};
  if(process.env.ACCEPTANCE_EVIDENCE)writeFileSync(process.env.ACCEPTANCE_EVIDENCE,JSON.stringify(evidence,null,2)+'\n');console.log(JSON.stringify(evidence));
}finally{globalThis.fetch=originalFetch;await new Promise(resolve=>api.close(resolve));rmSync(directory,{recursive:true,force:true});}
