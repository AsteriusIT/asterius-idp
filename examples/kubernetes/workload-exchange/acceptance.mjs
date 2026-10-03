// Controlled local acceptance: an explicitly supplied disposable kind cluster,
// isolated pre-migrated DB, running Asterius, and loopback TLS API. No credentials logged.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash, createPublicKey, generateKeyPairSync, randomUUID, sign, verify } from 'node:crypto';
import https from 'node:https';

const required = name => { assert(process.env[name], `Missing ${name}`); return process.env[name]; };
const kubeconfig=required('ACCEPTANCE_KUBECONFIG');
const context=required('ACCEPTANCE_CONTEXT');
assert.match(context,/^kind-asterius-dd1y[0-9]+$/,'Disposable acceptance cluster required');
const database=required('ACCEPTANCE_DATABASE_URL');
assert.match(new URL(database).pathname,/^\/ast_dd1y[0-9]+$/,'Isolated acceptance DB required');
const namespace=required('ACCEPTANCE_NAMESPACE');
assert.match(namespace,/^workload-exchange-/);
const issuer=required('ACCEPTANCE_ISSUER');
assert.equal(new URL(issuer).hostname,'localhost');
const certificate=readFileSync(required('ACCEPTANCE_CERTIFICATE'));
const tlsKey=readFileSync(required('ACCEPTANCE_TLS_KEY'));
const resource='https://localhost:9450/data/';
const tenant='workload', client='pod-client', trust='inventory';
const audience=`urn:asterius:workload:${tenant}:${trust}`;
function command(program,args,input) {
  const result=spawnSync(program,args,{input,encoding:'utf8'});
  assert.equal(result.status,0,`${program} failed: ${result.stderr}`);
  return result.stdout;
}
function kube(...args) { return command('kubectl',['--kubeconfig',kubeconfig,'--context',context,...args]); }
function sql(statement) { return command('psql',[database,'-X','-At','-v','ON_ERROR_STOP=1'],statement); }
const literal=value=>`'${String(value).replaceAll("'","''")}'`;
const object=(kind,name)=>JSON.parse(kube('-n',namespace,'get',kind,name,'-o','json'));
const pod=object('pod','inventory'), serviceAccount=object('serviceaccount','inventory');
const discovery=JSON.parse(kube('get','--raw','/.well-known/openid-configuration'));
const clusterKeys=JSON.parse(kube('get','--raw','/openid/v1/jwks'));
const {privateKey:clientKey,publicKey:clientPublic}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const {privateKey:dpopKey,publicKey:dpopPublic}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const publicClient={...clientPublic.export({format:'jwk'}),kid:'client',alg:'ES256',use:'sig'};
const dpopJwk=dpopPublic.export({format:'jwk'});
const thumbprint=createHash('sha256').update(JSON.stringify({crv:dpopJwk.crv,kty:dpopJwk.kty,x:dpopJwk.x,y:dpopJwk.y})).digest('base64url');
function jwt(header,claims,key) {
  const input=[header,claims].map(v=>Buffer.from(JSON.stringify(v)).toString('base64url')).join('.');
  return `${input}.${sign('sha256',Buffer.from(input),{key,dsaEncoding:'ieee-p1363'}).toString('base64url')}`;
}
function decode(token) { return JSON.parse(Buffer.from(token.split('.')[1],'base64url')); }
function verifyJWT(token,keys) {
  const [header,payload,signature]=token.split('.');
  const metadata=JSON.parse(Buffer.from(header,'base64url'));
  const key=keys.find(k=>k.kid===metadata.kid);
  assert(key,'Pinned public key required');
  const publicKey=createPublicKey({key,format:'jwk'});
  assert(['EdDSA','ES256','RS256','PS256'].includes(metadata.alg));
  const options=metadata.alg==='ES256'?{key:publicKey,dsaEncoding:'ieee-p1363'}:metadata.alg==='PS256'?{key:publicKey,padding:6,saltLength:32}:publicKey;
  assert(verify(metadata.alg==='EdDSA'?null:'sha256',Buffer.from(`${header}.${payload}`),options,Buffer.from(signature,'base64url')),'Signature required');
  return decode(token);
}
function proof(method,url,token,nonce) {
  const claims={htm:method,htu:url,iat:Math.floor(Date.now()/1000),jti:randomUUID()};
  if(token) claims.ath=createHash('sha256').update(token).digest('base64url');
  if(nonce) claims.nonce=nonce;
  return jwt({typ:'dpop+jwt',alg:'ES256',jwk:dpopJwk},claims,dpopKey);
}
const config={issuer:discovery.issuer,audience,subject:`system:serviceaccount:${namespace}:inventory`,provider:'kubernetes',principal:'workload:inventory',clients:[client],scopes:['ledger.read'],resources:[resource],actions:['read'],required_claims:{'/kubernetes.io/namespace':namespace,'/kubernetes.io/serviceaccount/name':'inventory','/kubernetes.io/serviceaccount/uid':serviceAccount.metadata.uid},algorithms:['RS256'],keys:{kind:'inline',jwks:clusterKeys},enabled:true};
const schema=JSON.parse(readFileSync(new URL('./actions-schema.json',import.meta.url)));
const initialGrants=Number(sql("select count(*) from workload_grant_bindings where tenant_id='workload';").trim());
sql(`insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,scopes,resources,jwks,authorization_details_types) values ('workload','pod-client','Acceptance pod','private_key_jwt',array['urn:ietf:params:oauth:grant-type:token-exchange'],array[]::text[],array['ledger.read','ledger.write'],array[${literal(resource)}],${literal(JSON.stringify({keys:[publicClient]}))}::jsonb,array['urn:asterius:workload-actions']) on conflict(tenant_id,client_id) do update set jwks=excluded.jwks;
insert into resource_servers(tenant_id,identifier,scopes) values('workload',${literal(resource)},array['ledger.read','ledger.write']) on conflict do nothing;
insert into authorization_details_types(tenant_id,type_name,schema) values('workload','urn:asterius:workload-actions',${literal(JSON.stringify(schema))}::jsonb) on conflict do nothing;
insert into workload_trusts(tenant_id,trust_id,config) values('workload','inventory',${literal(JSON.stringify(config))}::jsonb) on conflict(tenant_id,trust_id) do update set config=excluded.config,version=nextval('workload_trust_versions');`);
const details=JSON.stringify([{type:'urn:asterius:workload-actions',actions:['read'],locations:[resource]}]);
function tokenRequest(targetAudience=audience,account='inventory',sourceNamespace=namespace,sourcePod=pod) {
  const token=kube('-n',sourceNamespace,'create','token',account,'--audience',targetAudience,'--duration','600s','--bound-object-kind','Pod','--bound-object-name',sourcePod.metadata.name,'--bound-object-uid',sourcePod.metadata.uid).trim();
  verifyJWT(token,clusterKeys.keys);
  return token;
}
const endpoint=`${issuer}/token`;
let nonce;
async function exchange(subject,overrides={}) {
  for(let attempt=0;attempt<2;attempt++) {
    const now=Math.floor(Date.now()/1000);
    const auth=jwt({alg:'ES256',kid:'client',typ:'JWT'},{iss:client,sub:client,aud:issuer,iat:now,exp:now+60,jti:randomUUID()},clientKey);
    const form=new URLSearchParams({grant_type:'urn:ietf:params:oauth:grant-type:token-exchange',subject_token_type:'urn:ietf:params:oauth:token-type:jwt',subject_token:subject,resource,scope:'ledger.read',authorization_details:details,client_id:client,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:auth,...overrides});
    const response=await fetch(endpoint,{method:'POST',redirect:'error',body:form,headers:{DPoP:proof('POST',endpoint,undefined,nonce)}});
    const body=await response.json();
    if(body.error==='use_dpop_nonce'&&attempt===0) {nonce=response.headers.get('DPoP-Nonce');assert(nonce);continue;}
    return {status:response.status,body};
  }
  throw new Error('Nonce failed');
}
const localKeys=(await(await fetch(`${issuer}/jwks`,{redirect:'error'})).json()).keys;
const tokens=()=>tokenRequest();
const firstAssertion=tokens();
const accepted=await exchange(firstAssertion);
assert.equal(accepted.status,200,JSON.stringify(accepted.body));
assert.equal(accepted.body.token_type,'DPoP');
assert(accepted.body.expires_in>0&&accepted.body.expires_in<=300);
assert(!('refresh_token' in accepted.body));
const output=verifyJWT(accepted.body.access_token,localKeys);
assert.equal(output.sub,'workload:inventory');
assert.equal(output.aud,resource);
assert.equal(output.scope,'ledger.read');
assert.equal(output.cnf.jkt,thumbprint);
assert.deepEqual(output.authorization_details,JSON.parse(details));
assert(output.exp-output.iat<=300);
const api=https.createServer({key:tlsKey,cert:certificate},(request,response)=>{
  try {
    assert.equal(request.url,'/data/');
    const token=request.headers.authorization?.replace(/^DPoP /,'');
    const claims=verifyJWT(token,localKeys);
    assert.equal(claims.aud,resource);assert.equal(claims.scope,'ledger.read');assert(claims.exp>Math.floor(Date.now()/1000));
    assert.deepEqual(claims.authorization_details,JSON.parse(details));
    const signed=request.headers.dpop;
    const header=JSON.parse(Buffer.from(signed.split('.')[0],'base64url'));
    const proofClaims=verifyJWT(signed,[{...header.jwk,kid:header.kid}]);
    assert.equal(proofClaims.htu,resource);assert.equal(proofClaims.htm,'GET');
    assert.equal(proofClaims.ath,createHash('sha256').update(token).digest('base64url'));
    assert.equal(createHash('sha256').update(JSON.stringify({crv:header.jwk.crv,kty:header.jwk.kty,x:header.jwk.x,y:header.jwk.y})).digest('base64url'),claims.cnf.jkt);
    response.writeHead(200);response.end('permitted');
  } catch {response.writeHead(401);response.end('refused');}
});
await new Promise(resolve=>api.listen(9450,'127.0.0.1',resolve));
const otherNamespace=`${namespace}-other`;
function changeTrust(value) {sql(`update workload_trusts set config=${literal(JSON.stringify(value))}::jsonb,version=nextval('workload_trust_versions') where tenant_id='workload' and trust_id='inventory';`);}
function fixturePod(sourceNamespace,account,name) {
  kube('-n',sourceNamespace,'create','serviceaccount',account);
  kube('-n',sourceNamespace,'run',name,'--image=registry.k8s.io/pause:3.10',`--overrides=${JSON.stringify({spec:{serviceAccountName:account,automountServiceAccountToken:false}})}`);
  return JSON.parse(kube('-n',sourceNamespace,'get','pod',name,'-o','json'));
}
try {
  const response=await fetch(resource,{redirect:'error',headers:{Authorization:`DPoP ${accepted.body.access_token}`,DPoP:proof('GET',resource,accepted.body.access_token)}});
  assert.equal(response.status,200,'Approved pod calls permitted API');
  assert.equal((await exchange(firstAssertion)).body.error,'invalid_grant','Replay denied');
  assert.equal((await exchange(tokenRequest('wrong-audience'))).body.error,'invalid_grant','Audience mismatch denied');
  kube('create','namespace',otherNamespace);
  const otherNamespacePod=fixturePod(otherNamespace,'inventory','inventory');
  assert.equal((await exchange(tokenRequest(audience,'inventory',otherNamespace,otherNamespacePod))).body.error,'invalid_grant','Namespace mismatch denied');
  const otherAccountPod=fixturePod(namespace,'inventory-other','inventory-other');
  assert.equal((await exchange(tokenRequest(audience,'inventory-other',namespace,otherAccountPod))).body.error,'invalid_grant','ServiceAccount mismatch denied');
  changeTrust({...config,issuer:'https://another-cluster.example'});
  assert.equal((await exchange(tokens())).body.error,'invalid_grant','Cluster issuer mismatch denied');
  changeTrust({...config,required_claims:{...config.required_claims,'/kubernetes.io/serviceaccount/uid':'recreated-account'}});
  assert.equal((await exchange(tokens())).body.error,'invalid_grant','ServiceAccount UID mismatch denied');
  changeTrust(config);
  assert.equal((await exchange(tokens(),{scope:'ledger.write'})).body.error,'invalid_scope','Scope widening denied');
  assert.equal((await exchange(tokens(),{resource:'https://other.example/'})).body.error,'invalid_target','Resource widening denied');
  assert.equal((await exchange(tokens(),{authorization_details:JSON.stringify([{type:'urn:asterius:workload-actions',actions:['write'],locations:[resource]}])})).body.error,'invalid_authorization_details','Action widening denied');
  assert.equal((await exchange(tokens(),{client_assertion:firstAssertion})).body.error,'invalid_client','ServiceAccount cannot authenticate client');
  const beforeDeletion=tokens(),unusedBeforeDeletion=tokens();
  assert.notEqual(beforeDeletion,unusedBeforeDeletion,'Fresh TokenRequest rotation');
  kube('-n',namespace,'delete','pod','inventory','--wait=false');
  const offline=await exchange(beforeDeletion);
  assert.equal(offline.status,200,'Offline validation intentionally permits a fresh pre-deletion assertion');
  const offlineClaims=verifyJWT(offline.body.access_token,localKeys);
  assert(offlineClaims.exp-decode(beforeDeletion).iat<=630,'Documented offline bound including skew');
  sql("update workload_trusts set config=jsonb_set(config,'{enabled}','false'),version=nextval('workload_trust_versions') where tenant_id='workload' and trust_id='inventory';");
  assert.equal((await exchange(unusedBeforeDeletion)).body.error,'invalid_grant','Disabled trust denied');
  assert.equal(Number(sql("select count(*) from workload_grant_bindings where tenant_id='workload';").trim()),initialGrants+2);
  const evidence={cluster:context,provider:'kubernetes',api:200,ttl:accepted.body.expires_in,replay:'denied',audience:'denied',namespace:'denied',serviceAccount:'denied',serviceAccountUID:'denied',clusterIssuer:'denied',scope:'denied',resource:'denied',action:'denied',clientBootstrap:'denied',rotation:'fresh',deletion:'offline-bounded',disable:'denied',grants:2};
  if(process.env.ACCEPTANCE_EVIDENCE)writeFileSync(process.env.ACCEPTANCE_EVIDENCE,JSON.stringify(evidence,null,2)+'\n');
  console.log(JSON.stringify(evidence));
} finally {
  await new Promise(resolve=>api.close(resolve));
  kube('delete','namespace',otherNamespace,'--ignore-not-found','--wait=false');
  kube('-n',namespace,'delete','pod','inventory-other','--ignore-not-found','--wait=false');
  kube('-n',namespace,'delete','serviceaccount','inventory-other','--ignore-not-found');
}
