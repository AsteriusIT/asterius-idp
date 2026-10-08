import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Adapter,credential,document,patch} from './adapter.mjs';
const ID='00000000-0000-4000-8000-000000000001';
const schema='urn:ietf:params:scim:schemas:core:2.0:User';
const user={schemas:[schema],externalId:'entra-object-1',userName:'alice@example.test',active:true,emails:[{type:'work',value:'alice@example.test'}]};
const change={schemas:['urn:ietf:params:scim:api:messages:2.0:PatchOp'],Operations:[{op:'replace',path:'active',value:false}]};
function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'entra-adapter-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));
 const remote={base:'https://id.test/t/tenant/admin/api/v1/scim/v2',value:null,version:1,mutations:0,locked:false,loseCreate:false,losePatch:false,
  async request(method,path,body,headers={}){
   if(method==='POST'){this.value={...body,id:ID,meta:{version:'W/"1"',location:this.base+'/Users/'+ID}};this.mutations++;if(this.loseCreate){this.loseCreate=false;throw new Error('lost create response');}return {status:201,body:structuredClone(this.value),headers:{etag:'W/"1"'}};}
   if(method==='GET'&&path.includes('?'))return {status:200,headers:{},body:{Resources:this.value?[structuredClone(this.value)]:[],totalResults:this.value?1:0}};
   if(!this.value)return {status:404,body:{status:'404'},headers:{}};
   if(method==='GET')return {status:200,body:structuredClone(this.value),headers:{etag:`W/"${this.version}"`}};
   if(this.locked)return {status:409,body:{status:'409'},headers:{}};
   if(headers['if-match']!==`W/"${this.version}"`)return {status:412,body:{status:'412'},headers:{}};
   this.mutations++;if(method==='DELETE'){this.value=null;return {status:204,headers:{},body:null};}
   this.version++;this.value.active=body.Operations?.[0]?.value??body.active;this.value.meta.version=`W/"${this.version}"`;
   if(this.losePatch){this.losePatch=false;throw new Error('lost PATCH response');}
   return {status:200,body:structuredClone(this.value),headers:{etag:`W/"${this.version}"`}};
  }};
 const adapter=new Adapter(join(dir,'state.db'),remote,'https://adapter.test/integration/scim/v2');t.after(()=>adapter.db.close());
 const req=(method,path,body,etag)=>adapter.handle(method,new URL(path,'https://adapter.test'),body,etag);
 return {dir,remote,adapter,req};
}
test('omitted If-Match uses one CAS; stale/foreign writes have no side effects; locked409 retained',async t=>{
 const {remote,req}=fixture(t);await req('POST','/Users',user);
 await assert.rejects(req('PATCH','/Users/'+ID,change,'W/"0"'),e=>e.status===412);assert.equal(remote.mutations,1);
 await assert.rejects(req('PATCH','/Users/00000000-0000-4000-8000-000000000099',change),e=>e.status===404);assert.equal(remote.mutations,1);
 remote.locked=true;assert.equal((await req('PATCH','/Users/'+ID,change)).status,409);assert.equal(remote.mutations,1);
 remote.locked=false;assert.equal((await req('PATCH','/Users/'+ID,change)).status,200);assert.equal(remote.value.active,false);assert.equal(remote.mutations,2);
 assert.equal((await req('PATCH','/Users/'+ID,change)).status,200);assert.equal(remote.mutations,2);
});
test('lost create response recovers durable identity without second creation',async t=>{
 const {remote,adapter,req}=fixture(t);remote.loseCreate=true;await assert.rejects(req('POST','/Users',user));
 assert.equal((await req('POST','/Users',user)).body.id,ID);assert.equal(remote.mutations,1);assert.equal(adapter.mapped('Users',ID).external,user.externalId);
 await assert.rejects(req('POST','/Users',{...user,userName:'different@example.test'}),e=>e.status===409);assert.equal(remote.mutations,1);
});
test('ambiguous lost PATCH refuses reordered retries rather than overwriting newer version',async t=>{
 const {remote,req}=fixture(t);await req('POST','/Users',user);remote.losePatch=true;
 await assert.rejects(req('PATCH','/Users/'+ID,change));
 await assert.rejects(req('PATCH','/Users/'+ID,change),e=>e.status===409);
 await assert.rejects(req('PATCH','/Users/'+ID,{...change,Operations:[{op:'replace',path:'active',value:true}]}),e=>e.status===409);assert.equal(remote.mutations,2);
});
test('externalId filtering and projection return exact owned identity',async t=>{
 const {req}=fixture(t);await req('POST','/Users',user);
 const result=await req('GET','/Users?filter='+encodeURIComponent('externalId eq "entra-object-1"')+'&excludedAttributes=emails');
 assert.equal(result.body.Resources[0].id,ID);assert.equal(result.body.Resources[0].emails,undefined);assert.match(result.body.Resources[0].meta.location,/adapter.test/);
 assert.equal((await req('GET','/Users?filter='+encodeURIComponent('externalId eq "foreign"'))).body.totalResults,0);
 await assert.rejects(req('GET','/Users?count=1&count=2'),e=>e.status===400);
});
test('minimal mapping rejects unknown fields, legacy bool, mutable identity and unsupported patch',()=>{
 assert.throws(()=>document('Users',{...user,name:{givenName:'A'}}));assert.throws(()=>document('Users',{...user,active:'true'}));
 assert.throws(()=>document('Users',{...user,externalId:'other'},user));assert.throws(()=>patch('Users',{...change,Operations:[{op:'replace',path:'externalId',value:'other'}]}));assert.throws(()=>patch('Users',{...change,Operations:[{op:'replace',path:'active',value:'false'}]}));
});
test('route-bound credential expires and revoked replacement refuses',t=>{
 const {dir}=fixture(t),file=join(dir,'credential.json'),now=Date.now(),token='a'.repeat(43);
 const data={audience:'https://adapter.test/scim/v2',tokens:[{value:token,createdAt:new Date(now-1000).toISOString(),expiresAt:new Date(now+60000).toISOString()}]};writeFileSync(file,JSON.stringify(data),{mode:0o600});
 assert.equal(credential(file,data.audience)('Bearer '+token),true);assert.equal(credential(file,data.audience)('DPoP '+token),false);assert.throws(()=>credential(file,'https://foreign.test'));
 data.tokens[0].revoked=true;writeFileSync(file,JSON.stringify(data));assert.equal(credential(file,data.audience)('Bearer '+token),false);
});
test('token and API requests use signed ES256 assertions, scoped audience and DPoP nonce/ath',async t=>{
 const {generateKeyPairSync,verify,createPublicKey,createHash}=await import('node:crypto');const {DpopClient}=await import('./adapter.mjs');
 const dir=mkdtempSync(join(tmpdir(),'entra-dpop-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));
 const key=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),file=join(dir,'key.pem');writeFileSync(file,key.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});
 const old=globalThis.fetch;t.after(()=>{globalThis.fetch=old;});const calls=[];
 globalThis.fetch=async(url,options)=>{calls.push({url,options});if(calls.length===1)return new Response('{}',{status:401,headers:{'DPoP-Nonce':'nonce-1'}});if(url.endsWith('/token'))return new Response(JSON.stringify({token_type:'DPoP',access_token:'bound-token',expires_in:60}),{status:200});return new Response('{}',{status:200});};
 const client=new DpopClient({issuer:'https://id.test/t/owned',clientId:'owned-client',keyId:'own-key',keyFile:file});await client.request('GET','/Users?count=1');assert.equal(calls.length,3);
 const decode=token=>JSON.parse(Buffer.from(token.split('.')[1],'base64url'));
 const form=new URLSearchParams(calls[1].options.body),assertion=form.get('client_assertion');assert.equal(form.get('scope'),'admin.scim:read admin.scim:write');assert.equal(form.get('resource'),'https://id.test/t/owned/admin/api/v1');assert.equal(decode(assertion).aud,'https://id.test/t/owned');
 assert.equal(verify('sha256',Buffer.from(assertion.split('.').slice(0,2).join('.')),{key:key.publicKey,dsaEncoding:'ieee-p1363'},Buffer.from(assertion.split('.')[2],'base64url')),true);
 const proof=calls[2].options.headers.dpop,header=JSON.parse(Buffer.from(proof.split('.')[0],'base64url')),claims=decode(proof);
 assert.equal(claims.htm,'GET');assert.equal(claims.htu,'https://id.test/t/owned/admin/api/v1/scim/v2/Users');assert.equal(claims.nonce,'nonce-1');assert.equal(claims.ath,createHash('sha256').update('bound-token').digest('base64url'));assert.equal(calls[2].options.headers.authorization,'DPoP bound-token');
 assert.equal(verify('sha256',Buffer.from(proof.split('.').slice(0,2).join('.')),{key:createPublicKey({key:header.jwk,format:'jwk'}),dsaEncoding:'ieee-p1363'},Buffer.from(proof.split('.')[2],'base64url')),true);
});
test('persisted map survives reopen and owned delete retries remain idempotent',async t=>{
 const {adapter,remote,dir,req}=fixture(t);await req('POST','/Users',user);
 const reopened=new Adapter(join(dir,'state.db'),remote,adapter.base);t.after(()=>reopened.db.close());assert.equal(reopened.mapped('Users',ID).external,user.externalId);
 assert.equal((await req('POST','/Users',user)).status,200);assert.equal(remote.mutations,1);
 assert.equal((await req('DELETE','/Users/'+ID)).status,204);assert.equal((await req('DELETE','/Users/'+ID)).status,204);assert.equal(remote.mutations,2);
});
test('real listener confines Bearer to exact route, rejects missing/revoked credentials, redacts logs',async t=>{
 const {spawn}=await import('node:child_process');const {generateKeyPairSync}=await import('node:crypto');const {createServer}=await import('node:net');const {fileURLToPath}=await import('node:url');
 const dir=mkdtempSync(join(tmpdir(),'entra-http-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));
 const probe=createServer();await new Promise(resolve=>probe.listen(0,'127.0.0.1',resolve));const port=probe.address().port;await new Promise(resolve=>probe.close(resolve));
 const keyFile=join(dir,'key.pem'),credentialFile=join(dir,'credentials.json'),configFile=join(dir,'config.json'),token='b'.repeat(43),publicBase='https://adapter.test/integration/scim/v2';
 writeFileSync(keyFile,generateKeyPairSync('ec',{namedCurve:'prime256v1'}).privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});
 const cred={audience:publicBase,tokens:[{value:token,createdAt:new Date(Date.now()-1000).toISOString(),expiresAt:new Date(Date.now()+60000).toISOString()}]};writeFileSync(credentialFile,JSON.stringify(cred),{mode:0o600});
 writeFileSync(configFile,JSON.stringify({issuer:'https://id.test/t/tenant',clientId:'client',keyId:'key',keyFile,publicBase,credentialFile,database:join(dir,'state.db'),port}),{mode:0o600});
 const child=spawn(process.execPath,[fileURLToPath(new URL('./server.mjs',import.meta.url)),configFile],{stdio:['ignore','pipe','pipe']});let logs='';
 t.after(async()=>{child.kill('SIGTERM');await new Promise(resolve=>child.once('exit',resolve));});
 await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('listener startup timeout')),5000);child.stdout.on('data',data=>{logs+=data;if(logs.includes('adapter ready')){clearTimeout(timer);resolve();}});child.once('exit',()=>{clearTimeout(timer);reject(new Error('listener exited'));});});
 const base=`http://127.0.0.1:${port}`;
 assert.equal((await fetch(base+'/integration/scim/v2/Users')).status,401);
 assert.equal((await fetch(base+'/other/Users',{headers:{authorization:'Bearer '+token}})).status,404);
 cred.tokens[0].revoked=true;writeFileSync(credentialFile,JSON.stringify(cred));
 assert.equal((await fetch(base+'/integration/scim/v2/Users',{headers:{authorization:'Bearer '+token}})).status,401);
 assert.equal(logs.includes(token),false);
});
