/** Adapter -> real Asterius controls. This is not an Entra cloud provisioning job. */
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync,spawn} from 'node:child_process';
import {Adapter,DpopClient,Failure,privateFile} from './adapter.mjs';
process.umask(0o077);
const config=JSON.parse(privateFile(process.argv[2]??'')),foreignConfig=JSON.parse(privateFile(process.argv[3]??''));
if(!/^ast_product_[a-f0-9]{32}$/.test(config.database)||config.database!==foreignConfig.database)throw new Error('One owned fixture database required');
const root=mkdtempSync(join(tmpdir(),'asterius-entra-control.')),base='https://entra-fixture.invalid/scim/v2';
const upstream=new DpopClient(config),foreign=new DpopClient(foreignConfig),records=[];
let fault=null;
const instrument={base:upstream.base,id:upstream.id,async request(method,path,body,headers){
 if(fault==='race'&&method==='PATCH'){fault=null;const race=await upstream.request('PATCH',path,patch('userName','racing-'+randomUUID()),{'if-match':headers['if-match']});assert.equal(race.status,200);}
 const result=await upstream.request(method,path,body,headers);
 if(fault==='lost-create'&&method==='POST'&&result.status===201||fault==='lost-patch'&&method==='PATCH'&&result.status===200){fault=null;throw new Error('Owned simulated response loss after successful backend commit');}
 return result;
}};
const adapter=new Adapter(join(root,'state.sqlite'),instrument,base);
const patch=(path,value)=>({schemas:['urn:ietf:params:scim:api:messages:2.0:PatchOp'],Operations:[{op:'replace',path,value}]});
async function call(label,method,path,status,body,etag){let result;try{result=await adapter.handle(method,new URL(path,'https://localhost'),body,etag);}catch(error){if(!(error instanceof Failure))throw error;result={status:error.status};}assert.equal(result.status,status,label);records.push({case:label,status});return result;}
function sql(statement){const r=spawnSync('docker',['exec','-i',process.env.ASTERIUS_ACCEPTANCE_DB_CONTAINER,'psql','-U','asterius','-d',config.database,'-v','ON_ERROR_STOP=1','-At'],{input:statement,encoding:'utf8'});if(r.status!==0)throw new Error('Owned fixture state control refused');return r.stdout.trim();}
let credentialServer;
try{
 await call('actual DPoP discovery','GET','/ServiceProviderConfig',200);
 const tag=randomUUID(),userDoc={schemas:['urn:ietf:params:scim:schemas:core:2.0:User'],userName:'entra-'+tag,externalId:'source-'+tag,active:true,emails:[{type:'work',value:tag+'@example.invalid'}]};
 fault='lost-create';await assert.rejects(()=>adapter.handle('POST',new URL('/Users','https://localhost'),userDoc));records.push({case:'successful create response deliberately lost',status:'interrupted'});
 const user=(await call('durable lost-create reconciliation','POST','/Users',200,userDoc)).body,id=user.id;
 await call('same source changed create refused','POST','/Users',409,{...userDoc,active:false});
 await call('owned externalId filter and projection','GET','/Users?'+new URLSearchParams({filter:`externalId eq ${JSON.stringify(userDoc.externalId)}`,excludedAttributes:'emails'}),200);
 const held=await upstream.request('GET','/Users/'+id);assert.equal(held.status,200);
 const renamed=await call('omitted If-Match uses actual GET and one CAS','PATCH','/Users/'+id,200,patch('userName','renamed-'+tag));
 await call('explicit stale ETag preserved','PATCH','/Users/'+id,412,patch('active',false),held.headers.etag);
 await call('reordered old event with stale ETag refused','PATCH','/Users/'+id,412,patch('userName',userDoc.userName),held.headers.etag);
 const outside=await foreign.request('GET','/Users/'+id);assert.equal(outside.status,404);records.push({case:'actual foreign namespace read',status:outside.status});
 const sid=randomUUID();sql(`INSERT INTO sessions(tenant_id,session_id,public_sid,user_id,authenticated_at,expires_at,idle_expires_at) VALUES('e2e','${sid}','${sid}','${id}',now(),now()+interval '1 hour',now()+interval '1 hour');`);
 await call('disable revokes owned seeded session','PATCH','/Users/'+id,200,patch('active',false));assert.equal(sql(`SELECT count(*) FROM sessions WHERE tenant_id='e2e' AND session_id='${sid}' AND revoked_at IS NOT NULL;`),'1');
 await call('reactivate provisioning-disabled user','PATCH','/Users/'+id,200,patch('active',true));
 fault='race';await call('actual intervening write returns one-CAS 412','PATCH','/Users/'+id,412,patch('active',false));
 const groupDoc={schemas:['urn:ietf:params:scim:schemas:core:2.0:Group'],displayName:'group-'+tag,externalId:'group-source-'+tag,members:[{value:id}]};
 const group=(await call('create actual group membership','POST','/Groups',201,groupDoc)).body;
 await call('remove actual group membership without If-Match','PATCH','/Groups/'+group.id,200,{schemas:['urn:ietf:params:scim:api:messages:2.0:PatchOp'],Operations:[{op:'remove',path:`members[value eq "${id}"]`}]});
 await call('delete actual group','DELETE','/Groups/'+group.id,204);
 await call('repeat group delete remains idempotent','DELETE','/Groups/'+group.id,204);
 sql(`UPDATE users SET status='locked',scim_revision=scim_revision+1 WHERE tenant_id='e2e' AND user_id='${id}';`);
 await call('security lock activation refused','PATCH','/Users/'+id,409,patch('active',true));
 await call('disable preserves security lock','PATCH','/Users/'+id,200,patch('active',false));
 await call('disable then activate cannot bypass lock','PATCH','/Users/'+id,409,patch('active',true));
 const lost=patch('userName','lost-'+tag);fault='lost-patch';await assert.rejects(()=>adapter.handle('PATCH',new URL('/Users/'+id,'https://localhost'),lost));records.push({case:'successful PATCH response deliberately lost',status:'interrupted'});
 await call('advanced ETag after lost PATCH remains ambiguous','PATCH','/Users/'+id,409,lost);
 // A fresh state DB cannot silently reconcile an uncertain write. This explicit
 // test cleanup removes only our pending marker before deleting the owned user.
 adapter.db.prepare('DELETE FROM writes WHERE path=?').run('/Users/'+id);
 await call('delete actual user','DELETE','/Users/'+id,204);
 await call('deleted actual user hidden','GET','/Users/'+id,404);
 const token=randomUUID()+randomUUID(),credentialFile=join(root,'credential.json'),serverConfig=join(root,'server.json');
 const secretDocument={audience:base,tokens:[{value:token,createdAt:new Date(Date.now()-1000).toISOString(),expiresAt:new Date(Date.now()+3600000).toISOString()}]};
 writeFileSync(credentialFile,JSON.stringify(secretDocument),{mode:0o600});writeFileSync(serverConfig,JSON.stringify({...config,publicBase:base,database:join(root,'server.sqlite'),credentialFile,port:19490}),{mode:0o600});
 credentialServer=spawn(process.execPath,[new URL('./server.mjs',import.meta.url).pathname,serverConfig],{stdio:['ignore','pipe','pipe']});
 await new Promise((resolve,reject)=>{credentialServer.stdout.once('data',resolve);credentialServer.once('exit',()=>reject(new Error('Owned adapter server exited')));setTimeout(()=>reject(new Error('Owned adapter readiness timed out')),10000).unref();});
 const request=()=>fetch('http://127.0.0.1:19490/scim/v2/ServiceProviderConfig',{headers:{authorization:'Bearer '+token}});
 assert.equal((await request()).status,200);records.push({case:'finite inbound credential reaches actual backend',status:200});
 secretDocument.tokens[0].revoked=true;writeFileSync(credentialFile,JSON.stringify(secretDocument),{mode:0o600});assert.equal((await request()).status,401);records.push({case:'authoritative credential-file revocation immediate',status:401});
 console.log(JSON.stringify({profile:'Controlled Entra adapter to actual Asterius; not native Entra cloud evidence',cases:records,limits:['Revocation uses an explicitly seeded disposable session, not a browser authentication ceremony.','Omitted-ETag reordered source events have no source sequence; native retry ambiguity requires operator reconciliation.','Lost-response faults are injected only after a verified actual successful backend response.']},null,2));
}finally{
 if(credentialServer&&credentialServer.exitCode===null){credentialServer.kill('SIGTERM');await new Promise(resolve=>credentialServer.once('exit',resolve));}
 adapter.db.close();rmSync(root,{recursive:true,force:true});
}
