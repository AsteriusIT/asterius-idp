import {createServer} from 'node:http';
import {openSync, closeSync, unlinkSync} from 'node:fs';
import {Adapter, DpopClient, Failure, credential, privateFile} from './adapter.mjs';
process.umask(0o077);
const config=JSON.parse(privateFile(process.argv[2]??''));
const base=new URL(config.publicBase);
if(base.protocol!=='https:'||base.search||base.hash||base.username||base.password||base.pathname.endsWith('/'))throw new Error('Exact HTTPS adapter base required');
const host=config.bind??'127.0.0.1';if(!['127.0.0.1','::1'].includes(host))throw new Error('Loopback bind required');
const lock=config.database+'.lock';const fd=openSync(lock,'wx',0o600);
process.on('exit',()=>{closeSync(fd);unlinkSync(lock);});
const upstream=new DpopClient(config),adapter=new Adapter(config.database,upstream,config.publicBase);
let queue=Promise.resolve(),queued=0;
const server=createServer((req,res)=>{
 if(queued>=64){res.writeHead(503);res.end();req.resume();return;}queued++;
 const task=async()=>{
  try{
   // Re-read the authoritative secret file on every request; replacement/revocation is immediate.
   if(!credential(config.credentialFile,config.publicBase)(req.headers.authorization))throw new Failure(401,'Provisioning credential refused');
   const target=new URL(req.url,'http://localhost');
   if(!target.pathname.startsWith(base.pathname+'/'))throw new Failure(404,'Unknown integration');
   target.pathname=target.pathname.slice(base.pathname.length);
   let raw=Buffer.alloc(0);for await(const chunk of req){raw=Buffer.concat([raw,chunk]);if(raw.length>65536)throw new Failure(413,'Request exceeds bound');}
   let body;if(raw.length){try{body=JSON.parse(raw);}catch{throw new Failure(400,'Invalid JSON');}}
   const result=await adapter.handle(req.method,target,body,req.headers['if-match']);
   res.writeHead(result.status,{'content-type':'application/scim+json',...(result.headers?.etag?{etag:result.headers.etag}:{})});res.end(result.body===null||result.body===undefined?'':JSON.stringify(result.body));
   console.info(JSON.stringify({event:'provisioning',method:req.method,status:result.status}));
  }catch(error){const status=error instanceof Failure?error.status:502;res.writeHead(status,{'content-type':'application/scim+json'});res.end(JSON.stringify({schemas:['urn:ietf:params:scim:api:messages:2.0:Error'],status:String(status),detail:error instanceof Failure?error.message:'Provisioning upstream unavailable'}));console.info(JSON.stringify({event:'provisioning',method:req.method,status}));}
 };
 queue=queue.then(task,task).finally(()=>{queued--;});
});
server.requestTimeout=30000;server.headersTimeout=10000;server.maxConnections=32;server.maxRequestsPerSocket=100;
server.listen(config.port??9490,host,()=>console.info('Entra adapter ready on configured loopback listener'));
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>server.close(()=>process.exit(0)));
