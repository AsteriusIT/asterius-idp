import {createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID, sign, timingSafeEqual} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync, statSync, chmodSync} from 'node:fs';
export const LIST='urn:ietf:params:scim:api:messages:2.0:ListResponse';
const PATCH='urn:ietf:params:scim:api:messages:2.0:PatchOp';
export class Failure extends Error { constructor(status,message){super(message);this.status=status;} }
const fail=(message,status=400)=>{throw new Failure(status,message);};
const hash=value=>createHash('sha256').update(value).digest('base64url');
const equal=(a,b)=>{const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&timingSafeEqual(x,y);};
export function privateFile(path){const st=statSync(path);if(!st.isFile()||(st.mode&0o077)||st.size>65536)fail('Private file permissions required',500);return readFileSync(path,'utf8');}
export function credential(path, audience){
 const c=JSON.parse(privateFile(path));
 if(c.audience!==audience||!Array.isArray(c.tokens)||c.tokens.length<1||c.tokens.length>2)fail('Invalid credentials',500);
 return header=>{
  const now=Date.now();let allowed=false;
  for(const t of c.tokens){
   if(typeof t.value!=='string'||t.value.length<43||!Number.isFinite(Date.parse(t.expiresAt))||!Number.isFinite(Date.parse(t.createdAt))||Date.parse(t.expiresAt)-Date.parse(t.createdAt)>30*86400000)fail('Invalid credential lifetime',500);
   allowed=equal(header??'',`Bearer ${t.value}`)&&Date.parse(t.createdAt)<=now&&now<Date.parse(t.expiresAt)&&!t.revoked||allowed;
  }
  return allowed;
 };
}
function jwt(key,header,claims){const input=[header,claims].map(x=>Buffer.from(JSON.stringify(x)).toString('base64url')).join('.');return `${input}.${sign('sha256',Buffer.from(input),{key,dsaEncoding:'ieee-p1363'}).toString('base64url')}`;}
export class DpopClient {
 constructor(config){
  this.issuer=config.issuer.replace(/\/$/,'');this.base=`${this.issuer}/admin/api/v1/scim/v2`;
  if(new URL(this.issuer).protocol!=='https:')fail('HTTPS issuer required',500);
  this.id=config.clientId;this.kid=config.keyId;this.key=createPrivateKey(privateFile(config.keyFile));
  if(this.key.asymmetricKeyDetails?.namedCurve!=='prime256v1')fail('P-256 client key required',500);
  this.proofKey=generateKeyPairSync('ec',{namedCurve:'prime256v1'}).privateKey;this.jwk=createPublicKey(this.proofKey).export({format:'jwk'});
  this.token='';this.expires=0;this.nonce=new Map();
 }
 async wire(method,url,body,headers={}){
  for(let attempt=0;attempt<2;attempt++){
   const claims={jti:randomUUID(),htm:method,htu:url.split('?')[0],iat:Math.floor(Date.now()/1000)};
   if(this.token)claims.ath=hash(this.token);
   if(this.nonce.has(new URL(url).origin))claims.nonce=this.nonce.get(new URL(url).origin);
   const res=await fetch(url,{method,redirect:'error',signal:AbortSignal.timeout(20000),headers:{'content-type':'application/scim+json',...headers,...(this.token?{authorization:`DPoP ${this.token}`} : {}),dpop:jwt(this.proofKey,{typ:'dpop+jwt',alg:'ES256',jwk:this.jwk},claims)},body});
   const nonce=res.headers.get('dpop-nonce');
   const reader=res.body?.getReader();let raw=Buffer.alloc(0);
   if(reader)for(;;){const {done,value}=await reader.read();if(done)break;raw=Buffer.concat([raw,value]);if(raw.length>1048576){await reader.cancel();fail('Upstream response exceeds bound',502);}}
   if(attempt===0&&[400,401].includes(res.status)&&nonce){this.nonce.set(new URL(url).origin,nonce);continue;}
   return {status:res.status,headers:{etag:res.headers.get('etag')},body:raw.length?JSON.parse(raw):null};
  }
 }
 async request(method,path,body,headers={}){
  if(Date.now()>=this.expires){
   this.token='';const now=Math.floor(Date.now()/1000);
   const assertion=jwt(this.key,{typ:'JWT',alg:'ES256',kid:this.kid},{iss:this.id,sub:this.id,aud:this.issuer,iat:now,exp:now+60,jti:randomUUID()});
   const form=new URLSearchParams({client_id:this.id,grant_type:'client_credentials',client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:assertion,scope:'admin.scim:read admin.scim:write',resource:`${this.issuer}/admin/api/v1`});
   const res=await this.wire('POST',`${this.issuer}/token`,form.toString(),{'content-type':'application/x-www-form-urlencoded'});
   if(res.status!==200||res.body?.token_type?.toLowerCase()!=='dpop'||typeof res.body.access_token!=='string'||!Number.isFinite(res.body.expires_in)||res.body.expires_in<=0)fail('Scoped DPoP credentials refused',502);
   this.token=res.body.access_token;this.expires=Date.now()+Math.max(0,res.body.expires_in-15)*1000;
  }
  return this.wire(method,`${this.base}${path}`,body===undefined?undefined:JSON.stringify(body),headers);
 }
}
function fields(kind){return kind==='Users'?['schemas','id','meta','userName','externalId','active','emails']:['schemas','id','meta','displayName','externalId','members'];}
export function document(kind,body,held){
 if(!body||typeof body!=='object'||Array.isArray(body))fail('Resource object required');
 for(const key of Object.keys(body))if(!fields(kind).includes(key))fail('Unsupported mapped attribute');
 if(typeof body.externalId!=='string'||!body.externalId||body.externalId.length>256)fail('Stable externalId required');
 if(held&&body.externalId!==held.externalId)fail('externalId is immutable',409);
 if(body.id!==undefined&&body.id!==held?.id)fail('Resource id is immutable');
 if(kind==='Users'&&body.active!==undefined&&typeof body.active!=='boolean')fail('active must be boolean');
 if(kind==='Users'&&body.emails!==undefined&&(!Array.isArray(body.emails)||body.emails.length>1||body.emails.some(e=>!e||typeof e.value!=='string'||e.type!=='work'||Object.keys(e).some(k=>!['value','type','primary'].includes(k)))))fail('One work email supported');
 const name=kind==='Users'?'userName':'displayName';if(typeof body[name]!=='string'||!body[name]||body[name].length>256)fail('Mapped name required');
 const out={...body};delete out.id;delete out.meta;return out;
}
export function patch(kind,body){
 if(!body||Object.keys(body).some(k=>!['schemas','Operations'].includes(k))||JSON.stringify(body.schemas)!==JSON.stringify([PATCH])||!Array.isArray(body.Operations)||!body.Operations.length||body.Operations.length>20)fail('Invalid PatchOp');
 const paths=kind==='Users'?['username','active','emails','emails[type eq "work"].value']:['displayname','members'];
 for(const op of body.Operations){
  if(!op||Object.keys(op).some(k=>!['op','path','value'].includes(k))||!['add','replace','remove'].includes(op.op?.toLowerCase()))fail('Unsupported patch operation');
  if(op.path){const path=op.path.toLowerCase();if(!paths.includes(path)&&!(kind==='Groups'&&/^members\[value eq "[0-9a-f-]{36}"\]$/.test(path)))fail('Unsupported patch path');if(path==='active'&&typeof op.value!=='boolean')fail('active must be boolean');}
  else {if(op.op.toLowerCase()==='remove'||!op.value||typeof op.value!=='object'||Array.isArray(op.value)||Object.keys(op.value).some(k=>!paths.includes(k.toLowerCase())))fail('Unsupported pathless patch');if(op.value.active!==undefined&&typeof op.value.active!=='boolean')fail('active must be boolean');}
 }
 return structuredClone(body);
}
export class Adapter {
 constructor(dbPath,upstream,publicBase){
  this.db=new DatabaseSync(dbPath);chmodSync(dbPath,0o600);this.upstream=upstream;this.base=publicBase;
  this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS mapping(kind TEXT, external TEXT, id TEXT, PRIMARY KEY(kind,external), UNIQUE(kind,id)); CREATE TABLE IF NOT EXISTS intent(key TEXT PRIMARY KEY, kind TEXT, external TEXT, body TEXT, name TEXT); CREATE TABLE IF NOT EXISTS receipt(key TEXT PRIMARY KEY, etag TEXT, body TEXT); CREATE TABLE IF NOT EXISTS writes(path TEXT PRIMARY KEY, fingerprint TEXT, etag TEXT); CREATE TABLE IF NOT EXISTS source(kind TEXT, external TEXT, fingerprint TEXT, PRIMARY KEY(kind,external)); CREATE TABLE IF NOT EXISTS deleted(path TEXT PRIMARY KEY);');
 }
 mapped(kind,id){return this.db.prepare('SELECT * FROM mapping WHERE kind=? AND id=?').get(kind,id);}
 remember(kind,body,id,key,text){this.db.exec('BEGIN IMMEDIATE');try{this.db.prepare('INSERT INTO mapping VALUES(?,?,?)').run(kind,body.externalId,id);this.db.prepare('INSERT INTO source VALUES(?,?,?)').run(kind,body.externalId,hash(text));this.db.prepare('DELETE FROM intent WHERE key=?').run(key);this.db.exec('COMMIT');}catch(error){this.db.exec('ROLLBACK');throw error;}}
 rewrite(value,toPublic=true){
  if(Array.isArray(value))return value.map(v=>this.rewrite(v,toPublic));
  if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,this.rewrite(v,toPublic)]));
  if(typeof value==='string'){const from=toPublic?this.upstream.base:this.base,to=toPublic?this.base:this.upstream.base;if(value.startsWith(from+'/'))return to+value.slice(from.length);}
  return value;
 }
 async handle(method,url,body,ifMatch){
  if(method==='GET'&&['/ServiceProviderConfig','/Schemas','/ResourceTypes'].includes(url.pathname)){const res=await this.upstream.request('GET',url.pathname);if(url.pathname==='/ServiceProviderConfig'&&res.status===200)res.body.authenticationSchemes=[{type:'oauthbearertoken',name:'Isolated Entra adapter credential',description:'Route-bound finite operator credential; upstream private_key_jwt and DPoP'}];res.body=this.rewrite(res.body);return res;}
  const m=/^\/(Users|Groups)(?:\/([0-9a-f-]{36}))?$/.exec(url.pathname);if(!m)fail('Unsupported resource',404);
  const [,kind,id]=m;const path=`/${kind}${id?'/'+id:''}`;
  if(!['GET','POST','PUT','PATCH','DELETE'].includes(method)||(!id&&!['GET','POST'].includes(method))||(id&&method==='POST'))fail('Unsupported operation',405);
  const query=url.searchParams;for(const key of query.keys())if(!['filter','startIndex','count','excludedAttributes'].includes(key)||query.getAll(key).length!==1)fail('Unsupported query');
  const count=Number(query.get('count')??100),start=Number(query.get('startIndex')??1);if(!Number.isInteger(count)||count<0||count>200||!Number.isInteger(start)||start<1||start>10001)fail('Invalid pagination');
  const exclude=(query.get('excludedAttributes')??'').split(',').filter(Boolean);if(exclude.some(x=>!(kind==='Users'?['groups','emails']:['members']).includes(x))||new Set(exclude).size!==exclude.length)fail('Unsupported projection');
  const project=res=>{res.body=this.rewrite(res.body);const docs=res.body?.Resources??(res.body?[res.body]:[]);for(const d of docs)for(const attr of exclude)delete d[attr];return res;};
  if(method==='GET'&&!id){
   let filter=query.get('filter');let target;
   if(filter){const match=/^(userName|displayName|externalId) eq (".*")$/.exec(filter);if(!match)fail('Unsupported filter');let val;try{val=JSON.parse(match[2]);}catch{fail('Invalid filter');}if(typeof val!=='string'||val.length>256)fail('Invalid filter');
    if(match[1]==='externalId'){target=this.db.prepare('SELECT id FROM mapping WHERE kind=? AND external=?').get(kind,val)?.id;if(!target)return {status:200,body:{schemas:[LIST],totalResults:0,startIndex:start,itemsPerPage:0,Resources:[]},headers:{}};}
    else if(match[1]!== (kind==='Users'?'userName':'displayName'))fail('Unsupported filter');
   }
   if(target){const res=await this.upstream.request('GET',`/${kind}/${target}`);if(res.status!==200)return res;const resources=start===1&&count? [res.body]:[];return project({status:200,headers:{},body:{schemas:[LIST],totalResults:1,startIndex:start,itemsPerPage:resources.length,Resources:resources}});}
   const q=new URLSearchParams({startIndex:String(start),count:String(count)});if(filter)q.set('filter',filter);
   return project(await this.upstream.request('GET',`${path}?${q}`));
  }
  if(method!=='GET'&&query.size)fail('Mutation query unsupported');
  if(id&&!this.mapped(kind,id))fail('Resource not owned',404);
  if(method==='GET')return project(await this.upstream.request('GET',path));
  if(method==='POST'){
   body=document(kind,body);const key=hash(`${kind}\n${body.externalId}`),text=JSON.stringify(body),name=body[kind==='Users'?'userName':'displayName'];
   const mapped=this.db.prepare('SELECT id FROM mapping WHERE kind=? AND external=?').get(kind,body.externalId);
   if(mapped){const source=this.db.prepare('SELECT fingerprint FROM source WHERE kind=? AND external=?').get(kind,body.externalId);if(source?.fingerprint!==hash(text))fail('Existing source identity differs',409);return project(await this.upstream.request('GET',`/${kind}/${mapped.id}`));}
   const pending=this.db.prepare('SELECT * FROM intent WHERE key=?').get(key);
   if(pending){if(pending.body!==text)fail('Pending create differs',409);const q=new URLSearchParams({filter:`${kind==='Users'?'userName':'displayName'} eq ${JSON.stringify(name)}`,count:'2'});const old=await this.upstream.request('GET',`/${kind}?${q}`);if(old.status!==200)return old;
    if(old.body.Resources?.length){if(old.body.Resources.length!==1||old.body.Resources[0].externalId!==body.externalId)fail('Ambiguous create recovery',409);const found=old.body.Resources[0];this.remember(kind,body,found.id,key,text);return project({status:200,headers:{etag:found.meta?.version},body:found});}
   }else this.db.prepare('INSERT INTO intent VALUES(?,?,?,?,?)').run(key,kind,body.externalId,text,name);
   const res=await this.upstream.request('POST',path,this.rewrite(body,false));
   if(res.status===201){this.remember(kind,body,res.body.id,key,text);}else if(res.status<500)this.db.prepare('DELETE FROM intent WHERE key=?').run(key);
   return project(res);
  }
  const held=await this.upstream.request('GET',path);if(held.status!==200){if(method==='DELETE'&&held.status===404&&(this.db.prepare('SELECT * FROM writes WHERE path=?').get(path)?.fingerprint==='DELETE'||this.db.prepare('SELECT * FROM deleted WHERE path=?').get(path))){this.db.prepare('DELETE FROM writes WHERE path=?').run(path);return {status:204,headers:{},body:null};}return held;}
  const etag=held.headers.etag;if(!etag)fail('Upstream ETag missing',502);
  if(ifMatch!==undefined&&ifMatch!==etag)fail('SCIM resource version changed',412);
  if(method==='PUT')body=document(kind,body,held.body);if(method==='PATCH')body=patch(kind,body);
  const key=hash(`${method}\n${path}\n${JSON.stringify(body)}`),receipt=this.db.prepare('SELECT * FROM receipt WHERE key=?').get(key);
  if(receipt?.etag===etag)return project({status:200,headers:{etag},body:JSON.parse(receipt.body)});
  const pending=this.db.prepare('SELECT * FROM writes WHERE path=?').get(path);
  if(pending&&(pending.etag!==etag||pending.fingerprint!==(method==='DELETE'?'DELETE':key)))fail('Ambiguous previous write; reconcile explicitly',409);
  this.db.prepare('INSERT OR REPLACE INTO writes VALUES(?,?,?)').run(path,method==='DELETE'?'DELETE':key,etag);
  const res=await this.upstream.request(method,path,this.rewrite(body,false),{'if-match':ifMatch??etag});
  if(method==='DELETE'&&res.status===204)this.db.prepare('INSERT OR IGNORE INTO deleted VALUES(?)').run(path);
  if(res.status<500)this.db.prepare('DELETE FROM writes WHERE path=?').run(path);
  if(res.status>=200&&res.status<300&&method!=='DELETE')this.db.prepare('INSERT OR REPLACE INTO receipt VALUES(?,?,?)').run(key,res.headers.etag,JSON.stringify(res.body));
  return project(res);
 }
}
