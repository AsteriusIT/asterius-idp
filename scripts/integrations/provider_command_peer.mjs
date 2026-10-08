/** Independent controlled RP for the two supported Provider Commands draft02 account operations. */
import {createServer} from 'node:http';
import {createPublicKey,verify} from 'node:crypto';
export function peer({issuer,endpoint,tenant='e2e',jwks}) {
 const state={client:'',subject:'',account:'active',sessions:1,tokens:1,mode:'normal',requests:[],refusals:[],seen:new Set(),lastToken:''};
 function refusal(status,error){return {status,body:{error}};}
 function accept(token){
  try {
   const parts=token.split('.');if(parts.length!==3)return refusal(400,'invalid_request');
   const header=JSON.parse(Buffer.from(parts[0],'base64url')),claims=JSON.parse(Buffer.from(parts[1],'base64url'));
   if(header.typ!=='command+jwt'||!['ES256','EdDSA'].includes(header.alg))return refusal(400,'invalid_request');
   const candidates=jwks.keys.filter(key=>key.kid===header.kid&&((header.alg==='ES256'&&key.kty==='EC'&&key.crv==='P-256')||(header.alg==='EdDSA'&&key.kty==='OKP'&&key.crv==='Ed25519')));
   if(candidates.length!==1||!verify(header.alg==='EdDSA'?null:'sha256',Buffer.from(parts.slice(0,2).join('.')),{key:createPublicKey({key:candidates[0],format:'jwk'}),dsaEncoding:'ieee-p1363'},Buffer.from(parts[2],'base64url')))return refusal(400,'invalid_request');
   if(claims.iss!==(state.mode==='wrong_issuer'?issuer+'/unrecognized':issuer))return refusal(401,'unrecognized_provider');
   if(claims.aud!==(state.mode==='wrong_audience'?endpoint+'/different':endpoint)||claims.client_id!==state.client||claims.tenant!==tenant||claims.sub!==state.subject)return refusal(400,'invalid_request');
   const now=state.mode==='expired'?claims.exp+1:Math.floor(Date.now()/1000);
   if(!Number.isInteger(claims.iat)||!Number.isInteger(claims.exp)||claims.exp<=now||claims.iat>now+5||claims.exp-claims.iat>300||typeof claims.jti!=='string'||!claims.jti||'nonce' in claims)return refusal(400,'invalid_request');
   const allowed=['iss','aud','client_id','iat','exp','jti','command','tenant','sub','aud_sub'];
   if(Object.keys(claims).some(name=>!allowed.includes(name)))return refusal(400,'invalid_request');
   if(!['invalidate','delete'].includes(claims.command)||state.mode==='unsupported')return refusal(400,'unsupported_command');
   if(state.seen.has(claims.jti))return refusal(400,'invalid_request');
   if(state.mode==='bad_response'){state.lastToken=token;state.requests.push({command:claims.command,signature_verified:true,signature_alg:header.alg,status:204,response_no_store:false,mutation:false});return {status:204,body:null,noStore:false};}
   state.seen.add(claims.jti);state.lastToken=token;state.sessions=0;state.tokens=0;if(claims.command==='delete')state.account='unknown';
   state.requests.push({command:claims.command,signature_verified:true,signature_alg:header.alg,status:200,response_no_store:true,mutation:true});
   return {status:200,body:{sub:claims.sub,account_state:state.account}};
  } catch {return refusal(400,'invalid_request');}
 }
 const server=createServer(async(request,response)=>{
  if(request.method!=='POST'||request.url!=='/provider-command-peer/command'){response.writeHead(404);response.end();return;}
  if(request.headers['content-type']?.split(';')[0]!=='application/x-www-form-urlencoded'||request.headers['transfer-encoding']){response.writeHead(400,{'content-type':'application/json','cache-control':'no-store'});response.end('{"error":"invalid_request"}');return;}
  let data=Buffer.alloc(0);for await(const part of request){data=Buffer.concat([data,part]);if(data.length>8192){response.writeHead(413);response.end();return;}}
  const form=new URLSearchParams(data.toString()),tokens=form.getAll('command_token');const result=tokens.length===1?accept(tokens[0]):refusal(400,'invalid_request');
  if(result.status>=400){let header={};try{header=JSON.parse(Buffer.from(tokens[0].split('.')[0],'base64url'));}catch{}state.refusals.push({status:result.status,error:result.body.error,alg:['ES256','EdDSA'].includes(header.alg)?header.alg:'other',typ:header.typ==='command+jwt'?'command+jwt':'other'});}
  response.writeHead(result.status,{'content-type':'application/json',...(result.noStore===false?{}:{'cache-control':'no-store'})});response.end(result.body?JSON.stringify(result.body):undefined);
 });
 return {state,server};
}
