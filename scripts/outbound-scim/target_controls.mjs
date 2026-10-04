// Owned target controls use real FAPI/DPoP; no tokens or keys enter evidence.
import assert from 'node:assert/strict';
import {request} from 'node:https';
import {readFile} from 'node:fs/promises';
import {createPrivateKey,createHash,randomUUID} from 'node:crypto';
import {SignJWT,generateKeyPair,exportJWK} from '../../e2e/node_modules/jose/dist/webapi/index.js';

export async function targetClient(input){
 const operator=createPrivateKey({key:await readFile(input.operator_key),format:'der',type:'pkcs8'});
 const {privateKey,publicKey}=await generateKeyPair('ES256',{extractable:true});
 const jwk=await exportJWK(publicKey),issuer=input.target_issuer;
 let token,issuerNonce,resourceNonce;
 async function proof(method,url,access,nonce){
  const body={htm:method,htu:url.split('?')[0],...(access?{ath:createHash('sha256').update(access).digest('base64url')}:{}) ,...(nonce?{nonce}:{})};
  return new SignJWT(body).setProtectedHeader({typ:'dpop+jwt',alg:'ES256',jwk}).setIssuedAt().setJti(randomUUID()).sign(privateKey);
 }
 async function wire(method,url,headers,body=''){
  const parsed=new URL(url);assert.equal(parsed.hostname,new URL(issuer).hostname);
  return new Promise((resolve,reject)=>{
   const req=request({hostname:'127.0.0.1',port:9492,servername:parsed.hostname,rejectUnauthorized:true,method,path:parsed.pathname+parsed.search,headers:{Host:parsed.host,...headers,'Content-Length':Buffer.byteLength(body)}},res=>{
    const parts=[];let size=0;
    res.on('data',chunk=>{size+=chunk.length;if(size>65536)req.destroy(Error('owned target response exceeded bound'));else parts.push(chunk);});
    res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:Buffer.concat(parts).toString('utf8')}));
   });
   req.setTimeout(10000,()=>req.destroy(Error('owned target timeout')));req.on('error',reject);req.end(body);
  });
 }
 for(let attempt=0;attempt<2;attempt++){
  const assertion=await new SignJWT({}).setProtectedHeader({alg:'ES256',kid:'outbound-peer-1'}).setIssuer('outbound-peer').setSubject('outbound-peer').setAudience(issuer).setIssuedAt().setExpirationTime('60s').setJti(randomUUID()).sign(operator);
  const data=new URLSearchParams({grant_type:'client_credentials',client_id:'outbound-peer',client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:assertion,scope:'admin.scim:read admin.scim:write',resource:issuer+'/admin/api/v1'}).toString();
  const response=await wire('POST',issuer+'/token',{'Content-Type':'application/x-www-form-urlencoded',DPoP:await proof('POST',issuer+'/token',undefined,issuerNonce)},data);
  issuerNonce=response.headers['dpop-nonce'];
  if(response.status===400&&issuerNonce&&JSON.parse(response.body).error==='use_dpop_nonce')continue;
  assert.equal(response.status,200);const value=JSON.parse(response.body);assert.equal(value.token_type.toLowerCase(),'dpop');token=value.access_token;break;
 }
 assert(token);
 return async(method,path,body,etag)=>{
  assert(/^(Users|Groups)(\/[0-9a-f-]{36})?$/.test(path));const url=issuer+'/admin/api/v1/scim/v2/'+path;
  for(let attempt=0;attempt<2;attempt++){
   const response=await wire(method,url,{Authorization:'DPoP '+token,DPoP:await proof(method,url,token,resourceNonce),'Content-Type':'application/scim+json',...(etag?{'If-Match':etag}:{})},body===undefined?'':JSON.stringify(body));
   resourceNonce=response.headers['dpop-nonce']??resourceNonce;
   if(response.status===401&&response.headers['dpop-nonce'])continue;
   return response;
  }
  throw Error('owned target nonce retry exhausted');
 };
}
