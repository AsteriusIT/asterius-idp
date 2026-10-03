// Node.js client: independent ES256 private_key_jwt plus ephemeral ES256 DPoP.
// Never logs an assertion, client credential or access token.
import { readFileSync } from 'node:fs';
import { createPrivateKey, generateKeyPairSync, randomUUID, sign, createHash } from 'node:crypto';
import https from 'node:https';

const required = name => { const value=process.env[name]; if (!value) throw new Error(`Missing ${name}`); return value; };
const issuer=required('ASTERIUS_ISSUER');
function secureURL(raw) { const url=new URL(raw);if(url.protocol!=='https:'||url.username||url.password||url.hash)throw new Error('HTTPS without embedded credentials required');return raw; }
secureURL(issuer);
const endpoint=`${issuer.replace(/\/$/,'')}/token`;
const resource=required('ASTERIUS_RESOURCE');
const clientId=required('ASTERIUS_CLIENT_ID');
const audience=required('ASTERIUS_WORKLOAD_AUDIENCE');
const clientKey=createPrivateKey(readFileSync(required('ASTERIUS_CLIENT_KEY_FILE')));
if(clientKey.asymmetricKeyType!=='ec'||clientKey.asymmetricKeyDetails?.namedCurve!=='prime256v1')throw new Error('A P-256 confidential client key is required');
const {privateKey:dpopKey,publicKey:dpopPublic}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const dpopJwk=dpopPublic.export({format:'jwk'});
function jwt(header,claims,key) {
  const encoded=[header,claims].map(value=>Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');
  return `${encoded}.${sign('sha256',Buffer.from(encoded),{key,dsaEncoding:'ieee-p1363'}).toString('base64url')}`;
}
function dpop(method,url,token,nonce) {
  const claims={jti:randomUUID(),htm:method,htu:url.split(/[?#]/)[0],iat:Math.floor(Date.now()/1000)};
  if (token) claims.ath=createHash('sha256').update(token).digest('base64url');
  if (nonce) claims.nonce=nonce;
  return jwt({typ:'dpop+jwt',alg:'ES256',jwk:dpopJwk},claims,dpopKey);
}
function kubeRequest(path,body) {
  // Read every request: projected credentials rotate by symlink replacement.
  const apiToken=readFileSync(process.env.KUBERNETES_API_TOKEN_FILE||'/var/run/workload/kube-api-token','utf8').trim();
  return new Promise((resolve,reject)=>{
    const request=https.request({hostname:required('KUBERNETES_SERVICE_HOST'),port:process.env.KUBERNETES_SERVICE_PORT_HTTPS||443,path,method:'POST',ca:readFileSync(process.env.KUBERNETES_CA_FILE||'/var/run/kube-ca/ca.crt'),headers:{Authorization:`Bearer ${apiToken}`,'Content-Type':'application/json'}},response=>{
      const chunks=[];let size=0;
      response.on('data',chunk=>{size+=chunk.length;if(size>32768){response.destroy(new Error('TokenRequest response too large'));return;}chunks.push(chunk);});
      response.on('error',reject);
      response.on('end',()=>{if(response.statusCode!==201&&response.statusCode!==200){reject(new Error(`TokenRequest HTTP ${response.statusCode}`));return;}try{resolve(JSON.parse(Buffer.concat(chunks).toString()));}catch{reject(new Error('Invalid TokenRequest response'));}});
    });
    request.on('error',reject);request.end(JSON.stringify(body));
  });
}
let lastAssertionDigest;
async function projectedAssertion() {
  const namespace=required('POD_NAMESPACE');const serviceAccount=required('SERVICE_ACCOUNT');
  for(let attempt=0;attempt<3;attempt++) {
  const result=await kubeRequest(`/api/v1/namespaces/${encodeURIComponent(namespace)}/serviceaccounts/${encodeURIComponent(serviceAccount)}/token`,{apiVersion:'authentication.k8s.io/v1',kind:'TokenRequest',spec:{audiences:[audience],expirationSeconds:600,boundObjectRef:{kind:'Pod',apiVersion:'v1',name:required('POD_NAME'),uid:required('POD_UID')}}});
  if (typeof result.status?.token!=='string') throw new Error('Missing projected assertion');
  const digest=createHash('sha256').update(result.status.token).digest('base64url');
  if(digest!==lastAssertionDigest){lastAssertionDigest=digest;return result.status.token;}
  if(attempt<2) await new Promise(resolve=>setTimeout(resolve,1100));
  }
  throw new Error('TokenRequest repeated the same assertion');
}
export async function apiCall() {
  // A nonce challenge starts a NEW mint with a fresh assertion and auth jti.
  let nonce;
  for(let attempt=0;attempt<2;attempt++) {
    const assertion=await projectedAssertion();
    const now=Math.floor(Date.now()/1000);
    const clientAssertion=jwt({alg:'ES256',typ:'JWT',kid:required('ASTERIUS_CLIENT_KID')},{iss:clientId,sub:clientId,aud:issuer,jti:randomUUID(),iat:now,exp:now+60},clientKey);
    const form=new URLSearchParams({grant_type:'urn:ietf:params:oauth:grant-type:token-exchange',subject_token_type:'urn:ietf:params:oauth:token-type:jwt',subject_token:assertion,resource,scope:required('ASTERIUS_SCOPE'),client_id:clientId,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:clientAssertion});
    if(process.env.ASTERIUS_ACTIONS) form.set('authorization_details',JSON.stringify([{type:'urn:asterius:workload-actions',locations:[resource],actions:process.env.ASTERIUS_ACTIONS.split(' ').filter(Boolean)}]));
    const reply=await fetch(endpoint,{method:'POST',redirect:'error',headers:{DPoP:dpop('POST',endpoint,undefined,nonce)},body:form});
    const body=await reply.json().catch(()=>{throw new Error('Invalid exchange response');});
    if(!reply.ok) { if(body.error==='use_dpop_nonce'&&reply.headers.has('DPoP-Nonce')&&attempt===0){nonce=reply.headers.get('DPoP-Nonce');continue;}throw new Error(`Exchange HTTP ${reply.status}`); }
    if(body.token_type!=='DPoP'||typeof body.access_token!=='string'||!(body.expires_in>0&&body.expires_in<=300)) throw new Error('Unexpected constrained token response');
    const url=secureURL(required('ASTERIUS_API_URL'));
    let response=await fetch(url,{redirect:'error',headers:{Authorization:`DPoP ${body.access_token}`,DPoP:dpop('GET',url,body.access_token)}});
    const apiNonce=response.headers.get('DPoP-Nonce');
    if(apiNonce&&response.status===401) response=await fetch(url,{redirect:'error',headers:{Authorization:`DPoP ${body.access_token}`,DPoP:dpop('GET',url,body.access_token,apiNonce)}});
    if(!response.ok) throw new Error(`API HTTP ${response.status}`);
    return response;
  }
  throw new Error('Nonce exchange failed');
}
if(import.meta.url===`file://${process.argv[1]}`) await apiCall().then(response=>console.log(`API HTTP ${response.status}`));
