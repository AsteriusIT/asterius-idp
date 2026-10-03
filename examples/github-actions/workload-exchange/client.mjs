// Approved self-hosted workflow: independent client key + GitHub subject JWT.
// No repository OAuth secret, token output, JWT claim output or response-body logging.
import { readFileSync } from 'node:fs';
import { createPrivateKey, generateKeyPairSync, sign, randomUUID, createHash } from 'node:crypto';

const required=name=>{if(!process.env[name])throw new Error(`Missing ${name}`);return process.env[name];};
function secureURL(raw) {const url=new URL(raw);if(url.protocol!=='https:'||url.username||url.password||url.hash)throw new Error('HTTPS without embedded credentials required');return url;}
const issuer=required('ASTERIUS_ISSUER'),resource=required('ASTERIUS_RESOURCE');
secureURL(issuer);secureURL(resource);
const endpoint=`${issuer.replace(/\/$/,'')}/token`;
const clientId=required('ASTERIUS_CLIENT_ID'),audience=required('ASTERIUS_WORKLOAD_AUDIENCE');
const key=createPrivateKey(readFileSync(required('ASTERIUS_CLIENT_KEY_FILE')));
if(key.asymmetricKeyType!=='ec'||key.asymmetricKeyDetails?.namedCurve!=='prime256v1')throw new Error('Independent P-256 confidential client key required');
const {privateKey:dpopKey,publicKey:dpopPublic}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const dpopJwk=dpopPublic.export({format:'jwk'});
function jwt(header,claims,key) {const input=[header,claims].map(value=>Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');return `${input}.${sign('sha256',Buffer.from(input),{key,dsaEncoding:'ieee-p1363'}).toString('base64url')}`;}
function proof(method,url,token,nonce) {
  const claims={htm:method,htu:url.split(/[?#]/)[0],iat:Math.floor(Date.now()/1000),jti:randomUUID()};
  if(token)claims.ath=createHash('sha256').update(token).digest('base64url');
  if(nonce)claims.nonce=nonce;
  return jwt({typ:'dpop+jwt',alg:'ES256',jwk:dpopJwk},claims,dpopKey);
}
async function boundedJSON(response,limit) {
  if(!response.body)throw new Error('Missing response body');
  const reader=response.body.getReader();let bytes=0;const chunks=[];
  for(;;){const {done,value}=await reader.read();if(done)break;bytes+=value.length;if(bytes>limit){await reader.cancel();throw new Error('Response too large');}chunks.push(value);}
  try{return JSON.parse(Buffer.concat(chunks).toString());}catch{throw new Error('Invalid response');}
}
let lastSubjectDigest;
async function githubAssertion() {
  const url=secureURL(required('ACTIONS_ID_TOKEN_REQUEST_URL'));
  if(!(url.hostname.endsWith('.actions.githubusercontent.com')||url.hostname==='run-actions.githubusercontent.com'))throw new Error('GitHub Actions OIDC endpoint required');
  url.searchParams.set('audience',audience);
  for(let attempt=0;attempt<3;attempt++) {
    const response=await fetch(url,{redirect:'error',headers:{Authorization:`Bearer ${required('ACTIONS_ID_TOKEN_REQUEST_TOKEN')}`},signal:AbortSignal.timeout(5000)});
    if(!response.ok)throw new Error(`OIDC HTTP ${response.status}`);
    const body=await boundedJSON(response,16384);
    if(typeof body.value!=='string'||body.value.length>8192)throw new Error('Invalid OIDC assertion');
    const digest=createHash('sha256').update(body.value).digest('base64url');
    if(digest!==lastSubjectDigest){lastSubjectDigest=digest;return body.value;}
    if(attempt<2)await new Promise(resolve=>setTimeout(resolve,1100));
  }
  throw new Error('OIDC returned a previously spent assertion');
}
export async function apiCall() {
  let nonce;
  for(let attempt=0;attempt<2;attempt++) {
    const subject=await githubAssertion();
    const now=Math.floor(Date.now()/1000);
    const auth=jwt({typ:'JWT',alg:'ES256',kid:required('ASTERIUS_CLIENT_KID')},{iss:clientId,sub:clientId,aud:issuer,iat:now,exp:now+60,jti:randomUUID()},key);
    const form=new URLSearchParams({grant_type:'urn:ietf:params:oauth:grant-type:token-exchange',subject_token_type:'urn:ietf:params:oauth:token-type:jwt',subject_token:subject,resource,scope:required('ASTERIUS_SCOPE'),client_id:clientId,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:auth});
    if(process.env.ASTERIUS_ACTIONS)form.set('authorization_details',JSON.stringify([{type:'urn:asterius:workload-actions',actions:process.env.ASTERIUS_ACTIONS.split(' ').filter(Boolean),locations:[resource]}]));
    const response=await fetch(endpoint,{method:'POST',redirect:'error',headers:{DPoP:proof('POST',endpoint,undefined,nonce)},body:form,signal:AbortSignal.timeout(5000)});
    const body=await boundedJSON(response,16384);
    if(!response.ok){if(body.error==='use_dpop_nonce'&&attempt===0&&response.headers.has('DPoP-Nonce')){nonce=response.headers.get('DPoP-Nonce');continue;}throw new Error(`Exchange HTTP ${response.status}`);}
    if(body.token_type!=='DPoP'||typeof body.access_token!=='string'||!(body.expires_in>0&&body.expires_in<=300))throw new Error('Unexpected constrained response');
    const apiURL=secureURL(required('ASTERIUS_API_URL')).href;
    const call=nonce=>fetch(apiURL,{redirect:'error',headers:{Authorization:`DPoP ${body.access_token}`,DPoP:proof('GET',apiURL,body.access_token,nonce)},signal:AbortSignal.timeout(5000)});
    let api=await call();
    if(api.status===401&&api.headers.has('DPoP-Nonce'))api=await call(api.headers.get('DPoP-Nonce'));
    if(!api.ok)throw new Error(`API HTTP ${api.status}`);
    return api;
  }
  throw new Error('Nonce exchange failed');
}
if(import.meta.url===`file://${process.argv[1]}`)await apiCall().then(response=>console.log(`API HTTP ${response.status}`));
