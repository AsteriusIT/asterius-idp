import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, verify, createPublicKey } from 'node:crypto';
import { EventEmitter } from 'node:events';
import https from 'node:https';

test('fresh bound TokenRequest, rotated projected credential and DPoP nonces', async () => {
  const dir=mkdtempSync(join(tmpdir(),'workload-client-'));
  const {privateKey,publicKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const tokenFile=join(dir,'kube-token');const keyFile=join(dir,'client.pem');const caFile=join(dir,'ca.crt');
  writeFileSync(tokenFile,'projected-api-one');writeFileSync(keyFile,privateKey.export({type:'pkcs8',format:'pem'}));writeFileSync(caFile,'mock-ca');
  const previous={...process.env};
  Object.assign(process.env,{ASTERIUS_ISSUER:'https://id.example/acme',ASTERIUS_RESOURCE:'https://api.example/',ASTERIUS_API_URL:'https://api.example/items',ASTERIUS_CLIENT_ID:'client',ASTERIUS_CLIENT_KID:'key',ASTERIUS_CLIENT_KEY_FILE:keyFile,ASTERIUS_WORKLOAD_AUDIENCE:'urn:asterius:workload:acme:inventory',ASTERIUS_SCOPE:'read',ASTERIUS_ACTIONS:'read',KUBERNETES_SERVICE_HOST:'kube.example',KUBERNETES_API_TOKEN_FILE:tokenFile,KUBERNETES_CA_FILE:caFile,POD_NAMESPACE:'apps',SERVICE_ACCOUNT:'inventory',POD_NAME:'pod',POD_UID:'uid'});
  const originalRequest=https.request;const originalFetch=globalThis.fetch;
  let requests=0;let exchanges=0;let calls=0;
  const checkJWT=(token,key)=>{const parts=token.split('.');assert(verify('sha256',Buffer.from(parts.slice(0,2).join('.')),{key,dsaEncoding:'ieee-p1363'},Buffer.from(parts[2],'base64url')));return JSON.parse(Buffer.from(parts[1],'base64url'));};
  https.request=(options, callback)=>{
    assert.equal(options.headers.Authorization,`Bearer projected-api-${requests===0?'one':'two'}`);
    assert.equal(options.path,'/api/v1/namespaces/apps/serviceaccounts/inventory/token');
    const request=new EventEmitter();
    request.end=raw=>{
      const body=JSON.parse(raw);assert.deepEqual(body.spec.audiences,['urn:asterius:workload:acme:inventory']);assert.equal(body.spec.boundObjectRef.uid,'uid');assert.equal(body.spec.boundObjectRef.kind,'Pod');
      const response=new EventEmitter();response.statusCode=201;response.destroy=error=>response.emit('error',error);callback(response);
      requests++;writeFileSync(tokenFile,'projected-api-two');
      queueMicrotask(()=>{response.emit('data',Buffer.from(JSON.stringify({status:{token:`fresh-subject-${requests===2?1:requests}`}})));response.emit('end');});
    };return request;
  };
  globalThis.fetch=async (url,options)=>{
    assert.equal(options.redirect,'error');
    const proof=options.headers.DPoP;const header=JSON.parse(Buffer.from(proof.split('.')[0],'base64url'));const claims=checkJWT(proof,createPublicKey({key:header.jwk,format:'jwk'}));
    assert.equal(claims.htu,url);
    if(url.endsWith('/token')) {
      exchanges++;const form=options.body;assert.equal(form.get('subject_token'),`fresh-subject-${exchanges===1?1:3}`);
      assert.equal(form.get('client_secret'),null);
      const client=checkJWT(form.get('client_assertion'),publicKey);assert.equal(client.sub,'client');assert.equal(client.aud,'https://id.example/acme');
      if(exchanges===1)return new Response(JSON.stringify({error:'use_dpop_nonce'}),{status:400,headers:{'DPoP-Nonce':'mint-nonce'}});
      assert.equal(claims.nonce,'mint-nonce');
      return new Response(JSON.stringify({token_type:'DPoP',access_token:'api-token',expires_in:300}),{status:200});
    }
    calls++;assert.equal(options.headers.Authorization,'DPoP api-token');assert(claims.ath);
    if(calls===1)return new Response('',{status:401,headers:{'DPoP-Nonce':'api-nonce'}});
    assert.equal(claims.nonce,'api-nonce');return new Response('ok',{status:200});
  };
  try {
    const {apiCall}=await import('./client.mjs');const reply=await apiCall();assert.equal(reply.status,200);assert.equal(requests,3);assert.equal(exchanges,2);assert.equal(calls,2);
  } finally {https.request=originalRequest;globalThis.fetch=originalFetch;for(const name of Object.keys(process.env))if(!(name in previous))delete process.env[name];Object.assign(process.env,previous);rmSync(dir,{recursive:true,force:true});}
});
