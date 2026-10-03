import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, createPublicKey, verify, createHash } from 'node:crypto';

test('fresh GitHub audience assertions remain separate from client authentication and DPoP',async()=>{
  const directory=mkdtempSync(join(tmpdir(),'github-workload-'));
  const {privateKey,publicKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const keyFile=join(directory,'client.pem');writeFileSync(keyFile,privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});
  const previousEnvironment={...process.env};
  Object.assign(process.env,{ASTERIUS_ISSUER:'https://id.example/t/ci',ASTERIUS_RESOURCE:'https://api.example/',ASTERIUS_API_URL:'https://api.example/status',ASTERIUS_CLIENT_ID:'workflow',ASTERIUS_CLIENT_KID:'key',ASTERIUS_CLIENT_KEY_FILE:keyFile,ASTERIUS_WORKLOAD_AUDIENCE:'urn:asterius:workload:ci:github',ASTERIUS_SCOPE:'inventory.read',ASTERIUS_ACTIONS:'read',ACTIONS_ID_TOKEN_REQUEST_URL:'https://run-actions.githubusercontent.com/token?api-version=2',ACTIONS_ID_TOKEN_REQUEST_TOKEN:'runtime-credential'});
  const originalFetch=globalThis.fetch;let acquisitions=0,exchanges=0,calls=0;
  const check=(token,key)=>{const parts=token.split('.');assert(verify('sha256',Buffer.from(parts.slice(0,2).join('.')),{key,dsaEncoding:'ieee-p1363'},Buffer.from(parts[2],'base64url')));return JSON.parse(Buffer.from(parts[1],'base64url'));};
  globalThis.fetch=async(url,options)=>{
    assert.equal(options.redirect,'error');
    if(String(url).includes('run-actions.githubusercontent.com')){
      acquisitions++;assert.equal(new URL(url).searchParams.get('audience'),'urn:asterius:workload:ci:github');assert.equal(options.headers.Authorization,'Bearer runtime-credential');
      return new Response(JSON.stringify({value:`subject-${acquisitions===2?1:acquisitions}`}));
    }
    const header=JSON.parse(Buffer.from(options.headers.DPoP.split('.')[0],'base64url'));
    const claims=check(options.headers.DPoP,createPublicKey({key:header.jwk,format:'jwk'}));
    assert.equal(claims.htu,String(url));
    if(String(url).endsWith('/token')){
      exchanges++;const form=options.body;
      assert.equal(form.get('subject_token'),`subject-${exchanges===1?1:3}`);
      assert.equal(form.get('client_secret'),null);
      const authenticated=check(form.get('client_assertion'),publicKey);
      assert.equal(authenticated.sub,'workflow');assert.equal(authenticated.aud,'https://id.example/t/ci');
      assert.notEqual(form.get('client_assertion'),form.get('subject_token'));
      if(exchanges===1)return new Response(JSON.stringify({error:'use_dpop_nonce'}),{status:400,headers:{'DPoP-Nonce':'mint-nonce'}});
      assert.equal(claims.nonce,'mint-nonce');
      return new Response(JSON.stringify({access_token:'bound-access',token_type:'DPoP',expires_in:300}));
    }
    calls++;assert.equal(options.headers.Authorization,'DPoP bound-access');assert.equal(claims.ath,createHash('sha256').update('bound-access').digest('base64url'));
    if(calls===1)return new Response('',{status:401,headers:{'DPoP-Nonce':'api-nonce'}});
    assert.equal(claims.nonce,'api-nonce');return new Response('permitted');
  };
  try{const {apiCall}=await import('./client.mjs');assert.equal((await apiCall()).status,200);assert.equal(acquisitions,3);assert.equal(exchanges,2);assert.equal(calls,2);}finally{globalThis.fetch=originalFetch;for(const key of Object.keys(process.env))if(!(key in previousEnvironment))delete process.env[key];Object.assign(process.env,previousEnvironment);rmSync(directory,{recursive:true,force:true});}
});
