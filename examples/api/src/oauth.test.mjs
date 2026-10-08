import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { calculateJwkThumbprint, decodeJwt, exportJWK, generateKeyPair, SignJWT } from 'jose';
import { OAuthRequests, verifyResourceProof, hasScope, sameOriginWrite, cookieValue } from './oauth.mjs';

test('financial OAuth nonce challenge retries exactly once with fresh signed assertions', async () => {
  const key = await generateKeyPair('ES256');
  const requests = [];
  const client = new OAuthRequests({ issuer: 'https://idp.example/t/demo', clientId: 'owned-client', clientKid: 'key', clientKey: key.privateKey, dpopPrivate: key.privateKey, dpopPublic: key.publicKey,
    fetchImpl: async (_url, options) => {
      requests.push({ proof: decodeJwt(options.headers.DPoP), assertion: decodeJwt(options.body.get('client_assertion')) });
      return requests.length === 1 ? Response.json({ error: 'use_dpop_nonce' }, { status: 400, headers: { 'dpop-nonce': 'issuer-nonce' } }) : Response.json({ active: true });
    } });
  await client.request('https://idp.example/t/demo/introspect', new URLSearchParams({ token: 'fixture' }));
  assert.equal(requests.length, 2);
  assert.equal(requests[1].proof.nonce, 'issuer-nonce');
  assert.notEqual(requests[0].proof.jti, requests[1].proof.jti);
  assert.notEqual(requests[0].assertion.jti, requests[1].assertion.jti);
});

test('resource verifier checks token hash, key, target and replay using actual signatures', async () => {
  const as = await generateKeyPair('EdDSA');
  const dpop = await generateKeyPair('ES256');
  const jwk = await exportJWK(dpop.publicKey);
  const issuer = 'https://idp.example/t/demo', resource = 'https://apps.example/financial-api';
  const token = await new SignJWT({ cnf: { jkt: await calculateJwkThumbprint(jwk) }, scope: 'accounts:read' }).setProtectedHeader({ alg: 'EdDSA', typ: 'at+jwt' }).setIssuer(issuer).setAudience(resource).setIssuedAt().setExpirationTime('1m').sign(as.privateKey);
  const proof = async (claims = {}) => new SignJWT({ htm: 'GET', htu: resource + '/resource/accounts', ath: createHash('sha256').update(token).digest('base64url'), jti: 'owned-proof', ...claims }).setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk }).setIssuedAt().sign(dpop.privateKey);
  const options = { token, method: 'GET', url: resource + '/resource/accounts?view=summary', keys: as.publicKey, issuer, resource, seen: new Map() };
  await assert.rejects(verifyResourceProof({ ...options, proof: await proof({ ath: 'wrong-token-hash' }) }), /wrong proof/);
  const signed = await proof();
  const claims = await verifyResourceProof({ ...options, proof: signed });
  assert(hasScope(claims, 'accounts:read'));
  assert(!hasScope(claims, 'accounts:write'));
  await assert.rejects(verifyResourceProof({ ...options, proof: signed }), /replayed/);
  await assert.rejects(verifyResourceProof({ ...options, proof: await proof({ jti: 'other', htm: 'POST' }) }), /wrong proof/);
});

test('financial logout accepts the RFC 7009 empty success response', async () => {
  const key = await generateKeyPair('ES256');
  const client = new OAuthRequests({ issuer: 'https://idp.example/t/demo', clientId: 'owned-client', clientKid: 'key', clientKey: key.privateKey, dpopPrivate: key.privateKey, dpopPublic: key.publicKey,
    fetchImpl: async () => new Response(null, { status: 200 }) });
  assert.deepEqual(await client.request('https://idp.example/t/demo/revoke', new URLSearchParams({ token: 'fixture' })), {});
});

test('browser write controls reject cross-site, missing-origin and non-JSON writes', () => {
  const origin = 'https://apps.example';
  assert(sameOriginWrite({ headers: { origin, 'content-type': 'application/json' } }, origin));
  assert(!sameOriginWrite({ headers: { origin: 'https://attacker.example', 'content-type': 'application/json' } }, origin));
  assert(!sameOriginWrite({ headers: { 'content-type': 'application/json' } }, origin));
  assert(!sameOriginWrite({ headers: { origin, 'content-type': 'text/plain' } }, origin));
});

test('financial cookie parsing isolates applications on the same host and refuses ambiguous cookies', () => {
  const header = 'financial_sid=old-app; asterius_session=idp;asterius_playground_financial=new-app; asterius_playground_financial_login=owned-state';
  assert.equal(cookieValue(header, 'asterius_playground_financial'), 'new-app');
  assert.equal(cookieValue(header, 'asterius_playground_financial_login'), 'owned-state');
  assert.equal(cookieValue(header, 'financial_sid'), 'old-app');
  assert.equal(cookieValue(header, 'playground_financial'), undefined);
  assert.equal(cookieValue(undefined, 'asterius_playground_financial'), undefined);
  assert.equal(cookieValue('asterius_playground_financial=one; asterius_playground_financial=two', 'asterius_playground_financial'), undefined);
});
