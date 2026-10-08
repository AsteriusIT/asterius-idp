import assert from 'node:assert/strict';
import test from 'node:test';
import { cookies, escapeHtml, sessionCookie } from './demo.mjs';

test('session cookies are host-safe and cross-site resistant', () => {
  assert.equal(sessionCookie('demo_a', 'session', '/demo-a', true), 'demo_a=session; Path=/demo-a; HttpOnly; SameSite=Lax; Secure');
  assert.deepEqual(cookies('a=1; demo_a=abc'), { a: '1', demo_a: 'abc' });
});

test('dynamic claims are escaped before rendering', () => {
  assert.equal(escapeHtml('<script>"x" & y</script>'), '&lt;script&gt;&quot;x&quot; &amp; y&lt;/script&gt;');
});

import { OidcClient, startDemo } from './demo.mjs';
import { decodeJwt, exportJWK, generateKeyPair, SignJWT } from 'jose';

async function configured(fetchImpl) {
  const pair = await generateKeyPair('ES256', { extractable: true });
  const key = { ...(await exportJWK(pair.privateKey)), kid: 'owned-test-key' };
  const issuer = 'https://idp.example/t/demo';
  const client = new OidcClient({ issuer, internalIssuer: 'http://idp:9443/t/demo', externalUrl: 'https://apps.example/demo-a', name: 'A', clientId: 'fixture-client', clientPrivateJwk: key, fetchImpl });
  await client.initialise();
  return client;
}
const discovery = { issuer: 'https://idp.example/t/demo', jwks_uri: 'https://idp.example/t/demo/jwks', token_endpoint: 'https://idp.example/t/demo/token', pushed_authorization_request_endpoint: 'https://idp.example/t/demo/par', authorization_endpoint: 'https://idp.example/t/demo/authorize' };

test('configured confidential client starts with closed registration and verifies issuer', async () => {
  let calls = 0;
  const client = await configured(async () => { calls++; return Response.json(discovery); });
  assert.equal(client.clientId, 'fixture-client');
  assert.equal(calls, 1);
  await assert.rejects(configured(async () => Response.json({ ...discovery, issuer: 'https://other.example/t/demo' })), /issuer mismatch/);
});

test('nonce retry signs a fresh proof and client assertion and is bounded', async () => {
  const requests = [];
  const client = await configured(async (url, options) => {
    if (String(url).includes('well-known')) return Response.json(discovery);
    requests.push({ proof: decodeJwt(options.headers.get('dpop')), assertion: decodeJwt(new URLSearchParams(options.body).get('client_assertion')) });
    return requests.length === 1 ? Response.json({ error: 'use_dpop_nonce' }, { status: 400, headers: { 'DPoP-Nonce': 'issuer-nonce' } }) : Response.json({ access_token: 'fixture', token_type: 'DPoP' });
  });
  const key = await generateKeyPair('ES256', { extractable: true });
  await client.token(new URLSearchParams({ grant_type: 'client_credentials' }), key);
  assert.equal(requests.length, 2);
  assert.equal(requests[0].proof.nonce, undefined);
  assert.equal(requests[1].proof.nonce, 'issuer-nonce');
  assert.notEqual(requests[0].proof.jti, requests[1].proof.jti);
  assert.notEqual(requests[0].assertion.jti, requests[1].assertion.jti);
  assert.equal(decodeJwt(await client.proof(key, 'GET', 'https://resource.example/accounts')).nonce, undefined);
  let attempts = 0;
  client.fetch = async () => { attempts++; return Response.json({ error: 'use_dpop_nonce' }, { status: 400, headers: { 'DPoP-Nonce': 'again' } }); };
  await assert.rejects(client.token(new URLSearchParams(), key), /failed \(400\)/);
  assert.equal(attempts, 2);
});

test('ID token verification obtains keys over the configured internal transport', async () => {
  const signer = await generateKeyPair('ES256', { extractable: true });
  const publicKey = { ...(await exportJWK(signer.publicKey)), kid: 'issuer-key', alg: 'ES256', use: 'sig' };
  const paths = [];
  const client = await configured(async (url) => { paths.push(String(url)); return Response.json(String(url).endsWith('/jwks') ? { keys: [publicKey] } : discovery); });
  const token = await new SignJWT({ nonce: 'browser-nonce' }).setProtectedHeader({ alg: 'ES256', kid: 'issuer-key' }).setIssuer(discovery.issuer).setAudience(client.clientId).setIssuedAt().setExpirationTime('1m').sign(signer.privateKey);
  await client.verifyIdToken(token, 'browser-nonce');
  assert(paths.includes('http://idp:9443/t/demo/jwks'));
  await assert.rejects(client.verifyIdToken(token, 'other-nonce'), /nonce mismatch/);
});

test('HTTP callback binds configured app cookie, state and issuer before handling an authorization refusal', async (t) => {
  const issuer = discovery.issuer;
  let flows = 0;
  t.mock.method(OidcClient.prototype, 'initialise', async function () {
    this.discovery = discovery;
    this.clientId = 'owned-fixture';
  });
  t.mock.method(OidcClient.prototype, 'begin', async () => ({
    state: `owned-state-${++flows}`, authorize: `${issuer}/authorize`, nonce: 'owned-nonce',
  }));
  t.mock.method(OidcClient.prototype, 'redeem', async () => { assert.fail('A refused authorization must never redeem a code'); });
  const cookieName = 'asterius_playground_demo_a';
  const server = await startDemo({ PORT: '0', BIND: '127.0.0.1', ISSUER: issuer,
    EXTERNAL_URL: 'https://apps.example/demo-a', COOKIE_NAME: cookieName });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}/demo-a`;
  const start = async () => {
    const response = await fetch(`${base}/login`, { redirect: 'manual' });
    assert.equal(response.status, 303);
    const cookie = response.headers.get('set-cookie');
    assert.match(cookie, /^asterius_playground_demo_a_login=owned-state-\d+; Path=\/demo-a; HttpOnly; SameSite=Lax; Secure; Max-Age=600$/);
    return { cookie: cookie.split(';')[0], state: `owned-state-${flows}` };
  };
  const callback = (flow, cookie, responseIssuer = issuer) => fetch(`${base}/callback?${new URLSearchParams({
    state: flow.state, error: 'login_required', ...(responseIssuer ? { iss: responseIssuer } : {}),
  })}`, { redirect: 'manual', headers: cookie ? { cookie } : {} });
  for (const cookie of [undefined, 'asterius_playground_demo_b_login=owned-state-1']) {
    const flow = await start();
    assert.equal((await callback(flow, cookie)).status, 500);
  }
  for (const wrongIssuer of ['', 'https://other.example/t/demo']) {
    const flow = await start();
    assert.equal((await callback(flow, flow.cookie, wrongIssuer)).status, 500);
  }
  const flow = await start();
  const accepted = await callback(flow, `other_app=ignored; ${flow.cookie}`);
  assert.equal(accepted.status, 303);
  assert.equal(accepted.headers.get('location'), 'https://apps.example/demo-a');
  assert.match(accepted.headers.get('set-cookie'), /^asterius_playground_demo_a=;/);
  assert.equal((await callback(flow, flow.cookie)).status, 500, 'consumed flow cannot be replayed');
});
