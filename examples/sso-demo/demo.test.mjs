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
  const missingCode = await start();
  assert.equal((await fetch(`${base}/callback?${new URLSearchParams({ state: missingCode.state, iss: issuer })}`,
    { redirect: 'manual', headers: { cookie: missingCode.cookie } })).status, 500, 'a successful callback requires a code');
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
  assert.equal(accepted.status, 401);
  assert.match(await accepted.text(), /identity provider refused/);
  assert.match(accepted.headers.get('set-cookie'), /^asterius_playground_demo_a=;/);
  assert.equal((await callback(flow, flow.cookie)).status, 500, 'consumed flow cannot be replayed');
});

test('HTTP SSO action journeys return canonical home and show actual outcomes once', async (t) => {
  let sequence = 0, refreshRefused = false, userInfoRefused = false, refreshSubject = 'owned-subject', refreshType = 'DPoP';
  const issuer = discovery.issuer, external = 'https://apps.example/demo-b';
  const dpop = { privateKey: 'owned-private-fixture', publicKey: 'owned-public-fixture' };
  t.mock.method(OidcClient.prototype, 'initialise', async function () { this.discovery = discovery; this.clientId = 'owned'; });
  t.mock.method(OidcClient.prototype, 'begin', async () => ({ state: `journey-${++sequence}`, nonce: 'owned-nonce', dpop, authorize: `${issuer}/authorize` }));
  t.mock.method(OidcClient.prototype, 'redeem', async () => ({ id_token: 'private-fixture-token', access_token: 'owned-access', refresh_token: 'owned-refresh' }));
  t.mock.method(OidcClient.prototype, 'verifyIdToken', async (token, nonce) => {
    if (token === 'refreshed-id-token') {
      assert.equal(nonce, undefined, 'refresh ID token has no new nonce');
      return { sub: refreshSubject };
    }
    return { sub: 'owned-subject', nonce: 'owned-nonce', acr: 'urn:asterius:acr:passkey' };
  });
  t.mock.method(OidcClient.prototype, 'refresh', async (session) => {
    assert.equal(session.dpop, dpop, 'refresh retains the original sender key');
    if (refreshRefused) throw new Error('private OAuth error must not be exposed');
    return { access_token: 'refreshed-access', refresh_token: 'rotated-refresh', token_type: refreshType, id_token: 'refreshed-id-token' };
  });
  t.mock.method(OidcClient.prototype, 'userInfo', async (session) => {
    assert.equal(session.dpop, dpop);
    if (userInfoRefused) throw new Error('private UserInfo error must not be exposed');
    return { sub: 'owned-subject' };
  });
  const server = await startDemo({ PORT: '0', BIND: '127.0.0.1', ISSUER: issuer, EXTERNAL_URL: external, COOKIE_NAME: 'owned_demo_b' });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}/demo-b`;
  const request = (path, cookie) => fetch(base + path, { redirect: 'manual', headers: cookie ? { cookie } : {} });
  const finish = async (path, sessionCookie, error) => {
    const started = await request(path, sessionCookie);
    assert.equal(started.status, 303);
    const loginCookie = started.headers.get('set-cookie').split(';')[0];
    const parameters = new URLSearchParams({ state: `journey-${sequence}`, iss: issuer, ...(error ? { error } : { code: 'owned-code' }) });
    return request(`/callback?${parameters}`, [sessionCookie, loginCookie].filter(Boolean).join('; '));
  };
  for (const path of ['/refresh', '/check-session', '/reauth', '/step-up', '/logout']) {
    const refused = await request(path);
    assert.equal(refused.status, 401);
    assert.match(await refused.text(), /requires an application session/);
  }
  assert.equal((await request('/unknown-action')).status, 404);
  const signedIn = await finish('/login');
  assert.equal(signedIn.headers.get('location'), external + '/');
  const cookie = signedIn.headers.get('set-cookie').split(';')[0];
  assert.match(await (await request('/', cookie)).text(), /Sign-in completed/);
  assert.doesNotMatch(await (await request('/', cookie)).text(), /Sign-in completed/);
  const refreshed = await request('/refresh', cookie);
  assert.equal(refreshed.headers.get('location'), external + '/');
  assert.match(await (await request('/', cookie)).text(), /Tokens refreshed successfully/);
  refreshSubject = 'other-subject';
  assert.equal((await request('/refresh', cookie)).status, 502, 'refresh cannot change authenticated subject');
  refreshSubject = 'owned-subject';
  refreshType = 'Bearer';
  assert.equal((await request('/refresh', cookie)).status, 502, 'refresh cannot silently drop sender binding');
  refreshType = 'DPoP';
  for (const [path, outcome] of [['/check-session', 'confirmed your session'], ['/reauth', 'Reauthentication completed'], ['/step-up', 'Passkey step-up completed']]) {
    const completed = await finish(path, cookie);
    assert.equal(completed.headers.get('location'), external + '/');
    assert.match(await (await request('/', cookie)).text(), new RegExp(outcome));
  }
  refreshRefused = true;
  const failedRefresh = await request('/refresh', cookie);
  assert.equal(failedRefresh.status, 502);
  const failureBody = await failedRefresh.text();
  assert.match(failureBody, /No successful refresh was confirmed/);
  assert.doesNotMatch(failureBody, /private OAuth error/);
  const refused = await finish('/check-session', cookie, 'login_required');
  assert.equal(refused.status, 401);
  assert.match(await refused.text(), /did not confirm an active session/);
  assert.equal((await request('/refresh', cookie)).status, 401);
  const again = await finish('/login');
  userInfoRefused = true;
  const unavailable = await request('/', again.headers.get('set-cookie').split(';')[0]);
  assert.equal(unavailable.status, 401);
  assert.match(await unavailable.text(), /UserInfo could not confirm/);
  assert.match(unavailable.headers.get('set-cookie'), /Max-Age=0/);
});
