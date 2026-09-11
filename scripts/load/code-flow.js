// The whole authorization code journey under load: PAR, /authorize, password
// sign-in, consent, token — with `private_key_jwt`, PKCE and DPoP throughout.
//
//     k6 run --vus 16 --duration 60s scripts/load/code-flow.js
//
// One iteration is one person signing in to one client: four HTTP requests
// through the browser's half and two client-authenticated ones (PAR, token).
// The cookie jar is emptied at the start of every iteration, so each
// one pays the Argon2id verification of the password rather than riding an
// existing session — set KEEP_SESSION=1 to measure the other shape.
//
// Four browser requests, not five: a verified password answers with the
// consent screen directly, so there is no separate GET for it.
//
// The same DPoP key pins the pushed request and redeems the code (RFC 9449
// §10.1), which is what a real client does and what the code-issuance path
// checks.

import { check, fail } from 'k6';
import http from 'k6/http';
import { Trend } from 'k6/metrics';
import {
  CLIENT_ASSERTION_TYPE,
  b64url,
  clientAssertion,
  configFromEnv,
  dpopProof,
  generateDpopKey,
  importClientKey,
  jti,
  urlPath,
} from './lib.js';

const keyDer = open(__ENV.CLIENT_KEY || `${__ENV.LOAD_DIR || '.'}/client-key.der`, 'b');

const REDIRECT_URI = __ENV.REDIRECT_URI || 'https://rp.example/cb';
const USERNAME = __ENV.USERNAME || 'load-user';
const PASSWORD = __ENV.PASSWORD || __ENV.ASTERIUS_ADMIN_PASSWORD;

export const options = {
  thresholds: {
    checks: [{ threshold: 'rate>0.99', abortOnFail: true, delayAbortEval: '5s' }],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

const parLatency = new Trend('par_duration', true);
const authorizeLatency = new Trend('authorize_duration', true);
const signInLatency = new Trend('sign_in_duration', true);
const consentLatency = new Trend('consent_duration', true);
const tokenLatency = new Trend('token_duration', true);

let cfg;
let dpop;

function csrfOf(html) {
  const match = /name="csrf" value="([^"]+)"/.exec(html);
  if (!match) {
    fail(`no csrf field in the page:\n${html.slice(0, 400)}`);
  }
  return match[1];
}

function parameterOf(url, name) {
  const match = new RegExp(`[?&]${name}=([^&#]*)`).exec(url);
  return match ? decodeURIComponent(match[1]) : null;
}

async function pkce() {
  const raw = new Uint8Array(32);
  crypto.getRandomValues(raw);
  const verifier = b64url(raw);
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return { verifier, challenge: b64url(new Uint8Array(digest)) };
}

export default async function () {
  if (!cfg) {
    if (!PASSWORD) {
      fail('set PASSWORD (or ASTERIUS_ADMIN_PASSWORD, which seed.sql copies onto the load user)');
    }
    cfg = configFromEnv(await importClientKey(keyDer));
    dpop = await generateDpopKey();
  }
  if (!__ENV.KEEP_SESSION) {
    // The session cookie is scoped to the tenant's path, so the URL handed
    // to `clear` has to be under it.
    http.cookieJar().clear(`${cfg.base}${urlPath(cfg.issuer)}/authorize`);
  }
  const headers = { Host: cfg.host };

  // 1. RFC 9126: push the request, pinned to this VU's DPoP key.
  const { verifier, challenge } = await pkce();
  const parUrl = `${cfg.issuer}/par`;
  const [assertion, parProof] = await Promise.all([
    clientAssertion(cfg.clientId, cfg.issuer, cfg.kid, cfg.clientKey),
    dpopProof(dpop, 'POST', parUrl),
  ]);
  const pushed = http.post(
    cfg.base + urlPath(parUrl),
    {
      client_id: cfg.clientId,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: assertion,
      response_type: 'code',
      redirect_uri: REDIRECT_URI,
      scope: 'openid',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state: jti('state'),
      nonce: jti('nonce'),
    },
    { headers: { ...headers, DPoP: parProof }, tags: { name: 'par' } },
  );
  parLatency.add(pushed.timings.duration);
  if (!check(pushed, { 'par accepted (201)': (r) => r.status === 201 })) {
    return console.error(`par ${pushed.status} ${pushed.body}`);
  }
  const requestUri = pushed.json('request_uri');

  // 2. The browser arrives with the reference and is sent into an interaction.
  const arrived = http.get(
    `${cfg.base}${urlPath(cfg.issuer)}/authorize?client_id=${encodeURIComponent(cfg.clientId)}&request_uri=${encodeURIComponent(requestUri)}`,
    { headers, redirects: 0, tags: { name: 'authorize' } },
  );
  authorizeLatency.add(arrived.timings.duration);
  if (!check(arrived, { 'authorize starts an interaction (303)': (r) => r.status === 303 })) {
    return console.error(`authorize ${arrived.status} ${arrived.body}`);
  }
  const interaction = cfg.base + arrived.headers.Location;

  // 3. The login page, then the password.
  const login = http.get(interaction, { headers, tags: { name: 'login-page' } });
  if (!check(login, { 'login page (200)': (r) => r.status === 200 })) {
    return console.error(`login page ${login.status}`);
  }
  const signedIn = http.post(
    interaction,
    { csrf: csrfOf(login.body), username: USERNAME, password: PASSWORD },
    { headers, redirects: 0, tags: { name: 'sign-in' } },
  );
  signInLatency.add(login.timings.duration + signedIn.timings.duration);
  // A verified password answers with the consent screen in the same response
  // (200); when the person has already granted this client what it asks for,
  // consent is skipped and the answer is the authorization response itself
  // (303 to the redirect URI, OIDC Core §3.1.2.4). A refused password
  // re-renders the login form, which has no decision to make.
  let back = signedIn.status === 303 ? signedIn.headers.Location : null;
  let consentPage = signedIn.status === 200 ? signedIn : null;
  if (back && !back.startsWith(REDIRECT_URI)) {
    consentPage = http.get(cfg.base + back, { headers, tags: { name: 'consent-page' } });
    back = null;
  }
  if (!check(signedIn, { 'password accepted': () => back !== null || (consentPage.status === 200 && consentPage.body.includes('name="decision"')) })) {
    return console.error(`sign-in ${signedIn.status} ${(consentPage ? consentPage.body : signedIn.body).slice(0, 300)}`);
  }

  // 4. Consent, approved in full, and the code it redirects with.
  if (consentPage) {
    const decided = http.post(
      interaction,
      { csrf: csrfOf(consentPage.body), decision: 'allow', scope: 'openid' },
      { headers, redirects: 0, tags: { name: 'consent' } },
    );
    consentLatency.add(decided.timings.duration);
    if (!check(decided, { 'consent answered (303)': (r) => r.status === 303 })) {
      return console.error(`consent ${decided.status} ${decided.body.slice(0, 300)}`);
    }
    back = decided.headers.Location;
  }
  const code = parameterOf(back, 'code');
  if (!check(back, { 'a code came back to the redirect URI': (b) => b.startsWith(REDIRECT_URI) && code })) {
    return console.error(`authorization response ${back}`);
  }

  // 5. RFC 6749 §4.1.3: redeem the code under the pinned key.
  const tokenUrl = `${cfg.issuer}/token`;
  const [redeemAssertion, tokenProof] = await Promise.all([
    clientAssertion(cfg.clientId, cfg.issuer, cfg.kid, cfg.clientKey),
    dpopProof(dpop, 'POST', tokenUrl),
  ]);
  const redeemed = http.post(
    cfg.base + urlPath(tokenUrl),
    {
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
      client_id: cfg.clientId,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: redeemAssertion,
    },
    { headers: { ...headers, DPoP: tokenProof }, tags: { name: 'token' } },
  );
  tokenLatency.add(redeemed.timings.duration);
  check(redeemed, {
    'code redeemed (200)': (r) => r.status === 200,
    'an ID token came back': (r) => r.status === 200 && typeof r.json('id_token') === 'string',
  }) || console.error(`token ${redeemed.status} ${redeemed.body}`);
}
