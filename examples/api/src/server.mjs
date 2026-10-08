import 'dotenv/config';
import express from 'express';
import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { OAuthRequests, verifyResourceProof, hasScope, sameOriginWrite } from './oauth.mjs';
import { createRemoteJWKSet, exportJWK, generateKeyPair, importJWK, jwtVerify, customFetch, calculateJwkThumbprint } from 'jose';

const app = express();
const port = Number(process.env.PORT || 4000);
const apiUrl = (process.env.API_URL || `http://localhost:${port}`).replace(/\/$/, '');
const webappUrl = process.env.WEBAPP_URL || 'http://localhost:5173';
const webappOrigin = new URL(webappUrl).origin;
const issuer = required('ISSUER');
const internalIssuer = process.env.OIDC_INTERNAL_ISSUER || issuer;
const clientId = required('CLIENT_ID');
const resource = process.env.RESOURCE || apiUrl;
const scopes = process.env.SCOPES || 'openid accounts:read accounts:write';
const sessions = new Map();
const transfers = [];
const accounts = new Map([
  ['checking', { id: 'checking', name: 'Everyday checking', currency: 'EUR', balance: 4250.75 }],
  ['savings', { id: 'savings', name: 'Rainy day savings', currency: 'EUR', balance: 12800.00 }],
]);

const clientJwk = JSON.parse(process.env.CLIENT_PRIVATE_KEY_JWK_FILE ? await readFile(process.env.CLIENT_PRIVATE_KEY_JWK_FILE, 'utf8') : required('CLIENT_PRIVATE_KEY_JWK'));
const clientKey = await importJWK(clientJwk, 'ES256');
const clientKid = process.env.CLIENT_KEY_ID || clientJwk.kid;
if (!clientKid || !clientJwk.d || clientJwk.kty !== 'EC' || clientJwk.crv !== 'P-256') throw new Error('ES256 private client key with kid is required');
const { privateKey: dpopPrivate, publicKey: dpopPublic } = await generateKeyPair('ES256');
const dpopJwk = await exportJWK(dpopPublic);
const dpopJkt = await calculateJwkThumbprint(dpopJwk);
const discovery = await getJson(`${internalIssuer}/.well-known/openid-configuration`, true);
if (discovery.issuer !== issuer) throw new Error('Discovery issuer mismatch');
const jwks = createRemoteJWKSet(new URL(discovery.jwks_uri), { [customFetch]: oidcFetch });
const oauth = new OAuthRequests({ issuer, clientId, clientKey, clientKid, dpopPrivate, dpopPublic, fetchImpl: oidcFetch });
const seenProofs = new Map();
const cookiePath = new URL(apiUrl).pathname || '/';

app.use(express.json({ limit: '32kb' }));
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', webappOrigin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Headers', 'content-type, authorization, dpop');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.get('/', (_req, res) => res.json({
  service: 'financial-example-api',
  status: 'ok',
  endpoints: ['/health', '/auth/start', '/api/accounts', '/api/transfers', '/resource/accounts'],
}));
app.get('/health', (_req, res) => res.json({ ok: true, service: 'financial-example-api' }));
app.get('/auth/start', async (_req, res) => {
  const state = random();
  const nonce = random();
  const verifier = random(48);
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const request = new URLSearchParams({ client_id: clientId, response_type: 'code', redirect_uri: `${apiUrl}/auth/callback`, scope: scopes, resource, code_challenge: challenge, code_challenge_method: 'S256', state, nonce });
  const par = await oauthPost(discovery.pushed_authorization_request_endpoint, request);
  sessions.set(state, { verifier, nonce, createdAt: Date.now() });
  res.setHeader('Set-Cookie', `financial_login=${state}; Path=${cookiePath}; HttpOnly; SameSite=Lax; Max-Age=600${process.env.COOKIE_SECURE === 'false' ? '' : '; Secure'}`);
  res.redirect(`${discovery.authorization_endpoint}?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(par.request_uri)}`);
});

app.get('/auth/callback', async (req, res) => {
  const pending = sessions.get(req.query.state);
  if (!pending || req.headers.cookie?.match(/(?:^|; )financial_login=([^;]+)/)?.[1] !== req.query.state || req.query.iss !== issuer || Date.now() - pending.createdAt > 10 * 60_000) return res.status(400).send('Invalid or expired OAuth state');
  sessions.delete(req.query.state);
  if (req.query.error) return res.status(400).send('Authorization was refused');
  const body = new URLSearchParams({ grant_type: 'authorization_code', code: req.query.code, redirect_uri: `${apiUrl}/auth/callback`, client_id: clientId, code_verifier: pending.verifier, resource });
  const token = await oauthPost(discovery.token_endpoint, body);
  const verified = await jwtVerify(token.id_token, jwks, { issuer, audience: clientId, algorithms: ['EdDSA', 'ES256', 'PS256'] });
  if (verified.payload.nonce !== pending.nonce || token.token_type?.toLowerCase() !== 'dpop') throw new Error('Invalid token response');
  const access = await jwtVerify(token.access_token, jwks, { issuer, audience: resource, algorithms: ['EdDSA', 'ES256', 'PS256'], typ: 'at+jwt' });
  if (access.payload.cnf?.jkt !== dpopJkt) throw new Error('Invalid access token binding');
  const sid = random();
  sessions.set(`sid:${sid}`, { ...token, claims: access.payload, createdAt: Date.now() });
  res.setHeader('Set-Cookie', sessionCookie(sid));
  res.redirect(webappUrl);
});

app.get('/api/session', async (req, res) => {
  const session = sessionFrom(req);
  let active = false;
  if (session) {
    try {
      const facts = await oauthPost(discovery.introspection_endpoint, new URLSearchParams({ token: session.access_token }));
      active = facts.active === true;
    } catch { /* Refusal or unavailable authority means the session is inactive. */ }
  }
  res.json({ authenticated: active, user: active ? session.claims.sub : null });
});
app.post('/auth/logout', async (req, res) => {
  if (!sameOriginWrite(req, webappOrigin)) return res.status(403).json({ error: 'csrf_refused' });
  const session = sessionFrom(req);
  if (session) for (const token of [session.refresh_token, session.access_token].filter(Boolean)) await oauthPost(discovery.revocation_endpoint, new URLSearchParams({ token }));
  const sid = req.headers.cookie?.match(/(?:^|; )financial_sid=([^;]+)/)?.[1];
  if (sid) sessions.delete(`sid:${sid}`);
  res.setHeader('Set-Cookie', `financial_sid=; Path=${cookiePath}; HttpOnly; SameSite=Lax; Max-Age=0${process.env.COOKIE_SECURE === 'false' ? '' : '; Secure'}`);
  res.status(204).end();
});

app.get('/api/accounts', requireSession, requireScope('accounts:read'), (_req, res) => res.json({ accounts: [...accounts.values()] }));
app.get('/api/transfers', requireSession, requireScope('accounts:read'), (_req, res) => res.json({ transfers }));
app.post('/api/transfers', requireSession, requireScope('accounts:write'), (req, res) => {
  if (!sameOriginWrite(req, webappOrigin)) return res.status(403).json({ error: 'csrf_refused' });
  const { from, to, amount, reference = '' } = req.body || {};
  if (!accounts.has(from) || !accounts.has(to) || from === to || !Number.isFinite(amount) || amount <= 0 || amount > accounts.get(from).balance) return res.status(400).json({ error: 'invalid_transfer' });
  accounts.get(from).balance -= amount;
  accounts.get(to).balance += amount;
  const transfer = { id: crypto.randomUUID(), from, to, amount, reference, createdAt: new Date().toISOString() };
  transfers.unshift(transfer);
  res.status(201).json(transfer);
});

// Direct protected-resource endpoint: send `Authorization: DPoP <access token>`
// and a valid DPoP proof to exercise the API-side token checks.
app.get('/resource/accounts', requireDpopToken, requireScope('accounts:read'), (_req, res) => res.json({ accounts: [...accounts.values()] }));

app.listen(port, '0.0.0.0', () => console.log(`Financial API listening on ${apiUrl}`));

function required(name) { if (!process.env[name]) throw new Error(`${name} is required`); return process.env[name]; }
function random(bytes = 32) { return crypto.randomBytes(bytes).toString('base64url'); }
function sessionCookie(sid) {
  const secure = process.env.COOKIE_SECURE !== 'false' ? '; Secure' : '';
  return `financial_sid=${sid}; Path=${cookiePath}; HttpOnly; SameSite=Lax; Max-Age=3600${secure}`;
}
async function getJson(url, oidc = false) {
  const response = await (oidc ? oidcFetch(url) : fetch(url));
  if (!response.ok) throw new Error(`Discovery failed: ${response.status}`);
  return response.json();
}
async function oauthPost(url, body) {
  return oauth.request(url, body);
}

async function oidcFetch(url, options = {}) {
  const publicUrl = new URL(issuer);
  const privateUrl = new URL(internalIssuer);
  let target = new URL(url);
  if (target.origin === publicUrl.origin) target = new URL(target.pathname + target.search, privateUrl);
  const headers = new Headers(options.headers);
  headers.set('host', publicUrl.host);
  headers.set('x-forwarded-host', publicUrl.host);
  headers.set('x-forwarded-proto', publicUrl.protocol.slice(0, -1));
  return retryFetch(() => fetch(target, { ...options, headers, redirect: 'error' }));
}
async function retryFetch(operation, attempts = 30) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try { return await operation(); }
    catch (error) { lastError = error; if (attempt + 1 < attempts) await new Promise((resolve) => setTimeout(resolve, 500)); }
  }
  throw lastError;
}
function sessionFrom(req) { const sid = req.headers.cookie?.match(/(?:^|; )financial_sid=([^;]+)/)?.[1]; return sid ? sessions.get(`sid:${sid}`) : null; }
async function requireSession(req, res, next) {
  const session = sessionFrom(req);
  if (!session) return res.status(401).json({ error: 'login_required' });
  try {
    const verified = await jwtVerify(session.access_token, jwks, { issuer, audience: resource, algorithms: ['EdDSA', 'ES256', 'PS256'], typ: 'at+jwt' });
    const facts = await oauthPost(discovery.introspection_endpoint, new URLSearchParams({ token: session.access_token }));
    if (facts.active !== true || verified.payload.cnf?.jkt !== dpopJkt) throw new Error('inactive token');
    req.token = verified.payload;
    req.session = session;
    next();
  } catch { res.status(401).json({ error: 'session_expired_or_revoked' }); }
}
function requireScope(scope) {
  return (req, res, next) => hasScope(req.token, scope) ? next() : res.status(403).json({ error: 'insufficient_scope' });
}
async function requireDpopToken(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    if (!header.startsWith('DPoP ') || !req.headers.dpop) throw new Error('DPoP required');
    const token = header.slice(5);
    req.token = await verifyResourceProof({ proof: req.headers.dpop, token, method: req.method, url: `${apiUrl}${req.originalUrl}`, keys: jwks, issuer, resource, seen: seenProofs });
    const facts = await oauthPost(discovery.introspection_endpoint, new URLSearchParams({ token }));
    if (facts.active !== true) throw new Error('inactive token');
    next();
  } catch { res.status(401).set('WWW-Authenticate', 'DPoP error="invalid_token"').json({ error: 'invalid_token' }); }
}

app.use((_error, _req, res, _next) => res.status(502).json({ error: 'upstream_request_refused' }));
