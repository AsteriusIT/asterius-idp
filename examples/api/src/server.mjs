import 'dotenv/config';
import express from 'express';
import crypto from 'node:crypto';
import { createRemoteJWKSet, exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT, calculateJwkThumbprint } from 'jose';

const app = express();
const port = Number(process.env.PORT || 4000);
const apiUrl = process.env.API_URL || `http://localhost:${port}`;
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

const clientKey = await importJWK(JSON.parse(required('CLIENT_PRIVATE_KEY_JWK')), 'ES256');
const { privateKey: dpopPrivate, publicKey: dpopPublic } = await generateKeyPair('ES256');
const dpopJwk = await exportJWK(dpopPublic);
const dpopJkt = await calculateJwkThumbprint(dpopJwk);
const discovery = await getJson(`${internalIssuer}/.well-known/openid-configuration`, true);
const jwks = createRemoteJWKSet(new URL(discovery.jwks_uri));

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
  const verifier = random(48);
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const request = new URLSearchParams({ client_id: clientId, response_type: 'code', redirect_uri: `${apiUrl}/auth/callback`, scope: scopes, resource, code_challenge: challenge, code_challenge_method: 'S256', state });
  const par = await oauthPost(discovery.pushed_authorization_request_endpoint, request);
  sessions.set(state, { verifier, createdAt: Date.now() });
  res.redirect(`${discovery.authorization_endpoint}?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(par.request_uri)}`);
});

app.get('/auth/callback', async (req, res) => {
  const pending = sessions.get(req.query.state);
  if (!pending || Date.now() - pending.createdAt > 10 * 60_000) return res.status(400).send('Invalid or expired OAuth state');
  sessions.delete(req.query.state);
  if (req.query.error) return res.status(400).send(`Authorization failed: ${req.query.error}`);
  const body = new URLSearchParams({ grant_type: 'authorization_code', code: req.query.code, redirect_uri: `${apiUrl}/auth/callback`, client_id: clientId, code_verifier: pending.verifier, resource });
  const token = await oauthPost(discovery.token_endpoint, body);
  const sid = random();
  sessions.set(`sid:${sid}`, { ...token, createdAt: Date.now() });
  res.setHeader('Set-Cookie', sessionCookie(sid));
  res.redirect(webappUrl);
});

app.get('/api/session', (req, res) => {
  const session = sessionFrom(req);
  res.json({ authenticated: Boolean(session), user: session?.claims?.sub || null });
});
app.post('/auth/logout', (req, res) => {
  const sid = req.headers.cookie?.match(/(?:^|; )financial_sid=([^;]+)/)?.[1];
  if (sid) sessions.delete(`sid:${sid}`);
  res.setHeader('Set-Cookie', 'financial_sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
  res.status(204).end();
});

app.get('/api/accounts', requireSession, (_req, res) => res.json({ accounts: [...accounts.values()] }));
app.get('/api/transfers', requireSession, (_req, res) => res.json({ transfers }));
app.post('/api/transfers', requireSession, (req, res) => {
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
app.get('/resource/accounts', requireDpopToken, (_req, res) => res.json({ accounts: [...accounts.values()] }));

app.listen(port, '0.0.0.0', () => console.log(`Financial API listening on ${apiUrl}`));

function required(name) { if (!process.env[name]) throw new Error(`${name} is required`); return process.env[name]; }
function random(bytes = 32) { return crypto.randomBytes(bytes).toString('base64url'); }
function sessionCookie(sid) {
  const secure = process.env.COOKIE_SECURE !== 'false' ? '; Secure' : '';
  return `financial_sid=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600${secure}`;
}
async function getJson(url, oidc = false) {
  const response = await (oidc ? oidcFetch(url) : fetch(url));
  if (!response.ok) throw new Error(`Discovery failed: ${response.status}`);
  return response.json();
}
async function oauthPost(url, body) {
  // Asterius FAPI client authentication requires aud to be the tenant issuer,
  // not the PAR or token endpoint URL.
  const assertion = await new SignJWT({}).setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: process.env.CLIENT_KEY_ID }).setIssuer(clientId).setSubject(clientId).setAudience(issuer).setIssuedAt().setExpirationTime('2m').setJti(random(16)).sign(clientKey);
  const proof = await new SignJWT({ htm: 'POST', htu: url, jti: random(16), iat: Math.floor(Date.now() / 1000) }).setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: dpopJwk }).sign(dpopPrivate);
  body.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
  body.set('client_assertion', assertion);
  const response = await oidcFetch(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', DPoP: proof }, body });
  const json = await response.json();
  if (!response.ok) throw new Error(`OAuth request failed (${response.status}): ${JSON.stringify(json)}`);
  return json;
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
  return retryFetch(() => fetch(target, { ...options, headers }));
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
function requireSession(req, res, next) { const session = sessionFrom(req); if (!session) return res.status(401).json({ error: 'login_required' }); req.session = session; next(); }
async function requireDpopToken(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    if (!header.startsWith('DPoP ')) return res.status(401).set('WWW-Authenticate', 'DPoP').json({ error: 'dpop_required' });
    const proof = req.headers.dpop;
    if (!proof) return res.status(401).json({ error: 'dpop_proof_required' });
    const proofHeader = JSON.parse(Buffer.from(proof.split('.')[0], 'base64url').toString());
    if (proofHeader.typ !== 'dpop+jwt' || !proofHeader.jwk) return res.status(401).json({ error: 'invalid_dpop_proof' });
    const proofKey = await importJWK(proofHeader.jwk, proofHeader.alg);
    const { payload: proofClaims } = await jwtVerify(proof, proofKey, { maxTokenAge: '5m' });
    if (proofClaims.htm !== req.method || proofClaims.htu !== `${apiUrl}${req.originalUrl}`) return res.status(401).json({ error: 'wrong_dpop_target' });
    const proofJkt = await calculateJwkThumbprint(proofHeader.jwk);
    const { payload } = await jwtVerify(header.slice(5), jwks, { issuer, audience: resource });
    if (payload.cnf?.jkt !== proofJkt) return res.status(401).json({ error: 'wrong_dpop_binding' });
    req.token = payload;
    next();
  } catch { res.status(401).set('WWW-Authenticate', 'DPoP error="invalid_token"').json({ error: 'invalid_token' }); }
}
