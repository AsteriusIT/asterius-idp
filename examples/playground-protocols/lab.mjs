import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { generateKeyPair } from 'jose';
import { OidcClient, escapeHtml } from '../sso-demo/demo.mjs';

export function publicResult(result) {
  const allowed = ['error', 'error_description', 'token_type', 'expires_in', 'scope', 'active', 'client_id', 'sub', 'aud', 'iss'];
  return Object.fromEntries(Object.entries(result).filter(([key]) => allowed.includes(key)));
}
export function validOrigin(origin, expected) { return origin === new URL(expected).origin; }
const hex = () => randomBytes(24).toString('hex');
const safe = escapeHtml;
const html = (body) => `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Asterius protocol lab</title><style>body{font:16px system-ui;max-width:64rem;margin:3rem auto;padding:0 1rem;color:#18212d;background:#f8fafc}section{padding:1.5rem;margin:1rem 0;border:1px solid #ccd5df;border-radius:12px;background:white}button,input{font:inherit;padding:.6rem;margin:.3rem}pre{white-space:pre-wrap;overflow-wrap:anywhere}a{color:#234eb8}</style><body><a href="/">Playground</a><h1>Protocol lab</h1><p>Real requests to the selected Asterius tenant. Tokens and private keys remain in this server. Use a disposable test account.</p>${body}</body></html>`;
export async function startLab(env = process.env) {
  const external = env.EXTERNAL_URL;
  const privateJwk = JSON.parse(await readFile(env.CLIENT_PRIVATE_KEY_JWK_FILE, 'utf8'));
  const client = new OidcClient({ issuer: env.ISSUER, internalIssuer: env.OIDC_INTERNAL_ISSUER, externalUrl: external, name: 'Playground protocol lab', clientId: env.CLIENT_ID, clientPrivateJwk: privateJwk, clientKeyId: env.CLIENT_KEY_ID });
  await client.initialise();
  const sessions = new Map();
  const cookiePath = new URL(external).pathname.replace(/\/$/, '') || '/';
  const server = createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    const path = new URL(req.url, 'http://localhost').pathname;
    if (path === '/health') { res.setHeader('Content-Type', 'application/json'); return res.end(JSON.stringify({ ready: true, issuer: client.issuer })); }
    let sid = req.headers.cookie?.match(/(?:^|;\s*)asterius_protocol_lab=([a-f0-9]+)/)?.[1];
    const now = Date.now();
    for (const [id, s] of sessions) if (s.expires < now) sessions.delete(id);
    let state = sessions.get(sid);
    if (!state) {
      if (sessions.size >= 100) { res.statusCode = 503; return res.end('Session capacity reached; retry later'); }
      sid = hex(); state = { csrf: hex(), expires: now + 30 * 60_000, events: [] }; sessions.set(sid, state);
      res.setHeader('Set-Cookie', `asterius_protocol_lab=${sid}; Path=${cookiePath}; Secure; HttpOnly; SameSite=Lax; Max-Age=1800`);
    }
    const record = (label, result) => { state.events.unshift({ operation: label, result: publicResult(result) }); state.events = state.events.slice(0, 12); };
    if (req.method === 'POST') {
      if (!validOrigin(req.headers.origin, external)) { res.statusCode = 403; return res.end('Origin refused'); }
      let body = ''; for await (const part of req) { body += part; if (body.length > 4096) { res.statusCode = 413; return res.end('Request too large'); } }
      const form = new URLSearchParams(body);
      if (form.get('csrf') !== state.csrf) { res.statusCode = 403; return res.end('CSRF refused'); }
      try {
        if (path === '/device') {
          const endpoint = client.discovery.device_authorization_endpoint;
          if (!endpoint) throw new Error('Device authorization is not advertised');
          const pair = await generateKeyPair('ES256', { extractable: true });
          const result = await client.oauthPost(endpoint, new URLSearchParams({ client_id: client.clientId, scope: 'openid profile', resource: client.discovery.userinfo_endpoint }), pair);
          state.flow = { mode: 'device', pair, code: result.device_code, userCode: result.user_code, verification: result.verification_uri_complete || result.verification_uri, interval: result.interval || 5, nextPoll: now + (result.interval || 5) * 1000, expires: now + result.expires_in * 1000 };
          record('Device authorization accepted', { expires_in: result.expires_in });
        } else if (path === '/ciba') {
          const endpoint = client.discovery.backchannel_authentication_endpoint;
          if (!endpoint) throw new Error('CIBA is not advertised');
          const hint = form.get('login_hint')?.trim(); if (!hint || hint.length > 254) throw new Error('Enter the disposable account login identifier');
          const pair = await generateKeyPair('ES256', { extractable: true });
          const result = await client.oauthPost(endpoint, new URLSearchParams({ client_id: client.clientId, scope: 'openid profile', resource: client.discovery.userinfo_endpoint, login_hint: hint, binding_message: 'Asterius playground', requested_expiry: '300' }), pair);
          state.flow = { mode: 'ciba', pair, code: result.auth_req_id, interval: result.interval || 5, nextPoll: now + (result.interval || 5) * 1000, expires: now + result.expires_in * 1000 };
          record('CIBA request accepted; approve or deny in My account on a separate browser', { expires_in: result.expires_in });
        } else if (path === '/poll') {
          const flow = state.flow;
          if (!flow || now >= flow.expires) throw new Error('No current authorization flow; start a new one');
          if (now < flow.nextPoll) throw new Error('Wait for the advertised polling interval before polling again');
          flow.nextPoll = now + flow.interval * 1000;
          const payload = flow.mode === 'device' ? { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: flow.code } : { grant_type: 'urn:openid:params:grant-type:ciba', auth_req_id: flow.code };
          const result = await client.token(new URLSearchParams(payload), flow.pair);
          state.token = { ...result, dpop: flow.pair }; state.flow = undefined;
          record('Token issued', result);
        } else if (path === '/userinfo') {
          if (!state.token) throw new Error('Approve a device or CIBA flow first');
          record('Live UserInfo', await client.userInfo(state.token));
        } else if (path === '/introspect') {
          if (!state.token) throw new Error('Approve a device or CIBA flow first');
          const result = await client.oauthPost(client.discovery.introspection_endpoint, new URLSearchParams({ token: state.token.access_token, token_type_hint: 'access_token' }), state.token.dpop);
          record('Authenticated token introspection', result);
        } else if (path === '/revoke') {
          if (!state.token) throw new Error('No issued token');
          await client.revoke(state.token.refresh_token); await client.revoke(state.token.access_token);
          record('Revocation accepted; try UserInfo and introspection again', { active: false });
        } else if (path === '/clear') { sessions.delete(sid); }
        else { res.statusCode = 404; return res.end('Unknown action'); }
      } catch (error) {
        // OAuth replies can contain one-time identifiers. Keep only the error
        // category in this browser and never echo exception payloads or tokens.
        const category = String(error.message).match(/\b(authorization_pending|slow_down|access_denied|expired_token|invalid_grant|invalid_scope|invalid_target|unsupported_grant_type)\b/)?.[1];
        if (category === 'slow_down' && state.flow) { state.flow.interval += 5; state.flow.nextPoll = now + state.flow.interval * 1000; }
        record('Request not completed', { error: category || 'request_failed', error_description: category ? 'Inspect the flow decision and retry only after its polling interval.' : 'Check the prerequisite, session and tenant/client policy; see operator logs without sharing credentials.' });
      }
      res.writeHead(303, { Location: external + '/' }); return res.end();
    }
    if (req.method !== 'GET' || path !== '/') { res.statusCode = 404; return res.end('Not found'); }
    const button = (route, title, extra = '') => `<form method="post" action="${safe(external + route)}"><input type="hidden" name="csrf" value="${state.csrf}">${extra}<button>${safe(title)}</button></form>`;
    const flow = state.flow;
    let device = '';
    if (flow?.mode === 'device') {
      const u = new URL(flow.verification);
      if (u.origin === new URL(client.issuer).origin && u.pathname.startsWith(new URL(client.issuer).pathname + '/')) device = `<p>Code: <strong>${safe(flow.userCode)}</strong>. <a href="${safe(flow.verification)}" target="_blank" rel="noopener">Open the Asterius approval page</a> in a second browser. Confirm only your own code.</p>`;
    }
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(html(`<section><h2>1. Device sign-in</h2><p>Start a confidential device request, approve or deny its displayed code on another browser, then poll. Pending and denied outcomes are expected until you approve.</p>${button('/device', 'Start device sign-in')}${device}</section><section><h2>2. CIBA separate-device approval</h2><p>Enter your disposable account identifier. In its separate My account session, inspect the pending request and approve or deny “Asterius playground”. Local notification mail is journaled privately.</p>${button('/ciba', 'Request CIBA approval', '<label>Test account <input name="login_hint" maxlength="254" required autocomplete="username"></label>')}<p><a href="${safe(client.issuer + '/account')}" target="_blank" rel="noopener">Open My account</a></p></section><section><h2>3. Observe authority</h2><p>${flow ? `A ${safe(flow.mode)} flow is waiting. Poll at intervals of at least ${flow.interval} seconds.` : 'Start a flow above.'}</p>${button('/poll','Poll once')}${button('/userinfo','Call live UserInfo')}${button('/introspect','Introspect this token')}${button('/revoke','Revoke this token')}${button('/clear','Clear local lab session')}<p>After revocation, UserInfo must refuse and introspection must report inactive. Clearing the lab only forgets its process-local state.</p></section><section><h2>Observed results</h2><pre>${safe(JSON.stringify(state.events,null,2))}</pre></section>`));
  });
  await new Promise(resolve => server.listen(Number(env.PORT || 8080), '0.0.0.0', resolve));
  return server;
}
if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) startLab().catch(() => { console.error('Protocol lab startup failed; check issuer, configured client and mounted key'); process.exitCode = 1; });
