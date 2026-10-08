import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import {
  SignJWT,
  createRemoteJWKSet,
  customFetch,
  importJWK,
  exportJWK,
  generateKeyPair,
  jwtVerify,
} from 'jose';

const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

export function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

export function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export function cookies(header = '') {
  return Object.fromEntries(
    header.split(';').flatMap((part) => {
      const at = part.indexOf('=');
      return at < 1 ? [] : [[part.slice(0, at).trim(), part.slice(at + 1).trim()]];
    }),
  );
}

export function sessionCookie(name, id, path = '/', secure = true) {
  return `${name}=${id}; Path=${path}; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`;
}

async function responseJson(response, operation) {
  const text = await response.text();
  if (!response.ok) throw new Error(`${operation} failed (${response.status})`);
  return JSON.parse(text);
}

export class OidcClient {
  constructor({ issuer, internalIssuer = issuer, externalUrl, name, clientId, clientPrivateJwk, clientKeyId, scopes = 'openid profile offline_access', resource, fetchImpl = fetch }) {
    this.issuer = issuer.replace(/\/$/, '');
    this.internalIssuer = internalIssuer.replace(/\/$/, '');
    this.externalUrl = externalUrl.replace(/\/$/, '');
    this.name = name;
    this.clientId = clientId;
    this.clientPrivateJwk = clientPrivateJwk;
    this.clientKid = clientKeyId ?? clientPrivateJwk?.kid;
    this.scopes = scopes;
    this.resource = resource ?? `${this.issuer}/userinfo`;
    this.nonces = new WeakMap();
    this.fetch = (url, options) => this.fetchInternal(url, options, fetchImpl);
  }

  async fetchInternal(url, options = {}, fetchImpl) {
    const publicUrl = new URL(this.issuer);
    const internalUrl = new URL(this.internalIssuer);
    let target = new URL(url);
    if (target.origin === publicUrl.origin) target = new URL(target.pathname + target.search, internalUrl);
    const headers = new Headers(options.headers);
    // Preserve the public authority while reaching the cleartext listener on
    // the trusted Compose network.
    headers.set('host', publicUrl.host);
    headers.set('x-forwarded-host', publicUrl.host);
    headers.set('x-forwarded-proto', publicUrl.protocol.slice(0, -1));
    return retryFetch(() => fetchImpl(target, { ...options, headers, redirect: 'error' }));
  }

  async initialise() {
    this.discovery = await responseJson(
      await this.fetch(`${this.internalIssuer}/.well-known/openid-configuration`),
      'discovery',
    );
    if (this.discovery.issuer !== this.issuer) throw new Error('discovery issuer mismatch');
    this.idTokenKeys = createRemoteJWKSet(new URL(this.discovery.jwks_uri), {
      [customFetch]: (url, options) => this.fetch(url, options),
    });
    if (this.clientId || this.clientPrivateJwk) {
      if (!this.clientId || !this.clientPrivateJwk || !this.clientKid) throw new Error('configured client requires an ID, private JWK and key ID');
      if (this.clientPrivateJwk.kty !== 'EC' || this.clientPrivateJwk.crv !== 'P-256' || !this.clientPrivateJwk.d) throw new Error('configured client requires an ES256 private JWK');
      this.clientPrivateKey = await importJWK(this.clientPrivateJwk, 'ES256');
      return;
    }
    if (!this.discovery.registration_endpoint) throw new Error('configure a registered client when registration is closed');
    const pair = await generateKeyPair('ES256', { extractable: true });
    this.clientPrivateKey = pair.privateKey;
    this.clientKid = `${this.name.toLowerCase().replaceAll(' ', '-')}-auth`;
    const publicJwk = {
      ...(await exportJWK(pair.publicKey)),
      kid: this.clientKid,
      alg: 'ES256',
      use: 'sig',
    };
    const registered = await responseJson(
      await this.fetch(this.discovery.registration_endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          client_name: this.name,
          redirect_uris: [`${this.externalUrl}/callback`],
          post_logout_redirect_uris: [`${this.externalUrl}/logged-out`],
          response_types: ['code'],
          grant_types: ['authorization_code', 'refresh_token'],
          scope: this.scopes,
          resources: [this.resource],
          token_endpoint_auth_method: 'private_key_jwt',
          jwks: { keys: [publicJwk] },
          require_pushed_authorization_requests: true,
          dpop_bound_access_tokens: true,
        }),
      }),
      'registration',
    );
    this.clientId = registered.client_id;
  }

  async assertion() {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', kid: this.clientKid, typ: 'JWT' })
      .setIssuer(this.clientId)
      .setSubject(this.clientId)
      .setAudience(this.discovery.issuer)
      .setJti(randomUUID())
      .setIssuedAt(now)
      .setExpirationTime(now + 60)
      .sign(this.clientPrivateKey);
  }

  async proof(key, method, url, accessToken) {
    const publicJwk = await exportJWK(key.publicKey);
    const target = new URL(url);
    target.search = ''; target.hash = '';
    const claims = { htm: method, htu: target.toString(), jti: randomUUID() };
    const nonce = this.nonces.get(key)?.get(target.origin);
    if (nonce) claims.nonce = nonce;
    if (accessToken) claims.ath = base64url(createHash('sha256').update(accessToken).digest());
    return new SignJWT(claims)
      .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
      .setIssuedAt()
      .sign(key.privateKey);
  }

  async dpopRequest(key, method, url, { form, accessToken } = {}) {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const body = form ? new URLSearchParams(form) : undefined;
      if (body) {
        body.set('client_id', this.clientId);
        body.set('client_assertion_type', ASSERTION_TYPE);
        body.set('client_assertion', await this.assertion());
      }
      const headers = { dpop: await this.proof(key, method, url, accessToken) };
      if (body) headers['content-type'] = 'application/x-www-form-urlencoded';
      if (accessToken) headers.authorization = `DPoP ${accessToken}`;
      const response = await this.fetch(url, { method, headers, body });
      const nonce = response.headers.get('dpop-nonce');
      if (nonce && nonce.length <= 512) {
        const nonces = this.nonces.get(key) ?? new Map();
        nonces.set(new URL(url).origin, nonce);
        this.nonces.set(key, nonces);
        if ((response.status === 400 || response.status === 401) && attempt === 0) {
          const error = await response.clone().json().catch(() => ({}));
          if (error.error === 'use_dpop_nonce') continue;
        }
      }
      return response;
    }
    throw new Error('DPoP nonce negotiation failed');
  }

  async oauthPost(endpoint, form, dpop) {
    return responseJson(await this.dpopRequest(dpop, 'POST', endpoint, { form }), 'OAuth request');
  }

  async begin(extra = {}) {
    const verifier = base64url(randomBytes(32));
    const challenge = base64url(createHash('sha256').update(verifier).digest());
    const state = randomUUID();
    const nonce = randomUUID();
    const dpop = await generateKeyPair('ES256', { extractable: true });
    const endpoint = this.discovery.pushed_authorization_request_endpoint;
    const form = new URLSearchParams({
      client_id: this.clientId,
      client_assertion_type: ASSERTION_TYPE,
      client_assertion: await this.assertion(),
      response_type: 'code',
      redirect_uri: `${this.externalUrl}/callback`,
      scope: this.scopes,
      resource: this.resource,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state,
      nonce,
      ...extra,
    });
    const pushed = await this.oauthPost(endpoint, form, dpop);
    const authorize = new URL(this.discovery.authorization_endpoint);
    authorize.searchParams.set('client_id', this.clientId);
    authorize.searchParams.set('request_uri', pushed.request_uri);
    return { authorize: authorize.toString(), verifier, state, nonce, dpop };
  }

  token(form, dpop) {
    return this.oauthPost(this.discovery.token_endpoint, form, dpop);
  }

  redeem(code, pending) {
    return this.token(
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: `${this.externalUrl}/callback`,
        code_verifier: pending.verifier,
      }),
      pending.dpop,
    );
  }

  refresh(session) {
    return this.token(
      new URLSearchParams({ grant_type: 'refresh_token', refresh_token: session.refresh_token }),
      session.dpop,
    );
  }

  async userInfo(session) {
    const endpoint = this.discovery.userinfo_endpoint;
    return responseJson(await this.dpopRequest(session.dpop, 'GET', endpoint, { accessToken: session.access_token }), 'UserInfo');
  }

  async revoke(token) {
    if (!token) return;
    const endpoint = this.discovery.revocation_endpoint;
    const form = new URLSearchParams({
      token,
      client_id: this.clientId,
      client_assertion_type: ASSERTION_TYPE,
      client_assertion: await this.assertion(),
    });
    const response = await this.fetch(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form,
    });
    if (!response.ok) throw new Error(`revocation failed (${response.status}): ${await response.text()}`);
  }

  async verifyIdToken(token, nonce) {
    const verified = await jwtVerify(token, this.idTokenKeys, {
      issuer: this.discovery.issuer,
      audience: this.clientId,
      algorithms: ['EdDSA', 'ES256', 'PS256'],
    });
    if (verified.payload.nonce !== nonce) throw new Error('ID token nonce mismatch');
    return verified.payload;
  }
}

function page(name, body) {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escapeHtml(name)}</title><style>body{font:16px system-ui;max-width:52rem;margin:4rem auto;padding:0 1rem}nav,a,button{margin:.35rem}pre{padding:1rem;background:#eee;overflow:auto}.ok{color:#176b30}</style><body><h1>${escapeHtml(name)}</h1>${body}</body></html>`;
}

export async function startDemo(config = process.env) {
  const port = Number(config.PORT ?? '8080');
  const externalUrl = (config.EXTERNAL_URL ?? `http://127.0.0.1:${port}`).replace(/\/$/, '');
  const homeUrl = `${externalUrl}/`;
  const name = config.APP_NAME ?? 'Asterius demo';
  const cookieName = config.COOKIE_NAME ?? `asterius_demo_${createHash('sha256').update(externalUrl).digest('hex').slice(0, 10)}`;
  const cookiePath = new URL(externalUrl).pathname.replace(/\/$/, '') || '/';
  const keyText = config.CLIENT_PRIVATE_KEY_JWK_FILE ? await readFile(config.CLIENT_PRIVATE_KEY_JWK_FILE, 'utf8') : config.CLIENT_PRIVATE_KEY_JWK;
  const client = new OidcClient({ issuer: config.ISSUER, internalIssuer: config.OIDC_INTERNAL_ISSUER, externalUrl, name,
    clientId: config.CLIENT_ID, clientPrivateJwk: keyText ? JSON.parse(keyText) : undefined,
    clientKeyId: config.CLIENT_KEY_ID, scopes: config.SCOPES, resource: config.RESOURCE });
  await client.initialise();
  const pending = new Map();
  const sessions = new Map();

  const handler = async (request, response) => {
    try {
      const url = new URL(request.url, externalUrl);
      const path = url.pathname.replace(new URL(externalUrl).pathname.replace(/\/$/, ''), '') || '/';
      const sid = cookies(request.headers.cookie)[cookieName];
      let session = sid ? sessions.get(sid) : undefined;
      const resultPage = (status, message) => {
        response.statusCode = status;
        response.end(page(name, `<p role="status">${escapeHtml(message)}</p><p><a href="${escapeHtml(homeUrl)}">Return to application</a></p><p><a href="${escapeHtml(externalUrl)}/login">Sign in with Asterius</a></p>`));
      };
      if (path === '/healthz') return void response.end('ok');
      if (['/refresh', '/check-session', '/reauth', '/step-up', '/logout'].includes(path) && !session) {
        return resultPage(401, 'This action requires an application session. Sign in first.');
      }
      if (path === '/login' || path === '/reauth' || path === '/step-up') {
        const extra = path === '/reauth' ? { prompt: 'login', max_age: '0' } :
          path === '/step-up' ? {
            claims: JSON.stringify({
              id_token: {
                acr: { essential: true, values: ['urn:asterius:acr:passkey'] },
              },
            }),
          } : {};
        const started = await client.begin(extra);
        pending.set(started.state, { ...started, sessionId: sid, action: path, createdAt: Date.now() });
        response.setHeader('set-cookie', sessionCookie(`${cookieName}_login`, started.state, cookiePath, externalUrl.startsWith('https:')) + '; Max-Age=600');
        response.writeHead(303, { location: started.authorize });
        return void response.end();
      }
      if (path === '/check-session' && session) {
        const started = await client.begin({ prompt: 'none' });
        pending.set(started.state, { ...started, sessionId: sid, action: path, createdAt: Date.now() });
        response.setHeader('set-cookie', sessionCookie(`${cookieName}_login`, started.state, cookiePath, externalUrl.startsWith('https:')) + '; Max-Age=600');
        response.writeHead(303, { location: started.authorize });
        return void response.end();
      }
      if (path === '/callback') {
        const state = url.searchParams.get('state');
        const flow = state ? pending.get(state) : undefined;
        if (!flow || Date.now() - flow.createdAt > 600_000 || cookies(request.headers.cookie)[`${cookieName}_login`] !== state || url.searchParams.get('iss') !== client.discovery.issuer) throw new Error('invalid authorization response');
        pending.delete(state);
        if (url.searchParams.has('error')) {
          if (flow.sessionId) sessions.delete(flow.sessionId);
          response.setHeader('set-cookie', sessionCookie(cookieName, '', cookiePath, externalUrl.startsWith('https:')) + '; Max-Age=0');
          return resultPage(401, flow.action === '/check-session'
            ? 'The identity provider did not confirm an active session. Sign in again.'
            : 'The identity provider refused this sign-in or authentication request.');
        }
        const tokens = await client.redeem(url.searchParams.get('code'), flow);
        const idClaims = await client.verifyIdToken(tokens.id_token, flow.nonce);
        if (flow.action === '/step-up' && idClaims.acr !== 'urn:asterius:acr:passkey') throw new Error('required authentication level was not confirmed');
        const id = flow.sessionId ?? randomUUID();
        const outcome = flow.action === '/check-session' ? 'The identity provider confirmed your session.'
          : flow.action === '/reauth' ? 'Reauthentication completed.'
          : flow.action === '/step-up' ? 'Passkey step-up completed.' : 'Sign-in completed.';
        sessions.set(id, { ...tokens, dpop: flow.dpop, idClaims, outcome });
        response.writeHead(303, { location: homeUrl, 'set-cookie': sessionCookie(cookieName, id, cookiePath, externalUrl.startsWith('https:')) });
        return void response.end();
      }
      if (path === '/refresh' && session) {
        let refreshed;
        try {
          refreshed = await client.refresh(session);
          if (refreshed.token_type?.toLowerCase() !== 'dpop') throw new Error('invalid refreshed token binding');
          if (refreshed.id_token) {
            // OIDC refresh ID tokens omit nonce; verify issuer/audience/signature
            // and retain the authenticated subject before replacing tokens.
            const claims = await client.verifyIdToken(refreshed.id_token, undefined);
            if (claims.sub !== session.idClaims.sub) throw new Error('refreshed identity changed');
            session.idClaims = claims;
          }
        }
        catch { return resultPage(502, 'Token refresh was refused or unavailable. No successful refresh was confirmed.'); }
        Object.assign(session, refreshed, { outcome: 'Tokens refreshed successfully.' });
        response.writeHead(303, { location: homeUrl });
        return void response.end();
      }
      if (path === '/logout' && session) {
        await client.revoke(session.refresh_token);
        await client.revoke(session.access_token);
        sessions.delete(sid);
        const logout = new URL(client.discovery.end_session_endpoint);
        logout.searchParams.set('id_token_hint', session.id_token);
        logout.searchParams.set('post_logout_redirect_uri', `${externalUrl}/logged-out`);
        response.writeHead(303, { location: logout.toString(), 'set-cookie': sessionCookie(cookieName, '', cookiePath, externalUrl.startsWith('https:')) + '; Max-Age=0' });
        return void response.end();
      }
      if (path === '/logged-out') {
        response.end(page(name, `<p class="ok">This application session is signed out.</p><p><a href="${escapeHtml(homeUrl)}">Return home</a></p>`));
        return;
      }
      if (path !== '/') return resultPage(404, 'This application action does not exist.');
      let userInfo;
      if (session) {
        try { userInfo = await client.userInfo(session); }
        catch {
          sessions.delete(sid);
          response.setHeader('set-cookie', sessionCookie(cookieName, '', cookiePath, externalUrl.startsWith('https:')) + '; Max-Age=0');
          return resultPage(401, 'UserInfo could not confirm this application session. The token may be expired, revoked, or the identity provider unavailable. Sign in again.');
        }
      }
      const outcome = session?.outcome;
      if (session) delete session.outcome;
      const body = session
        ? `<p class="ok">Signed in as ${escapeHtml(userInfo.sub)}</p><pre data-testid="userinfo">${escapeHtml(JSON.stringify(userInfo, null, 2))}</pre><nav><a href="${escapeHtml(externalUrl)}/refresh">Refresh tokens</a><a href="${escapeHtml(externalUrl)}/check-session">Check IdP session</a><a href="${escapeHtml(externalUrl)}/reauth">Force reauthentication</a><a href="${escapeHtml(externalUrl)}/step-up">Require passkey step-up</a><a href="${escapeHtml(externalUrl)}/logout">Revoke and log out</a></nav>`
        : `<p>Signed out.</p><p><a href="${escapeHtml(externalUrl)}/login">Sign in with Asterius</a></p>`;
      response.end(page(name, (outcome ? `<p role="status">${escapeHtml(outcome)}</p>` : '') + body));
    } catch (error) {
      response.statusCode = 500;
      response.end(page(name, `<p role="status">${error.message === 'invalid authorization response' ? 'Invalid or expired authorization response. Start sign-in again.' : 'The requested operation was refused or unavailable.'}</p><p><a href="${escapeHtml(homeUrl)}">Return to application</a></p>`));
    }
  };

  const server = config.TLS_CERT && config.TLS_KEY
    ? createHttpsServer({ cert: await readFile(config.TLS_CERT), key: await readFile(config.TLS_KEY) }, handler)
    : createHttpServer(handler);
  await new Promise((resolve) => server.listen(port, config.BIND ?? '0.0.0.0', resolve));
  console.log(`${name} listening on ${externalUrl}; client ${client.clientId}`);
  return server;
}

async function retryFetch(operation, attempts = 30) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      if (attempt + 1 < attempts) await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
  throw lastError;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  startDemo().catch((error) => { console.error(error); process.exitCode = 1; });
}
