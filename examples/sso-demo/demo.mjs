import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import {
  SignJWT,
  createRemoteJWKSet,
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
  if (!response.ok) throw new Error(`${operation} failed (${response.status}): ${text}`);
  return JSON.parse(text);
}

export class OidcClient {
  constructor({ issuer, externalUrl, name, fetchImpl = fetch }) {
    this.issuer = issuer.replace(/\/$/, '');
    this.externalUrl = externalUrl.replace(/\/$/, '');
    this.name = name;
    this.fetch = fetchImpl;
  }

  async initialise() {
    this.discovery = await responseJson(
      await this.fetch(`${this.issuer}/.well-known/openid-configuration`),
      'discovery',
    );
    if (!this.discovery.registration_endpoint) {
      throw new Error('the tenant does not advertise dynamic client registration');
    }
    this.idTokenKeys = createRemoteJWKSet(new URL(this.discovery.jwks_uri));
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
          scope: 'openid profile offline_access',
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
      .setProtectedHeader({ alg: 'ES256', kid: this.clientKid, typ: 'client-authentication+jwt' })
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
    const claims = { htm: method, htu: url, jti: randomUUID() };
    if (accessToken) claims.ath = base64url(createHash('sha256').update(accessToken).digest());
    return new SignJWT(claims)
      .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
      .setIssuedAt()
      .sign(key.privateKey);
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
      scope: 'openid profile offline_access',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state,
      nonce,
      ...extra,
    });
    const pushed = await responseJson(
      await this.fetch(endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          dpop: await this.proof(dpop, 'POST', endpoint),
        },
        body: form,
      }),
      'PAR',
    );
    const authorize = new URL(this.discovery.authorization_endpoint);
    authorize.searchParams.set('client_id', this.clientId);
    authorize.searchParams.set('request_uri', pushed.request_uri);
    return { authorize: authorize.toString(), verifier, state, nonce, dpop };
  }

  async token(form, dpop) {
    const endpoint = this.discovery.token_endpoint;
    form.set('client_id', this.clientId);
    form.set('client_assertion_type', ASSERTION_TYPE);
    form.set('client_assertion', await this.assertion());
    return responseJson(
      await this.fetch(endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          dpop: await this.proof(dpop, 'POST', endpoint),
        },
        body: form,
      }),
      'token request',
    );
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
    return responseJson(
      await this.fetch(endpoint, {
        headers: {
          authorization: `DPoP ${session.access_token}`,
          dpop: await this.proof(session.dpop, 'GET', endpoint, session.access_token),
        },
      }),
      'UserInfo',
    );
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
  const externalUrl = config.EXTERNAL_URL ?? `http://127.0.0.1:${port}`;
  const name = config.APP_NAME ?? 'Asterius demo';
  const cookieName = config.COOKIE_NAME ?? `asterius_demo_${createHash('sha256').update(externalUrl).digest('hex').slice(0, 10)}`;
  const cookiePath = new URL(externalUrl).pathname.replace(/\/$/, '') || '/';
  const client = new OidcClient({ issuer: config.ISSUER, externalUrl, name });
  await client.initialise();
  const pending = new Map();
  const sessions = new Map();

  const handler = async (request, response) => {
    try {
      const url = new URL(request.url, externalUrl);
      const path = url.pathname.replace(new URL(externalUrl).pathname.replace(/\/$/, ''), '') || '/';
      const sid = cookies(request.headers.cookie)[cookieName];
      let session = sid ? sessions.get(sid) : undefined;
      if (path === '/healthz') return void response.end('ok');
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
        pending.set(started.state, started);
        response.writeHead(303, { location: started.authorize });
        return void response.end();
      }
      if (path === '/check-session' && session) {
        const started = await client.begin({ prompt: 'none' });
        pending.set(started.state, { ...started, sessionId: sid });
        response.writeHead(303, { location: started.authorize });
        return void response.end();
      }
      if (path === '/callback') {
        const state = url.searchParams.get('state');
        const flow = state ? pending.get(state) : undefined;
        if (!flow || url.searchParams.get('iss') !== client.discovery.issuer) throw new Error('invalid authorization response');
        pending.delete(state);
        if (url.searchParams.has('error')) {
          if (flow.sessionId) sessions.delete(flow.sessionId);
          response.writeHead(303, {
            location: externalUrl,
            'set-cookie': sessionCookie(cookieName, '', cookiePath, externalUrl.startsWith('https:')) + '; Max-Age=0',
          });
          return void response.end();
        }
        const tokens = await client.redeem(url.searchParams.get('code'), flow);
        const idClaims = await client.verifyIdToken(tokens.id_token, flow.nonce);
        const id = flow.sessionId ?? randomUUID();
        sessions.set(id, { ...tokens, dpop: flow.dpop, idClaims });
        response.writeHead(303, { location: externalUrl, 'set-cookie': sessionCookie(cookieName, id, cookiePath, externalUrl.startsWith('https:')) });
        return void response.end();
      }
      if (path === '/refresh' && session) {
        const refreshed = await client.refresh(session);
        Object.assign(session, refreshed);
        response.writeHead(303, { location: externalUrl });
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
        response.end(page(name, `<p class="ok">This application session is signed out.</p><p><a href="${escapeHtml(externalUrl)}">Return home</a></p>`));
        return;
      }
      let userInfo;
      if (session) {
        try { userInfo = await client.userInfo(session); }
        catch { sessions.delete(sid); session = undefined; }
      }
      const body = session
        ? `<p class="ok">Signed in as ${escapeHtml(userInfo.sub)}</p><pre data-testid="userinfo">${escapeHtml(JSON.stringify(userInfo, null, 2))}</pre><nav><a href="${escapeHtml(externalUrl)}/refresh">Refresh tokens</a><a href="${escapeHtml(externalUrl)}/check-session">Check IdP session</a><a href="${escapeHtml(externalUrl)}/reauth">Force reauthentication</a><a href="${escapeHtml(externalUrl)}/step-up">Require passkey step-up</a><a href="${escapeHtml(externalUrl)}/logout">Revoke and log out</a></nav>`
        : `<p>Signed out.</p><p><a href="${escapeHtml(externalUrl)}/login">Sign in with Asterius</a></p>`;
      response.end(page(name, body));
    } catch (error) {
      response.statusCode = 500;
      response.end(page(name, `<p>Request failed: ${escapeHtml(error.message)}</p>`));
    }
  };

  const server = config.TLS_CERT && config.TLS_KEY
    ? createHttpsServer({ cert: await readFile(config.TLS_CERT), key: await readFile(config.TLS_KEY) }, handler)
    : createHttpServer(handler);
  await new Promise((resolve) => server.listen(port, config.BIND ?? '0.0.0.0', resolve));
  console.log(`${name} listening on ${externalUrl}; client ${client.clientId}`);
  return server;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  startDemo().catch((error) => { console.error(error); process.exitCode = 1; });
}
