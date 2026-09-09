/**
 * Getting a browser to the first page of a flow.
 *
 * A user never reaches the login page by typing a URL. ADR-0002 makes PAR the
 * only way to start an authorization request, and FAPI 2.0 requires the push to
 * be authenticated with `private_key_jwt` — so before any browser is involved
 * there is a client to register and an assertion to sign. That is what this
 * module does, over the same HTTPS the browser will use.
 *
 * It deliberately reads the discovery document rather than hard-coding paths.
 * A sweep that knew where `/par` lived would keep passing after the endpoint
 * moved, and the two well-known forms are already covered by
 * `scripts/smoke-test.sh`.
 */
import type { APIRequestContext } from '@playwright/test';
import { SignJWT, exportJWK, generateKeyPair, type CryptoKey } from 'jose';

/** The subset of the discovery document this harness uses. */
export interface Discovery {
  readonly issuer: string;
  readonly authorization_endpoint: string;
  readonly pushed_authorization_request_endpoint: string;
  readonly registration_endpoint?: string;
}

/** A client registered for the duration of one test run. */
export interface RegisteredClient {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly privateKey: CryptoKey;
  readonly kid: string;
}

/**
 * RFC 7636 Appendix B's published `code_verifier`/`code_challenge` pair.
 *
 * Taken from the specification rather than computed here for the reason
 * `crates/server/tests/authorization_code.rs` gives: a pair this harness
 * derived would only assert that it agrees with itself. Nothing in the browser
 * sweep redeems the code, so only the challenge actually travels.
 */
export const PKCE_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

/** Reads the tenant's discovery document. */
export async function discover(api: APIRequestContext, baseUrl: string): Promise<Discovery> {
  const response = await api.get(`${baseUrl}/.well-known/openid-configuration`);
  if (!response.ok()) {
    throw new Error(
      `discovery failed: ${response.status()} ${await response.text()} (is the tenant's custom host seeded?)`,
    );
  }
  return (await response.json()) as Discovery;
}

/**
 * Registers a confidential client whose keys this process holds.
 *
 * The key is generated per run and never leaves memory: a fixture private key
 * committed to a repository is a credential in version control even when the
 * server it authenticates to is a throwaway.
 */
export async function registerClient(
  api: APIRequestContext,
  discovery: Discovery,
  redirectUri: string,
): Promise<RegisteredClient> {
  const endpoint = discovery.registration_endpoint;
  if (!endpoint) {
    throw new Error('the tenant advertises no registration endpoint; is `[registration]` set?');
  }

  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  const kid = 'e2e-client-key';
  const jwk = { ...(await exportJWK(publicKey)), kid, alg: 'ES256', use: 'sig' };

  const response = await api.post(endpoint, {
    headers: { 'content-type': 'application/json' },
    data: {
      client_name: 'Browser sweep',
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code'],
      scope: 'openid profile',
      token_endpoint_auth_method: 'private_key_jwt',
      jwks: { keys: [jwk] },
    },
  });
  if (response.status() !== 201) {
    throw new Error(`registration failed: ${response.status()} ${await response.text()}`);
  }
  const document = (await response.json()) as { client_id: string };
  return { clientId: document.client_id, redirectUri, privateKey, kid };
}

/**
 * Signs a `private_key_jwt` client assertion (OIDC Core §9, RFC 7523 §3).
 *
 * `aud` is the issuer and nothing else: `AssertionRules::for_issuer` accepts
 * one spelling of "this server", so an assertion audienced at the endpoint URL
 * is refused. The `jti` is single-use, so it is fresh per call.
 */
async function clientAssertion(client: RegisteredClient, issuer: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return await new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', kid: client.kid, typ: 'JWT' })
    .setIssuer(client.clientId)
    .setSubject(client.clientId)
    .setAudience(issuer)
    .setJti(crypto.randomUUID())
    .setIssuedAt(now)
    .setExpirationTime(now + 60)
    .sign(client.privateKey);
}

/**
 * Pushes an authorization request and returns the URL to send a browser to.
 *
 * The returned URL carries only the `request_uri` and the `client_id`, which is
 * the whole point of RFC 9126: nothing a browser holds can alter what was
 * requested.
 */
export async function pushAuthorizationRequest(
  api: APIRequestContext,
  discovery: Discovery,
  client: RegisteredClient,
  state: string,
  responseMode?: string,
): Promise<string> {
  const assertion = await clientAssertion(client, discovery.issuer);
  const response = await api.post(discovery.pushed_authorization_request_endpoint, {
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    form: {
      client_id: client.clientId,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: assertion,
      response_type: 'code',
      redirect_uri: client.redirectUri,
      scope: 'openid profile',
      code_challenge: PKCE_CHALLENGE,
      code_challenge_method: 'S256',
      state,
      // Omitted rather than sent as `query` when no mode is asked for: the
      // default is what almost every request looks like, and a suite that
      // always named a mode would never exercise it.
      ...(responseMode === undefined ? {} : { response_mode: responseMode }),
    },
  });
  if (response.status() !== 201) {
    throw new Error(`pushed authorization request failed: ${response.status()} ${await response.text()}`);
  }
  const document = (await response.json()) as { request_uri: string };
  const url = new URL(discovery.authorization_endpoint);
  url.searchParams.set('client_id', client.clientId);
  url.searchParams.set('request_uri', document.request_uri);
  return url.toString();
}
