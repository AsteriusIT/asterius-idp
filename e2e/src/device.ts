/**
 * The device's half of RFC 8628, so a browser can walk the person's half.
 *
 * Nothing here is a browser: a device with no browser is the whole premise of
 * the grant. It asks at `device_authorization_endpoint` (§3.1), shows a code,
 * and polls the token endpoint (§3.4) until somebody has answered — and the
 * only thing that makes that polling stop is a person, in a browser, without
 * JavaScript. That is what `tests/no-js-device.spec.ts` asserts and what this
 * module exists to make possible.
 *
 * The client authenticates with `private_key_jwt` like every other client here:
 * FAPI 2.0 SP §5.3.2.1 item 3 admits no public client, so a device holds a key.
 */
import type { APIRequestContext } from '@playwright/test';
import { SignJWT, exportJWK, generateKeyPair, type CryptoKey, type JWK } from 'jose';
import { type Discovery, type RegisteredClient, clientAssertion } from './authorization.js';

/** The key a device proves possession of, and the public half it shows. */
export interface ProofKey {
  readonly privateKey: CryptoKey;
  readonly publicJwk: JWK;
}

/**
 * A fresh DPoP key (RFC 9449 §4).
 *
 * Per device, and never on disk: the whole claim of a proof is that the holder
 * of the key made this request, which a key shared with anything else does not
 * support.
 */
export async function newProofKey(): Promise<ProofKey> {
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  return { privateKey, publicJwk: await exportJWK(publicKey) };
}

/**
 * One DPoP proof for one request (RFC 9449 §4.2).
 *
 * `htu` is the endpoint as the metadata advertises it, with no query and no
 * fragment, because that is what the server compares against — and it builds
 * its side from `issuer`, never from the request.
 */
async function dpopProof(key: ProofKey, method: string, url: string): Promise<string> {
  return await new SignJWT({ htm: method, htu: url })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: key.publicJwk })
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .sign(key.privateKey);
}

/** The grant a device redeems its code under. */
export const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

/** RFC 8628 §3.2: what the device is given to show. */
export interface DeviceAuthorization {
  readonly device_code: string;
  readonly user_code: string;
  readonly verification_uri: string;
  readonly verification_uri_complete: string;
  readonly expires_in: number;
  readonly interval: number;
}

/** RFC 8628 §3.1: the device asks, authenticating as itself. */
export async function requestDeviceAuthorization(
  api: APIRequestContext,
  discovery: Discovery,
  client: RegisteredClient,
): Promise<DeviceAuthorization> {
  const endpoint = discovery.device_authorization_endpoint;
  if (!endpoint) {
    throw new Error(
      'the tenant advertises no device_authorization_endpoint; is `[features] device_flow` on?',
    );
  }
  const response = await api.post(endpoint, {
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    form: {
      client_id: client.clientId,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: await clientAssertion(client, discovery.issuer),
      scope: 'openid',
    },
  });
  if (response.status() !== 200) {
    throw new Error(`device authorization failed: ${response.status()} ${await response.text()}`);
  }
  return (await response.json()) as DeviceAuthorization;
}

/** What one poll of the token endpoint answered. */
export interface Poll {
  readonly status: number;
  readonly body: Record<string, unknown>;
}

/**
 * RFC 8628 §3.4: one poll, and exactly one.
 *
 * Single rather than a loop with a sleep inside it, because the assertions
 * differ: before the approval the device must be told `authorization_pending`
 * and nothing else, and after it a token. A helper that polled until something
 * happened would hide the first half, which is the half §3.5 is about.
 */
export async function pollOnce(
  api: APIRequestContext,
  discovery: Discovery,
  client: RegisteredClient,
  deviceCode: string,
  key: ProofKey,
): Promise<Poll> {
  const response = await api.post(discovery.token_endpoint, {
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      // RFC 8628 says nothing about DPoP and this server does: a device code
      // is redeemed for a token, and every token this server mints is bound to
      // something its holder must prove (FAPI 2.0 SP §5.3.1).
      dpop: await dpopProof(key, 'POST', discovery.token_endpoint),
    },
    form: {
      client_id: client.clientId,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: await clientAssertion(client, discovery.issuer),
      grant_type: DEVICE_GRANT,
      device_code: deviceCode,
    },
  });
  return {
    status: response.status(),
    body: (await response.json()) as Record<string, unknown>,
  };
}

/**
 * Polls the way a device does, until it is told something terminal.
 *
 * §3.5's two non-terminal answers are the loop's condition and nothing else:
 * `authorization_pending` means carry on, and `slow_down` means carry on more
 * slowly — the increment is five seconds, and a test that treated either as a
 * failure would be asserting its own timing rather than the server's answer.
 * Everything else, token or error, is returned to the caller to judge.
 */
export async function pollUntilAnswered(
  api: APIRequestContext,
  discovery: Discovery,
  client: RegisteredClient,
  deviceCode: string,
  key: ProofKey,
  intervalSeconds: number,
  attempts = 6,
): Promise<Poll> {
  let wait = intervalSeconds * 1000;
  let last = await pollOnce(api, discovery, client, deviceCode, key);
  for (let attempt = 1; attempt < attempts; attempt += 1) {
    const code = last.body['error'];
    if (code !== 'authorization_pending' && code !== 'slow_down') {
      return last;
    }
    if (code === 'slow_down') {
      wait += 5_000;
    }
    await new Promise((resume) => setTimeout(resume, wait));
    last = await pollOnce(api, discovery, client, deviceCode, key);
  }
  return last;
}
