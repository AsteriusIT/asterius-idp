import { createHash, randomUUID } from 'node:crypto';
import { exportJWK, importJWK, jwtVerify, SignJWT, calculateJwkThumbprint } from 'jose';

export class OAuthRequests {
  constructor({ issuer, clientId, clientKey, clientKid, dpopPrivate, dpopPublic, fetchImpl }) {
    Object.assign(this, { issuer, clientId, clientKey, clientKid, dpopPrivate, dpopPublic, fetchImpl });
    this.nonces = new Map();
  }
  async request(url, form) {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const now = Math.floor(Date.now() / 1000);
      const assertion = await new SignJWT({}).setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: this.clientKid })
        .setIssuer(this.clientId).setSubject(this.clientId).setAudience(this.issuer).setIssuedAt(now).setExpirationTime(now + 60).setJti(randomUUID()).sign(this.clientKey);
      const target = new URL(url); target.search = ''; target.hash = '';
      const claims = { htm: 'POST', htu: target.toString(), jti: randomUUID(), iat: now };
      if (this.nonces.has(target.origin)) claims.nonce = this.nonces.get(target.origin);
      const proof = await new SignJWT(claims).setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: await exportJWK(this.dpopPublic) }).sign(this.dpopPrivate);
      const body = new URLSearchParams(form);
      body.set('client_id', this.clientId);
      body.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
      body.set('client_assertion', assertion);
      const response = await this.fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', DPoP: proof }, body });
      const nonce = response.headers.get('dpop-nonce');
      const json = await response.json();
      if (nonce && nonce.length <= 512) {
        this.nonces.set(target.origin, nonce);
        if ((response.status === 400 || response.status === 401) && json.error === 'use_dpop_nonce' && attempt === 0) continue;
      }
      if (!response.ok) throw new Error(`OAuth request failed (${response.status})`);
      return json;
    }
    throw new Error('DPoP nonce negotiation failed');
  }
}

export async function verifyResourceProof({ proof, token, method, url, keys, issuer, resource, seen, now = Math.floor(Date.now() / 1000) }) {
  const header = JSON.parse(Buffer.from(proof.split('.')[0], 'base64url').toString());
  if (header.typ !== 'dpop+jwt' || header.alg !== 'ES256' || !header.jwk || header.jwk.d) throw new Error('invalid proof profile');
  const { payload } = await jwtVerify(proof, await importJWK(header.jwk, 'ES256'), { algorithms: ['ES256'], requiredClaims: ['iat', 'jti', 'htm', 'htu', 'ath'], currentDate: new Date(now * 1000), maxTokenAge: '5m' });
  const target = new URL(url); target.search = ''; target.hash = '';
  if (payload.htm !== method || payload.htu !== target.toString() || payload.ath !== createHash('sha256').update(token).digest('base64url') || typeof payload.jti !== 'string' || !payload.jti || payload.iat > now + 5) throw new Error('wrong proof binding');
  const thumbprint = await calculateJwkThumbprint(header.jwk);
  const verified = await jwtVerify(token, keys, { issuer, audience: resource, algorithms: ['EdDSA', 'ES256', 'PS256'], typ: 'at+jwt', requiredClaims: ['exp', 'iat'], currentDate: new Date(now * 1000) });
  if (verified.payload.cnf?.jkt !== thumbprint) throw new Error('wrong token key');
  for (const [key, expires] of seen) if (expires < now) seen.delete(key);
  const replay = `${thumbprint}:${payload.jti}`;
  if (seen.has(replay) || seen.size >= 10_000) throw new Error('replayed or saturated proof');
  seen.set(replay, now + 300);
  return verified.payload;
}

export function hasScope(claims, scope) {
  return typeof claims.scope === 'string' && claims.scope.split(' ').includes(scope);
}

export function sameOriginWrite(req, origin) {
  return req.headers.origin === origin && (req.headers['content-type'] ?? '').split(';')[0] === 'application/json';
}
