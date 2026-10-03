import {
  createRemoteJWKSet,
  importJWK,
  SignJWT,
  calculateJwkThumbprint,
} from "jose";
import {
  boundedJson,
  Failure,
  hash,
  https,
  newKey,
  now,
  random,
  requireValue,
  verifyIdentity,
} from "./security.mjs";

export class Upstream {
  constructor(cluster, metadata, key, keySet, transport = fetch) {
    this.cluster = cluster;
    this.metadata = metadata;
    this.key = key;
    this.keySet = keySet;
    this.transport = transport;
  }
  static async create(cluster, transport = fetch) {
    https(cluster.issuer);
    requireValue(
      typeof cluster.clientId === "string" &&
        cluster.clientId.length > 0 &&
        cluster.clientId.length <= 128,
      "invalid_client",
    );
    const response = await transport(
      cluster.issuer + "/.well-known/openid-configuration",
      { redirect: "error", signal: AbortSignal.timeout(10000) },
    );
    requireValue(response.ok, "discovery_failed", 502);
    const metadata = await boundedJson(response);
    requireValue(metadata.issuer === cluster.issuer, "issuer_mismatch");
    for (const name of [
      "authorization_endpoint",
      "token_endpoint",
      "pushed_authorization_request_endpoint",
      "jwks_uri",
      "revocation_endpoint",
    ])
      requireValue(
        https(metadata[name]).origin === https(cluster.issuer).origin,
        "untrusted_endpoint",
      );
    requireValue(
      cluster.privateJwk?.kty === "EC" &&
        cluster.privateJwk.crv === "P-256" &&
        typeof cluster.privateJwk.d === "string",
      "invalid_client_key",
    );
    requireValue(
      typeof cluster.keyId === "string" &&
        cluster.keyId.length > 0 &&
        cluster.keyId.length <= 128,
      "invalid_client_key_id",
    );
    const key = await importJWK(cluster.privateJwk, "ES256");
    return new Upstream(
      cluster,
      metadata,
      key,
      createRemoteJWKSet(new URL(metadata.jwks_uri), {
        timeoutDuration: 10000,
      }),
      transport,
    );
  }
  async post(endpoint, parameters, dpop) {
    const url = this.metadata[endpoint];
    let nonce;
    // Only an explicit nonce rejection proves the grant wasn't consumed.
    for (let attempt = 0; attempt < 2; attempt++) {
      const assertion = await new SignJWT({})
        .setProtectedHeader({
          alg: "ES256",
          typ: "JWT",
          kid: this.cluster.keyId,
        })
        .setIssuer(this.cluster.clientId)
        .setSubject(this.cluster.clientId)
        .setAudience(this.cluster.issuer)
        .setIssuedAt()
        .setExpirationTime("60s")
        .setJti(random())
        .sign(this.key);
      const proof = await new SignJWT({
        htu: url,
        htm: "POST",
        ...(nonce ? { nonce } : {}),
      })
        .setProtectedHeader({
          alg: "ES256",
          typ: "dpop+jwt",
          jwk: dpop.publicJwk,
        })
        .setIssuedAt()
        .setJti(random())
        .sign(await importJWK(dpop.privateJwk, "ES256"));
      const response = await this.transport(url, {
        method: "POST",
        redirect: "error",
        signal: AbortSignal.timeout(15000),
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          DPoP: proof,
        },
        body: new URLSearchParams({
          ...parameters,
          client_id: this.cluster.clientId,
          client_assertion_type:
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          client_assertion: assertion,
        }),
      });
      // RFC7009 success may have an empty body.
      if (endpoint === "revocation_endpoint" && response.ok) return {};
      const data = await boundedJson(response);
      if (!response.ok && data.error === "use_dpop_nonce" && attempt === 0) {
        nonce = response.headers.get("DPoP-Nonce");
        requireValue(nonce && nonce.length <= 1024, "invalid_dpop_nonce", 502);
        continue;
      }
      requireValue(response.ok, "upstream_rejected", 502);
      return data;
    }
    throw new Failure("upstream_rejected", 502);
  }
  async begin(callback) {
    const dpop = await newKey(),
      verifier = random(),
      state = random(),
      nonce = random();
    const result = await this.post(
      "pushed_authorization_request_endpoint",
      {
        response_type: "code",
        redirect_uri: callback,
        scope: "openid offline_access",
        prompt: "consent",
        state,
        nonce,
        code_challenge: hash(verifier),
        code_challenge_method: "S256",
        dpop_jkt: await calculateJwkThumbprint(dpop.publicJwk),
      },
      dpop,
    );
    requireValue(
      typeof result.request_uri === "string" &&
        result.request_uri.length <= 2048 &&
        Number.isInteger(result.expires_in) &&
        result.expires_in > 0,
      "invalid_par",
      502,
    );
    const authorize = new URL(this.metadata.authorization_endpoint);
    authorize.searchParams.set("client_id", this.cluster.clientId);
    authorize.searchParams.set("request_uri", result.request_uri);
    return { dpop, verifier, state, nonce, authorize: authorize.href };
  }
  async exchange(transaction, code, callback) {
    requireValue(
      typeof code === "string" && code.length > 0 && code.length <= 4096,
      "invalid_code",
    );
    return this.tokens(
      await this.post(
        "token_endpoint",
        {
          grant_type: "authorization_code",
          code,
          redirect_uri: callback,
          code_verifier: transaction.verifier,
        },
        transaction.dpop,
      ),
      transaction.nonce,
    );
  }
  async refresh(session) {
    return this.tokens(
      await this.post(
        "token_endpoint",
        { grant_type: "refresh_token", refresh_token: session.refreshToken },
        session.dpop,
      ),
      undefined,
      session.subject,
      session.nonce,
    );
  }
  async tokens(result, nonce, subject, refreshNonce) {
    requireValue(
      typeof result.refresh_token === "string" &&
        result.refresh_token.length > 0 &&
        result.refresh_token.length <= 16384 &&
        result.token_type?.toLowerCase() === "dpop",
      "invalid_token_response",
      502,
    );
    const claims = await verifyIdentity(
      result.id_token,
      this.keySet,
      this.cluster,
      nonce,
      subject,
    );
    requireValue(
      !subject || claims.nonce === undefined || claims.nonce === refreshNonce,
      "identity_binding_failed",
      502,
    );
    if (claims.at_hash !== undefined) {
      requireValue(
        typeof result.access_token === "string",
        "invalid_token_response",
        502,
      );
      const expected = Buffer.from(hash(result.access_token), "base64url")
        .subarray(0, 16)
        .toString("base64url");
      requireValue(claims.at_hash === expected, "identity_binding_failed", 502);
    }
    return {
      idToken: result.id_token,
      refreshToken: result.refresh_token,
      subject: claims.sub,
      sid: claims.sid,
      expiration: claims.exp,
    };
  }
  async revoke(session) {
    await this.post(
      "revocation_endpoint",
      { token: session.refreshToken, token_type_hint: "refresh_token" },
      session.dpop,
    );
  }
}
