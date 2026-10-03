import { createHash, randomBytes } from "node:crypto";
import {
  calculateJwkThumbprint,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  SignJWT,
} from "jose";
export class Failure extends Error {
  constructor(code, status = 400) {
    super(code);
    this.code = code;
    this.status = status;
  }
}
export const random = () => randomBytes(32).toString("base64url");
export const hash = (value) =>
  createHash("sha256").update(value).digest("base64url");
export const now = () => Math.floor(Date.now() / 1000);
export function requireValue(condition, code, status = 400) {
  if (!condition) throw new Failure(code, status);
}
export function identifier(value) {
  requireValue(
    typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value),
    "invalid_identifier",
  );
  return value;
}
export function secret(value) {
  requireValue(
    typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value),
    "invalid_secret",
  );
  return value;
}
export function https(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Failure("invalid_url");
  }
  requireValue(
    url.protocol === "https:" &&
      !url.username &&
      !url.password &&
      !url.hash &&
      !url.search,
    "https_required",
  );
  return url;
}
export function fields(value, names) {
  requireValue(
    value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.keys(value).every((key) => names.includes(key)),
    "invalid_fields",
  );
}
export async function newKey() {
  const { privateKey, publicKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  return {
    privateJwk: await exportJWK(privateKey),
    publicJwk: await exportJWK(publicKey),
  };
}
export async function publicKey(jwk) {
  fields(jwk, ["kty", "crv", "x", "y"]);
  requireValue(
    jwk.kty === "EC" &&
      jwk.crv === "P-256" &&
      typeof jwk.x === "string" &&
      typeof jwk.y === "string",
    "invalid_proof_key",
  );
  return {
    key: await importJWK(jwk, "ES256"),
    thumbprint: await calculateJwkThumbprint(jwk),
  };
}
export async function signRequest(privateJwk, publicJwk, origin, path, body) {
  return new SignJWT({
    htu: origin + path,
    htm: "POST",
    body: hash(JSON.stringify(body)),
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "asterius-kubernetes-proof+jwt",
      jwk: publicJwk,
    })
    .setAudience(origin)
    .setIssuedAt()
    .setExpirationTime("60s")
    .setJti(random())
    .sign(await importJWK(privateJwk, "ES256"));
}
export async function verifyRequest(
  proof,
  origin,
  path,
  body,
  expected,
  replayStore,
) {
  requireValue(
    typeof proof === "string" && proof.length <= 4096,
    "invalid_proof",
    401,
  );
  let result, thumbprint;
  try {
    const header = decodeProtectedHeader(proof);
    requireValue(
      header.typ === "asterius-kubernetes-proof+jwt",
      "invalid_proof",
      401,
    );
    const parsed = await publicKey(header.jwk);
    thumbprint = parsed.thumbprint;
    result = await jwtVerify(proof, parsed.key, {
      algorithms: ["ES256"],
      audience: origin,
      requiredClaims: ["iat", "exp", "jti"],
      maxTokenAge: 60,
    });
  } catch {
    throw new Failure("invalid_proof", 401);
  }
  const p = result.payload;
  requireValue(
    (!expected || expected === thumbprint) &&
      p.htu === origin + path &&
      p.htm === "POST" &&
      p.body === hash(JSON.stringify(body)) &&
      p.exp - p.iat <= 60 &&
      p.iat <= now() + 5,
    "invalid_proof",
    401,
  );
  secret(p.jti);
  requireValue(
    replayStore.useProof(hash(thumbprint + ":" + p.jti), p.exp),
    "replayed_proof",
    401,
  );
  return thumbprint;
}
export async function verifyIdentity(token, keySet, cluster, nonce, subject) {
  requireValue(
    typeof token === "string" && token.length <= 16384,
    "invalid_id_token",
    502,
  );
  let payload;
  try {
    ({ payload } = await jwtVerify(token, keySet, {
      algorithms: ["ES256"],
      issuer: cluster.issuer,
      audience: cluster.clientId,
      requiredClaims: ["sub", "iat", "exp"],
    }));
  } catch {
    throw new Failure("invalid_id_token", 502);
  }
  requireValue(
    payload.aud === cluster.clientId &&
      typeof payload.sub === "string" &&
      payload.sub.length > 0 &&
      payload.sub.length <= 512 &&
      Number.isSafeInteger(payload.iat) &&
      Number.isSafeInteger(payload.exp) &&
      payload.exp > payload.iat &&
      payload.exp - payload.iat <= 300 &&
      payload.iat <= now() + 5 &&
      payload.exp > now() + 30,
    "invalid_id_token",
    502,
  );
  requireValue(
    (nonce === undefined || payload.nonce === nonce) &&
      (!subject || subject === payload.sub) &&
      (payload.azp === undefined || payload.azp === cluster.clientId),
    "identity_binding_failed",
    502,
  );
  requireValue(
    payload.group_ids === undefined ||
      (Array.isArray(payload.group_ids) &&
        payload.group_ids.length <= 100 &&
        payload.group_ids.every(
          (group) =>
            typeof group === "string" &&
            /^group:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
              group,
            ),
        )),
    "invalid_groups",
    502,
  );
  requireValue(
    payload.sid === undefined ||
      (typeof payload.sid === "string" &&
        payload.sid.length > 0 &&
        payload.sid.length <= 512),
    "invalid_id_token",
    502,
  );
  return payload;
}
export function escapeHtml(value) {
  return String(value).replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
}
export async function boundedJson(response) {
  const reader = response.body?.getReader();
  requireValue(reader, "upstream_unavailable", 502);
  let length = 0;
  const chunks = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.length;
    if (length > 65536) {
      await reader.cancel();
      throw new Failure("response_too_large", 502);
    }
    chunks.push(Buffer.from(value));
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new Failure("invalid_response", 502);
  }
}
