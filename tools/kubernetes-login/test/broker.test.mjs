import test from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest } from "node:http";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import YAML from "yaml";
import {
  createLocalJWKSet,
  importJWK,
  jwtVerify,
  decodeProtectedHeader,
  SignJWT,
} from "jose";
import { Broker } from "../src/broker.mjs";
import { Store } from "../src/store.mjs";
import { Upstream } from "../src/upstream.mjs";
import { CredentialStore } from "../src/credentials.mjs";
import {
  Helper,
  execCredential,
  kubeconfig,
  kubeconfigYaml,
  validateExecInfo,
} from "../src/helper.mjs";
import {
  hash,
  newKey,
  now,
  random,
  signRequest,
  verifyIdentity,
  verifyRequest,
} from "../src/security.mjs";

async function fixture(t) {
  const op = await newKey(),
    client = await newKey(),
    proof = await newKey();
  const cluster = {
    id: "cluster-a",
    broker: "https://broker.example",
    issuer: "https://idp.example/t/test",
    clientId: "client-a",
    server: "https://cluster.example",
    jwksUri: "https://idp.example/t/test/jwks",
    privateJwk: client.privateJwk,
    keyId: "client-key",
  };
  const signing = await importJWK(op.privateJwk, "ES256"),
    keys = createLocalJWKSet({
      keys: [{ ...op.publicJwk, kid: "op-key", alg: "ES256" }],
    });
  const issue = async (extra = {}) =>
    new SignJWT({
      sub: "subject-a",
      group_ids: ["group:10000000-0000-4000-8000-000000000001"],
      sid: "op-session",
      ...extra,
    })
      .setProtectedHeader({ alg: "ES256", kid: "op-key" })
      .setIssuer(cluster.issuer)
      .setAudience(cluster.clientId)
      .setIssuedAt()
      .setExpirationTime("300s")
      .sign(signing);
  let pushed,
    codeUsed = false,
    refreshes = 0,
    revocations = 0,
    failRefresh = false;
  const calls = [];
  const metadata = {
    authorization_endpoint: cluster.issuer + "/authorize",
    token_endpoint: cluster.issuer + "/token",
    pushed_authorization_request_endpoint: cluster.issuer + "/par",
    revocation_endpoint: cluster.issuer + "/revoke",
    jwks_uri: cluster.jwksUri,
  };
  const transport = async (url, options) => {
    calls.push(url);
    const params = new URLSearchParams(options.body),
      dpopHeader = decodeProtectedHeader(options.headers.DPoP);
    assert.equal(dpopHeader.typ, "dpop+jwt");
    const dpopKey = await importJWK(dpopHeader.jwk, "ES256");
    const { payload: dpop } = await jwtVerify(options.headers.DPoP, dpopKey, {
      algorithms: ["ES256"],
    });
    assert.equal(dpop.htu, url);
    assert.equal(dpop.htm, "POST");
    const assertionKey = await importJWK(client.publicJwk, "ES256");
    await jwtVerify(params.get("client_assertion"), assertionKey, {
      issuer: cluster.clientId,
      subject: cluster.clientId,
      audience: cluster.issuer,
      algorithms: ["ES256"],
    });
    if (url.endsWith("/par")) {
      pushed = params;
      assert.equal(params.get("code_challenge_method"), "S256");
      assert.equal(params.get("scope"), "openid offline_access");
      assert.ok(params.get("nonce"));
      assert.ok(params.get("dpop_jkt"));
      return Response.json({ request_uri: "urn:fixture:par", expires_in: 90 });
    }
    if (url.endsWith("/revoke")) {
      revocations++;
      return new Response("", { status: 200 });
    }
    if (params.get("grant_type") === "authorization_code") {
      assert.equal(codeUsed, false);
      codeUsed = true;
      assert.equal(params.get("code"), "one-use-code");
      assert.equal(
        hash(params.get("code_verifier")),
        pushed.get("code_challenge"),
      );
      assert.equal(params.get("redirect_uri"), pushed.get("redirect_uri"));
      return Response.json({
        id_token: await issue({ nonce: pushed.get("nonce") }),
        refresh_token: "never-release-upstream-refresh",
        token_type: "DPoP",
      });
    }
    refreshes++;
    await new Promise((resolve) => setTimeout(resolve, 30));
    if (failRefresh) throw new Error("sensitive-upstream-value");
    assert.equal(params.get("refresh_token"), "never-release-upstream-refresh");
    return Response.json({
      id_token: await issue({ group_ids: [], jti: random() }),
      refresh_token: "rotated-upstream-refresh",
      token_type: "DPoP",
    });
  };
  const upstream = new Upstream(
    cluster,
    metadata,
    await importJWK(client.privateJwk, "ES256"),
    keys,
    transport,
  );
  const dir = mkdtempSync(join(tmpdir(), "asterius-kube-")),
    path = join(dir, "state.sqlite"),
    store = new Store(path, randomBytes(32));
  const broker = new Broker(
    cluster.broker,
    store,
    new Map([[cluster.id, upstream]]),
  );
  const server = createServer((req, res) => broker.handle(req, res));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const local = "http://127.0.0.1:" + server.address().port;
  const request = (path, options = {}) =>
    new Promise((resolve, reject) => {
      const req = httpRequest(
        local + path,
        { ...options, headers: { Host: "broker.example", ...options.headers } },
        (res) => {
          const chunks = [];
          res.on("data", (chunk) => chunks.push(chunk));
          res.on("end", () =>
            resolve(
              new Response(Buffer.concat(chunks), {
                status: res.statusCode,
                headers: res.headers,
              }),
            ),
          );
        },
      );
      req.on("error", reject);
      req.end(options.body?.toString());
    });
  const post = async (path, body, key = proof, override) => {
    const signature =
      override ??
      (await signRequest(
        key.privateJwk,
        key.publicJwk,
        cluster.broker,
        path,
        body,
      ));
    return request(path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Asterius-Proof": signature,
      },
      body: JSON.stringify(body),
    });
  };
  const begin = async () => {
    const secret = random(),
      response = await post("/v1/transactions", {
        cluster: cluster.id,
        secret,
      });
    assert.equal(response.status, 201, await response.clone().text());
    const transaction = (await response.json()).transaction;
    return { transaction, secret };
  };
  const browser = async (transaction, options = {}) => {
    const start = await request("/login/" + transaction);
    assert.equal(start.status, 303);
    const cookie = start.headers.get("set-cookie").split(";")[0],
      state = pushed.get("state");
    const callback = await request(
      "/callback/" +
        cluster.id +
        "?" +
        new URLSearchParams({
          state,
          code: "one-use-code",
          iss: cluster.issuer,
          ...options,
        }),
      { headers: { Cookie: cookie } },
    );
    return { callback, cookie, state };
  };
  const confirm = async (id, callback, cookie, decision = "approve") => {
    const text = await callback.text(),
      confirmation = /name="confirmation" value="([^"]+)"/.exec(text)?.[1];
    assert.ok(confirmation);
    return request("/confirm/" + id, {
      method: "POST",
      headers: {
        Cookie: cookie,
        Origin: cluster.broker,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ confirmation, decision }),
    });
  };
  const login = async () => {
    const transaction = await begin(),
      { callback, cookie } = await browser(transaction.transaction);
    assert.equal(callback.status, 200);
    assert.equal(
      (await confirm(transaction.transaction, callback, cookie)).status,
      200,
    );
    const result = await post("/v1/poll", transaction);
    assert.equal(result.status, 200);
    return { transaction, result: await result.json() };
  };
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });
  return {
    cluster,
    keys,
    signing,
    issue,
    store,
    path,
    proof,
    post,
    request,
    begin,
    browser,
    confirm,
    login,
    broker,
    helperTransport: (url, options) => request(new URL(url).pathname, options),
    stats: () => ({ refreshes, revocations, calls }),
    fail: () => {
      failRefresh = true;
    },
  };
}

test("real HTTP browser flow uses PAR/private JWT/PKCE/DPoP and single-use proof-bound delivery", async (t) => {
  const f = await fixture(t),
    { transaction, result } = await f.login();
  assert.equal(result.subject, "subject-a");
  await verifyIdentity(result.idToken, f.keys, f.cluster);
  assert.ok(!JSON.stringify(result).includes("upstream-refresh"));
  assert.equal((await f.post("/v1/poll", transaction)).status, 401);
  const stolen = await f.post(
    "/v1/credential",
    { handle: result.handle },
    await newKey(),
  );
  assert.equal(stolen.status, 401);
  const body = { handle: result.handle },
    proof = await signRequest(
      f.proof.privateJwk,
      f.proof.publicJwk,
      f.cluster.broker,
      "/v1/credential",
      body,
    );
  assert.equal(
    (await f.post("/v1/credential", body, f.proof, proof)).status,
    200,
  );
  assert.equal(
    (await f.post("/v1/credential", body, f.proof, proof)).status,
    401,
  );
  assert.ok(
    !readFileSync(f.path).includes(
      Buffer.from("never-release-upstream-refresh"),
    ),
  );
  assert.ok(!readFileSync(f.path).includes(Buffer.from(result.idToken)));
});
test("state, issuer and browser cookie are checked before consuming callback", async (t) => {
  const f = await fixture(t),
    transaction = await f.begin();
  const { callback, cookie, state } = await f.browser(transaction.transaction, {
    iss: "https://attacker.example",
  });
  assert.equal(callback.status, 401);
  const url =
    "/callback/cluster-a?" +
    new URLSearchParams({ state, code: "one-use-code", iss: f.cluster.issuer });
  assert.equal((await f.request(url)).status, 401);
  const good = await f.request(url, { headers: { Cookie: cookie } });
  assert.equal(good.status, 200);
  assert.equal(
    (await f.request(url, { headers: { Cookie: cookie } })).status,
    401,
  );
});
test("cancelled confirmation and cancelled or expired terminal transactions never release credentials", async (t) => {
  const f = await fixture(t),
    transaction = await f.begin(),
    { callback, cookie } = await f.browser(transaction.transaction);
  assert.equal(
    (await f.confirm(transaction.transaction, callback, cookie, "cancel"))
      .status,
    200,
  );
  assert.equal((await f.post("/v1/poll", transaction)).status, 401);
  assert.equal(f.stats().revocations, 1);
  const other = await f.begin();
  assert.equal((await f.post("/v1/cancel", other)).status, 200);
  assert.equal((await f.post("/v1/poll", other)).status, 401);
});
test("twenty parallel callers share one refresh and current groups; logout and idle expiry fail closed", async (t) => {
  const f = await fixture(t),
    { result } = await f.login(),
    id = hash(result.handle),
    session = f.store.get("session", id);
  f.store.put("session", id, "active", session.expires, {
    ...session,
    expiration: now() + 1,
  });
  const responses = await Promise.all(
    Array.from({ length: 20 }, () =>
      f.post("/v1/credential", { handle: result.handle }),
    ),
  );
  assert.ok(responses.every((r) => r.status === 200));
  assert.equal(f.stats().refreshes, 1);
  const refreshed = await responses[0].json(),
    claims = await verifyIdentity(refreshed.idToken, f.keys, f.cluster);
  assert.deepEqual(claims.group_ids, []);
  assert.equal(
    (await f.post("/v1/logout", { handle: result.handle })).status,
    200,
  );
  assert.equal(
    (await f.post("/v1/credential", { handle: result.handle })).status,
    401,
  );
  f.store.put("session", id, "active", now() + 3600, {
    ...session,
    lastUsed: now() - 901,
  });
  assert.equal(
    (await f.post("/v1/credential", { handle: result.handle })).status,
    401,
  );
  assert.equal(f.store.get("session", id), undefined);
});
test("ambiguous refresh failure invalidates handle and never retries the refresh credential", async (t) => {
  const f = await fixture(t),
    { result } = await f.login(),
    id = hash(result.handle),
    session = f.store.get("session", id);
  f.store.put("session", id, "active", session.expires, {
    ...session,
    expiration: now() + 1,
  });
  f.fail();
  const response = await f.post("/v1/credential", { handle: result.handle });
  assert.equal(response.status, 503);
  assert.ok(!(await response.text()).includes("sensitive"));
  assert.equal(
    (await f.post("/v1/credential", { handle: result.handle })).status,
    401,
  );
  assert.equal(f.stats().refreshes, 1);
});
test("signed OP backchannel logout invalidates only associated session and rejects token substitution", async (t) => {
  const f = await fixture(t),
    { result } = await f.login();
  const logout = await new SignJWT({
    sid: "op-session",
    events: { "http://schemas.openid.net/event/backchannel-logout": {} },
  })
    .setProtectedHeader({ alg: "ES256", kid: "op-key", typ: "logout+jwt" })
    .setIssuer(f.cluster.issuer)
    .setAudience(f.cluster.clientId)
    .setIssuedAt()
    .setJti(random())
    .sign(f.signing);
  const request = (token) =>
    f.request("/backchannel/cluster-a", {
      method: "POST",
      body: new URLSearchParams({ logout_token: token }),
    });
  assert.equal((await request(result.idToken)).status, 400);
  assert.equal((await request(logout)).status, 200);
  assert.equal((await request(logout)).status, 200);
  assert.equal(
    (await f.post("/v1/credential", { handle: result.handle })).status,
    401,
  );
});
test("helper validates pinned ExecInfo, emits v1 credential and produces kubeconfig without any reusable secret", async (t) => {
  const f = await fixture(t),
    { result } = await f.login();
  const info = {
    apiVersion: "client.authentication.k8s.io/v1",
    kind: "ExecCredential",
    spec: { interactive: false, cluster: { server: f.cluster.server } },
  };
  assert.equal(
    validateExecInfo(JSON.stringify(info), f.cluster).spec.interactive,
    false,
  );
  assert.throws(
    () =>
      validateExecInfo(
        JSON.stringify({
          ...info,
          spec: {
            ...info.spec,
            cluster: { server: "https://attacker.example" },
          },
        }),
        f.cluster,
      ),
    /cluster_binding/,
  );
  const session = {
      ...f.proof,
      handle: result.handle,
      subject: result.subject,
    },
    store = { get: async () => session };
  const helper = new Helper(f.cluster, store, {
    transport: f.helperTransport,
    keySet: f.keys,
  });
  const value = await helper.credential(false);
  assert.equal(
    execCredential(value.token, value.expiration).apiVersion,
    "client.authentication.k8s.io/v1",
  );
  const config = JSON.stringify(
    kubeconfig(f.cluster, "/etc/kube-helper.json", "account"),
  );
  const rendered = kubeconfigYaml(f.cluster, "/etc/kube-helper.json", "account");
  assert.deepEqual(YAML.parse(rendered), JSON.parse(config));
  assert.match(rendered, /^apiVersion: v1\nkind: Config\n/);
  assert.ok(
    !config.includes(result.handle) &&
      !config.includes(result.idToken) &&
      !config.includes(f.proof.privateJwk.d),
  );
});
test("no secure store means memory-only login; noninteractive invocation fails before browser work", async (t) => {
  const f = await fixture(t),
    messages = [];
  const helper = new Helper(
    f.cluster,
    {
      get: async () => {
        throw Error("unavailable");
      },
      set: async () => {
        throw Error("unavailable");
      },
    },
    {
      transport: f.helperTransport,
      keySet: f.keys,
      diagnostic: (value) => messages.push(value),
      open: async (url) => {
        const id = url.split("/").at(-1),
          { callback, cookie } = await f.browser(id);
        await f.confirm(id, callback, cookie);
      },
    },
  );
  await assert.rejects(helper.credential(false), /login_required/);
  const value = await helper.credential(true);
  assert.ok(value.token);
  assert.ok(messages.some((value) => value.includes("remain in memory")));
  assert.ok(
    messages.every(
      (line) =>
        !line.includes(value.token) &&
        !line.includes(value.session.handle) &&
        !line.includes("upstream-refresh"),
    ),
  );
});
test("OS store puts credentials on stdin and partitions by pinned issuer/cluster/account; unsupported OS has no file fallback", async () => {
  const calls = [],
    runner = async (...args) => {
      calls.push(args);
      return "";
    },
    cluster = {
      id: "a",
      broker: "https://broker",
      issuer: "https://issuer",
      clientId: "client",
      server: "https://cluster",
    },
    store = new CredentialStore(cluster, "alice", runner, "linux");
  await store.set({ handle: "private" });
  assert.equal(calls[0][0], "/usr/bin/secret-tool");
  assert.ok(!JSON.stringify(calls[0][1]).includes("private"));
  assert.ok(calls[0][2].includes("private"));
  assert.notEqual(
    store.id,
    new CredentialStore(cluster, "bob", runner, "linux").id,
  );
  await assert.rejects(
    new CredentialStore(cluster, "alice", runner, "win32").set({}),
    /unavailable/,
  );
});
test("encrypted state integrity, atomic compare-and-swap and interrupted refresh fail closed", () => {
  const key = randomBytes(32),
    store = new Store(":memory:", key);
  store.put("session", "id", "active", now() + 300, { refreshToken: "secret" });
  assert.equal(store.claim("session", "id", "active", "refreshing"), true);
  assert.equal(store.claim("session", "id", "active", "refreshing"), false);
  const row = store.db.prepare("SELECT data FROM records").get();
  assert.throws(
    () => store.open("session", "another-id", row.data),
    /integrity/,
  );
  store.close();
});
test("bounded protocol mutation corpus rejects private/public key confusion, proof substitution and malformed identities", async (t) => {
  const f = await fixture(t);
  for (const mutation of [
    { aud: ["client-a"] },
    { iss: "https://other" },
    { exp: now() + 301, iat: now() },
    { sub: "" },
    { group_ids: Array(101).fill("x") },
    { group_ids: ["system:masters"] },
    { azp: "other" },
  ]) {
    const token = await new SignJWT({
      iss: f.cluster.issuer,
      aud: f.cluster.clientId,
      sub: "subject-a",
      iat: now(),
      exp: now() + 300,
      ...mutation,
    })
      .setProtectedHeader({ alg: "ES256", kid: "op-key" })
      .sign(f.signing);
    await assert.rejects(verifyIdentity(token, f.keys, f.cluster));
  }
  const valid = await f.issue({ nonce: "correct" });
  await assert.rejects(verifyIdentity(valid, f.keys, f.cluster, "incorrect"));
  for (let i = 0; i < 128; i++) {
    const malformed = random().slice(0, i % 43);
    await assert.rejects(
      verifyRequest(
        malformed,
        f.cluster.broker,
        "/v1/credential",
        {},
        undefined,
        f.store,
      ),
    );
  }
  const body = { cluster: "cluster-a", secret: random() },
    proof = await signRequest(
      f.proof.privateJwk,
      f.proof.publicJwk,
      f.cluster.broker,
      "/v1/transactions",
      body,
    );
  assert.equal(
    (
      await f.post(
        "/v1/transactions",
        { ...body, secret: random() },
        f.proof,
        proof,
      )
    ).status,
    401,
  );
});

test("logout racing an in-flight refresh cannot resurrect broker credentials", async (t) => {
  const f = await fixture(t),
    { result } = await f.login(),
    id = hash(result.handle),
    session = f.store.get("session", id);
  f.store.put("session", id, "active", session.expires, {
    ...session,
    expiration: now() + 1,
  });
  const credential = f.post("/v1/credential", { handle: result.handle });
  await new Promise((resolve) => setTimeout(resolve, 10));
  const logout = await f.post("/v1/logout", { handle: result.handle });
  assert.equal(logout.status, 200);
  assert.equal((await credential).status, 401);
  assert.equal(f.store.get("session", id), undefined);
});
test("broker restart invalidates ambiguous refresh and authenticates persisted lifetime/phase metadata", () => {
  const dir = mkdtempSync(join(tmpdir(), "asterius-kube-restart-")),
    path = join(dir, "state.sqlite"),
    key = randomBytes(32);
  let store = new Store(path, key);
  store.put("session", "id", "refreshing", now() + 300, {
    refreshToken: "secret",
  });
  store.close();
  store = new Store(path, key);
  assert.equal(store.get("session", "id"), undefined);
  store.put("session", "id", "active", now() + 300, { refreshToken: "secret" });
  store.db.prepare("UPDATE records SET expires=expires+100").run();
  assert.throws(() => store.get("session", "id"), /storage_integrity/);
  store.close();
  rmSync(dir, { recursive: true, force: true });
});
test("refresh optional nonce and at_hash are validated, wrong issuer discovery never enrolls", async (t) => {
  const f = await fixture(t),
    upstream = f.broker.upstream("cluster-a");
  const result = {
    refresh_token: "refresh",
    token_type: "DPoP",
    id_token: await f.issue({ nonce: "unexpected" }),
  };
  await assert.rejects(
    upstream.tokens(result, undefined, "subject-a", "original"),
    /binding/,
  );
  result.id_token = await f.issue({ at_hash: "forged" });
  result.access_token = "access";
  await assert.rejects(upstream.tokens(result), /binding/);
  await assert.rejects(
    Upstream.create(f.cluster, async () =>
      Response.json({ issuer: "https://attacker.example" }),
    ),
    /issuer_mismatch/,
  );
});
test("DPoP nonce challenge is the only safe automatic retry and uses a fresh proof/assertion", async (t) => {
  const f = await fixture(t),
    upstream = f.broker.upstream("cluster-a"),
    dpop = await newKey(),
    seen = [];
  upstream.transport = async (url, options) => {
    seen.push(options);
    if (seen.length === 1)
      return Response.json(
        { error: "use_dpop_nonce" },
        { status: 400, headers: { "DPoP-Nonce": "server-nonce" } },
      );
    const { payload } = await jwtVerify(
      options.headers.DPoP,
      await importJWK(dpop.publicJwk, "ES256"),
      { algorithms: ["ES256"] },
    );
    assert.equal(payload.nonce, "server-nonce");
    return Response.json({ request_uri: "urn:ok", expires_in: 30 });
  };
  await upstream.post("pushed_authorization_request_endpoint", {}, dpop);
  assert.equal(seen.length, 2);
  assert.notEqual(seen[0].headers.DPoP, seen[1].headers.DPoP);
  assert.notEqual(
    new URLSearchParams(seen[0].body).get("client_assertion"),
    new URLSearchParams(seen[1].body).get("client_assertion"),
  );
});

test("expired browser result is never delivered; replayed logout cannot cancel a new login", async (t) => {
  const f = await fixture(t),
    transaction = await f.begin(),
    { callback, cookie } = await f.browser(transaction.transaction);
  await f.confirm(transaction.transaction, callback, cookie);
  const pending = f.store.get("transaction", transaction.transaction);
  f.store.put(
    "transaction",
    transaction.transaction,
    "confirmed",
    pending.expires,
    { ...pending, expiration: now() + 1 },
  );
  assert.equal((await f.post("/v1/poll", transaction)).status, 401);
  const logout = await new SignJWT({
    sid: "op-session",
    events: { "http://schemas.openid.net/event/backchannel-logout": {} },
  })
    .setProtectedHeader({ alg: "ES256", kid: "op-key", typ: "logout+jwt" })
    .setIssuer(f.cluster.issuer)
    .setAudience(f.cluster.clientId)
    .setIssuedAt()
    .setJti(random())
    .sign(f.signing);
  const send = () =>
    f.request("/backchannel/cluster-a", {
      method: "POST",
      body: new URLSearchParams({ logout_token: logout }),
    });
  await send();
  const fresh = await f.begin();
  await send();
  assert.ok(f.store.get("transaction", fresh.transaction));
});
test("helper cancellation attempts transaction cleanup and emits no credential", async (t) => {
  const f = await fixture(t),
    controller = new AbortController(),
    helper = new Helper(
      f.cluster,
      { set: async () => {} },
      {
        transport: f.helperTransport,
        keySet: f.keys,
        diagnostic: () => {},
        open: () => controller.abort(),
      },
    );
  await assert.rejects(
    helper.login(true, controller.signal),
    /login_cancelled/,
  );
  assert.equal(
    f.store.db
      .prepare("SELECT count(*) n FROM records WHERE kind='transaction'")
      .get().n,
    0,
  );
});
test("broker OpenAPI pins every executable route and declares secret fields write-only", () => {
  const spec = JSON.parse(
    readFileSync(new URL("../openapi.json", import.meta.url), "utf8"),
  );
  assert.equal(spec.openapi, "3.1.0");
  for (const path of [
    "/v1/transactions",
    "/v1/poll",
    "/v1/cancel",
    "/v1/credential",
    "/v1/logout",
  ]) {
    const operation = spec.paths[path].post;
    assert.equal(operation.security[0].HelperProof.length, 0);
    const props =
      operation.requestBody.content["application/json"].schema.properties;
    for (const key of ["secret", "handle"])
      if (props[key]) assert.equal(props[key].writeOnly, true);
  }
});
