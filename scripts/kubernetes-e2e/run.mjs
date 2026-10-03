import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createServer, request as httpsRequest } from "node:https";
import { spawn, spawnSync, execFileSync, execFile } from "node:child_process";
import { chromium } from "../../e2e/node_modules/playwright/index.mjs";
import {
  decodeJwt,
  decodeProtectedHeader,
} from "../../tools/kubernetes-login/node_modules/jose/dist/webapi/index.js";
import { Broker } from "../../tools/kubernetes-login/src/broker.mjs";
import { Store } from "../../tools/kubernetes-login/src/store.mjs";
import { Upstream } from "../../tools/kubernetes-login/src/upstream.mjs";
import { kubeconfig } from "../../tools/kubernetes-login/src/helper.mjs";
import { promisify } from "node:util";
const runFile = promisify(execFile);

const directory = process.env.KUBE_E2E_DIR,
  database = process.env.E2E_DATABASE_URL;
if (
  !directory ||
  !database ||
  !new URL(database).pathname.startsWith("/ast_dd1y14")
)
  throw Error("isolated_fixture_required");
const config = JSON.parse(readFileSync(directory + "/broker.json", "utf8")),
  publicConfig = JSON.parse(readFileSync(directory + "/public.json", "utf8"));
const adminConfig = JSON.parse(
  execFileSync(
    "kubectl",
    [
      "--kubeconfig",
      directory + "/admin-kubeconfig",
      "config",
      "view",
      "--raw",
      "-o",
      "json",
    ],
    { encoding: "utf8" },
  ),
);
const cluster = {
  id: "cluster-a",
  broker: publicConfig.broker,
  issuer: publicConfig.issuer,
  clientId: publicConfig.clientId,
  jwksUri: publicConfig.jwksUri,
  server: adminConfig.clusters[0].cluster.server,
  certificateAuthorityData:
    adminConfig.clusters[0].cluster["certificate-authority-data"],
};
const helperClusters = config.clusters.map((c) => ({
  ...cluster,
  id: c.id,
  issuer: c.issuer,
  clientId: c.clientId,
  jwksUri: c.issuer + "/jwks",
}));
writeFileSync(
  directory + "/helper.json",
  JSON.stringify({ clusters: helperClusters }),
  { mode: 0o600 },
);
execFileSync("docker", [
  "exec",
  "asterius-dd1y14-secret-service",
  "sh",
  "-c",
  "cp /fixture/helper.json /tmp/helper.json && chmod 600 /tmp/helper.json",
]);
writeFileSync(
  directory + "/helper-wrapper",
  `#!/bin/sh\nexec docker exec -i --env KUBERNETES_EXEC_INFO --env DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/asterius-bus --env NODE_EXTRA_CA_CERTS=/fixture/cert.pem asterius-dd1y14-secret-service node /repo/tools/kubernetes-login/src/helper.mjs "$@"\n`,
  { mode: 0o700 },
);
for (const c of helperClusters)
  writeFileSync(
    directory + "/" + c.id + "-kubeconfig.json",
    JSON.stringify(
      kubeconfig(
        c,
        "/tmp/helper.json",
        "fixture",
        directory + "/helper-wrapper",
      ),
    ),
    { mode: 0o600 },
  );
mkdirSync(directory + "/broker", { recursive: true, mode: 0o700 });
const store = new Store(
    config.database,
    Buffer.from(config.storageKey, "base64"),
  ),
  upstreams = new Map();
for (const c of config.clusters) upstreams.set(c.id, await Upstream.create(c));
for (const session of store.sessions()) {
  store.delete("session", session.id);
  try {
    await upstreams.get(session.cluster).revoke(session);
  } catch {}
}
try {
  execFileSync("docker", [
    "exec",
    "-e",
    "DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/asterius-bus",
    "asterius-dd1y14-secret-service",
    "/usr/bin/secret-tool",
    "clear",
    "application",
    "asterius-kubernetes",
  ]);
} catch {}
const broker = new Broker(config.origin, store, upstreams);
const httpsServer = createServer(
  {
    key: readFileSync(directory + "/key.pem"),
    cert: readFileSync(directory + "/cert.pem"),
  },
  (req, res) => broker.handle(req, res),
);
await new Promise((resolve) => httpsServer.listen(9449, "127.0.0.1", resolve));
const browser = await chromium.launch({
    headless: true,
    args: ["--no-sandbox", "--host-resolver-rules=MAP localhost 127.0.0.1"],
  }),
  context = await browser.newContext({ ignoreHTTPSErrors: true }),
  page = await context.newPage();
const cdp = await context.newCDPSession(page);
await cdp.send("WebAuthn.enable");
const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
  options: {
    protocol: "ctap2",
    transport: "internal",
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
  },
});
sql(
  `UPDATE tenants SET settings=jsonb_set(settings,'{refresh,rotation}','{"mode":"none"}'::jsonb) WHERE tenant_id='e2e-webauthn'`,
);
await new Promise((resolve) => setTimeout(resolve, 31000));
sql(
  "UPDATE users SET status='active' WHERE tenant_id='e2e-webauthn' AND user_id='3f1d5c2a-0000-4000-8000-000000000001'",
);
let enrollment = true,
  passkeyUsed = false;
const report = {
  date: new Date().toISOString(),
  clusterVersion: "v1.35.0",
  checks: [],
};
const check = (name, details = {}) => {
  report.checks.push({ name, ...details });
  process.stdout.write("PASS " + name + "\n");
};
async function authorize(url) {
  const selected = store.get("transaction", url.split("/").at(-1))?.cluster;
  if (!enrollment)
    await cdp.send("WebAuthn.setAutomaticPresenceSimulation", {
      authenticatorId,
      enabled: false,
    });
  await page.goto(url);
  if (
    await page
      .locator('input[name="password"]')
      .isVisible()
      .catch(() => false)
  ) {
    if (enrollment || selected === "cluster-c") {
      await page.locator('input[name="username"]').fill("sweep@example.test");
      await page
        .locator('input[name="password"]')
        .fill("correct horse battery staple");
      await page.getByRole("button", { name: "Sign in", exact: true }).click();
    } else {
      await cdp.send("WebAuthn.setAutomaticPresenceSimulation", {
        authenticatorId,
        enabled: false,
      });
      await page
        .getByRole("button", { name: "Sign in with a passkey", exact: true })
        .click();
      await cdp.send("WebAuthn.setAutomaticPresenceSimulation", {
        authenticatorId,
        enabled: true,
      });
      passkeyUsed = true;
    }
  }
  await page
    .getByRole("button", { name: "Allow", exact: true })
    .waitFor({ timeout: 15000 });
  await page.getByRole("button", { name: "Allow", exact: true }).click();
  await page
    .getByRole("button", { name: "Approve this terminal", exact: true })
    .waitFor({ timeout: 15000 });
  if (enrollment) {
    const enroll = await context.newPage(),
      session = await context.newCDPSession(enroll);
    await session.send("WebAuthn.enable");
    const { authenticatorId: second } = await session.send(
      "WebAuthn.addVirtualAuthenticator",
      {
        options: {
          protocol: "ctap2",
          transport: "internal",
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          automaticPresenceSimulation: true,
        },
      },
    );
    await enroll.goto(cluster.issuer + "/passkeys");
    await enroll
      .getByRole("button", { name: "Create a passkey", exact: true })
      .click();
    let credentials;
    for (let i = 0; i < 50; i++) {
      ({ credentials } = await session.send("WebAuthn.getCredentials", {
        authenticatorId: second,
      }));
      if (credentials.length) break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.equal(credentials.length, 1);
    await cdp.send("WebAuthn.addCredential", {
      authenticatorId,
      credential: credentials[0],
    });
    await enroll.close();
    enrollment = false;
    check("real Chromium WebAuthn resident passkey enrolled");
  }
  const [confirmation] = await Promise.all([
    page.waitForResponse((response) => response.url().includes("/confirm/")),
    page
      .getByRole("button", { name: "Approve this terminal", exact: true })
      .click(),
  ]);
  assert.equal(confirmation.status(), 200, await confirmation.text());
}
async function kube(args, expected = 0, selected = "cluster-a") {
  return new Promise((resolve, reject) => {
    const command = [
      "kubectl",
      "--kubeconfig",
      directory + "/" + selected + "-kubeconfig.json",
      "--request-timeout=15s",
      ...args,
    ]
      .map((v) => "'" + v.replaceAll("'", "'\\''") + "'")
      .join(" ");
    const child = spawn(
        "/usr/bin/script",
        ["-q", "-e", "-c", command, "/dev/null"],
        { stdio: ["pipe", "pipe", "pipe"] },
      ),
      chunks = [];
    let pending = false,
      flowError;
    const timer = setTimeout(() => {
      child.kill();
      reject(Error("kubectl_timeout"));
    }, 60000);
    const collect = (chunk) => {
      const value = chunk.toString();
      chunks.push(value);
      const match = value.match(
        /https:\/\/localhost:9449\/login\/[A-Za-z0-9_-]{43}/,
      );
      if (match && !pending) {
        pending = true;
        authorize(match[0]).catch((error) => {
          flowError = error;
          child.kill();
        });
      }
    };
    child.stdout.on("data", collect);
    child.stderr.on("data", collect);
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      const output = chunks.join("");
      if (flowError) return reject(flowError);
      assert.ok(!output.includes("eyJ"), "credential leaked to diagnostics");
      if (expected === 0 && code !== 0)
        return reject(Error("kubectl_failed: " + output));
      if (expected !== 0 && code === 0)
        return reject(Error("kubectl_unexpectedly_allowed"));
      resolve({ code, output });
    });
    child.stdin.write("\n");
  });
}
function sql(value) {
  return execFileSync(
    "psql",
    [database, "-q", "-v", "ON_ERROR_STOP=1", "-c", value],
    { encoding: "utf8" },
  );
}
function latest() {
  const rows = store.sessions().filter((v) => v.cluster === "cluster-a");
  assert.equal(rows.length, 1);
  return rows[0];
}
function forceRefresh() {
  const session = latest(),
    record = store.get("session", session.id);
  store.put("session", session.id, "active", record.expires, {
    ...record,
    expiration: Math.floor(Date.now() / 1000) + 1,
  });
}
async function api(token, path) {
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      cluster.server + path,
      {
        ca: Buffer.from(cluster.certificateAuthorityData, "base64"),
        headers: { Authorization: "Bearer " + token },
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode));
      },
    );
    req.on("error", reject);
    req.end();
  });
}
async function logout() {
  await runFile(
    directory + "/helper-wrapper",
    [
      "logout",
      "--config",
      "/tmp/helper.json",
      "--cluster",
      "cluster-a",
      "--account",
      "fixture",
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
}
try {
  await kube(["get", "configmaps", "-n", "human-access", "-o", "name"]);
  check("kubectl obtains verified ExecCredential and namespace read succeeds");
  await kube(
    [
      "create",
      "configmap",
      "forbidden-write",
      "--from-literal=x=y",
      "-n",
      "human-access",
    ],
    1,
  );
  check("write denied by namespace view RBAC");
  await kube(["get", "secrets", "-n", "human-access"], 1);
  check("secret read denied by view RBAC");
  await logout();
  await context.clearCookies();
  await kube(["get", "configmaps", "-n", "human-access", "-o", "name"]);
  assert.equal(passkeyUsed, true);
  check("actual helper external browser passkey login succeeds");
  const initial = latest(),
    refreshToken = initial.refreshToken,
    original = initial.idToken;
  forceRefresh();
  await kube(["get", "configmaps", "-n", "human-access", "-o", "name"]);
  assert.ok(latest().refreshToken === refreshToken, "stable_refresh_changed");
  check("actual Asterius default stable sender-bound refresh accepted");
  sql(
    `UPDATE tenants SET settings=jsonb_set(settings,'{refresh,rotation}','{"mode":"migration","grace_seconds":30}'::jsonb) WHERE tenant_id='e2e-webauthn'`,
  );
  process.stdout.write(
    "Waiting for actual 30-second tenant snapshot after fixture policy change.\n",
  );
  await new Promise((resolve) => setTimeout(resolve, 31000));
  forceRefresh();
  await kube(["get", "configmaps", "-n", "human-access", "-o", "name"]);
  assert.ok(
    latest().refreshToken !== refreshToken,
    "migration_refresh_did_not_rotate",
  );
  check(
    "actual Asterius explicit migration refresh rotates and helper adopts it",
  );
  const removedAt = Date.now();
  sql(
    "DELETE FROM group_memberships WHERE tenant_id='e2e-webauthn' AND group_id='10000000-0000-4000-8000-000000000001'",
  );
  forceRefresh();
  await kube(["get", "configmaps", "-n", "human-access", "-o", "name"], 1);
  assert.ok(!decodeJwt(latest().idToken).group_ids?.length);
  assert.equal(
    await api(original, "/api/v1/namespaces/human-access/configmaps"),
    200,
  );
  check(
    "group removal blocks new refreshed identity while issued JWT remains valid",
    { refreshDenialMilliseconds: Date.now() - removedAt },
  );
  sql(
    "INSERT INTO group_memberships(tenant_id,group_id,user_id,created_at) VALUES('e2e-webauthn','10000000-0000-4000-8000-000000000001','3f1d5c2a-0000-4000-8000-000000000001',now())",
  );
  forceRefresh();
  await kube(["get", "configmaps", "-n", "human-access", "-o", "name"]);
  await kube(
    ["get", "configmaps", "-n", "human-access", "-o", "name"],
    1,
    "cluster-b",
  );
  const b = store.sessions().find((s) => s.cluster === "cluster-b");
  assert.equal(
    await api(b.idToken, "/api/v1/namespaces/human-access/configmaps"),
    401,
  );
  check("actual Asterius token for different cluster audience rejected");
  await kube(
    ["get", "configmaps", "-n", "human-access", "-o", "name"],
    1,
    "cluster-c",
  );
  const c = store.sessions().find((s) => s.cluster === "cluster-c");
  assert.equal(
    await api(c.idToken, "/api/v1/namespaces/human-access/configmaps"),
    401,
  );
  check("actual different Asterius issuer identity rejected");
  const beforeRotation = latest().idToken,
    beforeKid = decodeProtectedHeader(beforeRotation).kid;
  await page.goto(cluster.issuer + "/admin/");
  await page.getByRole("link", { name: "Signing keys", exact: true }).click();
  const section = page
    .locator('section[aria-labelledby^="alg-"]')
    .filter({ has: page.getByRole("heading", { name: "ES256", exact: true }) });
  await section
    .getByRole("button", { name: "Rotate and sign immediately", exact: true })
    .click();
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Rotate and sign immediately", exact: true })
    .click();
  await page
    .getByRole("status")
    .filter({ hasText: "is now signing" })
    .waitFor({ timeout: 15000 });
  assert.equal(
    await api(beforeRotation, "/api/v1/namespaces/human-access/configmaps"),
    200,
  );
  process.stdout.write(
    "Waiting for broker JWKS cooldown before new signing key use.\n",
  );
  await new Promise((resolve) => setTimeout(resolve, 31000));
  forceRefresh();
  const propagationStarted = Date.now();
  let initialKeyPropagationRejection = false;
  try {
    await kube(["get", "configmaps", "-n", "human-access", "-o", "name"]);
  } catch (error) {
    if (!error.message.includes("(Unauthorized)")) throw error;
    initialKeyPropagationRejection = true;
  }
  let rotated = latest();
  const newKid = decodeProtectedHeader(rotated.idToken).kid;
  let nativeStatus;
  do {
    nativeStatus = await api(
      rotated.idToken,
      "/api/v1/namespaces/human-access/configmaps",
    );
    if (nativeStatus === 200) break;
    assert.equal(nativeStatus, 401, "unexpected_rotation_status");
    if (decodeJwt(rotated.idToken).exp * 1000 - Date.now() < 60000) {
      forceRefresh();
      try {
        await kube(["get", "configmaps", "-n", "human-access", "-o", "name"]);
      } catch (error) {
        if (!error.message.includes("(Unauthorized)")) throw error;
      }
      rotated = latest();
      assert.equal(decodeProtectedHeader(rotated.idToken).kid, newKid);
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  } while (Date.now() - propagationStarted < 360000);
  assert.equal(
    nativeStatus,
    200,
    "new_key_did_not_converge_within_jwks_cache_bound",
  );
  await kube(["get", "configmaps", "-n", "human-access", "-o", "name"]);
  assert.ok(newKid !== beforeKid, "tenant_rotation_did_not_change_kid");
  const jwks = await (await fetch(cluster.jwksUri)).json();
  assert.ok(
    jwks.keys.some((k) => k.kid === beforeKid) &&
      jwks.keys.some((k) => k.kid === newKid),
  );
  check(
    "real ES256 signing key rotation: old JWT retained and newly signed credential accepted",
    {
      initialKeyPropagationRejection,
      propagationMilliseconds: Date.now() - propagationStarted,
    },
  );
  const suspendedAt = Date.now(),
    held = rotated.idToken;
  sql(
    "UPDATE users SET status='disabled' WHERE tenant_id='e2e-webauthn' AND user_id='3f1d5c2a-0000-4000-8000-000000000001'",
  );
  forceRefresh();
  await kube(["get", "configmaps", "-n", "human-access", "-o", "name"], 1);
  assert.equal(
    await api(held, "/api/v1/namespaces/human-access/configmaps"),
    200,
  );
  check(
    "account disable blocks actual refresh while existing offline JWT remains usable",
    { refreshDenialMilliseconds: Date.now() - suspendedAt },
  );
  sql(
    "UPDATE users SET status='active' WHERE tenant_id='e2e-webauthn' AND user_id='3f1d5c2a-0000-4000-8000-000000000001'",
  );
  await kube(["get", "configmaps", "-n", "human-access", "-o", "name"]);
  const loggedOut = latest(),
    logoutAt = Date.now();
  await logout();
  assert.equal(store.get("session", loggedOut.id), undefined);
  await assert.rejects(
    upstreams.get("cluster-a").refresh(loggedOut),
    /upstream_rejected/,
  );
  assert.equal(
    await api(loggedOut.idToken, "/api/v1/namespaces/human-access/configmaps"),
    200,
  );
  check(
    "helper logout erases OS credential, invalidates broker and revokes actual OP refresh grant without revoking issued JWT",
  );
  const wait = Math.max(0, decodeJwt(held).exp * 1000 - Date.now() + 1500);
  process.stdout.write(
    "Waiting " +
      Math.ceil(wait / 1000) +
      "s for an actual five-minute issued JWT to expire.\n",
  );
  await new Promise((resolve) => setTimeout(resolve, wait));
  assert.equal(
    await api(held, "/api/v1/namespaces/human-access/configmaps"),
    401,
  );
  check("disabled-user offline JWT rejected after its actual signed expiry", {
    nativeDenialMilliseconds: Date.now() - suspendedAt,
  });
  const remaining = Math.max(
    0,
    decodeJwt(loggedOut.idToken).exp * 1000 - Date.now() + 1500,
  );
  await new Promise((resolve) => setTimeout(resolve, remaining));
  assert.equal(
    await api(loggedOut.idToken, "/api/v1/namespaces/human-access/configmaps"),
    401,
  );
  check("logged-out JWT rejected after actual expiry", {
    nativeDenialMilliseconds: Date.now() - logoutAt,
  });
  writeFileSync(
    directory + "/evidence.json",
    JSON.stringify(report, null, 2) + "\n",
  );
} catch (error) {
  try {
    const container = execFileSync(
      "docker",
      [
        "exec",
        "asterius-dd1y14-control-plane",
        "crictl",
        "ps",
        "-q",
        "--name",
        "kube-apiserver",
      ],
      { encoding: "utf8" },
    ).trim();
    const diagnostic = spawnSync(
      "docker",
      ["exec", "asterius-dd1y14-control-plane", "crictl", "logs", container],
      { encoding: "utf8", maxBuffer: 2097152 },
    );
    const logs = (diagnostic.stdout || "") + (diagnostic.stderr || "");
    writeFileSync(
      "/tmp/asterius-dd1y14-apiserver-diagnostic.log",
      logs.replace(/eyJ[A-Za-z0-9_.-]+/g, "[redacted JWT]"),
      { mode: 0o600 },
    );
  } catch {}
  process.stderr.write("Acceptance failure: " + error.message + "\n");
  throw error;
} finally {
  for (const session of store.sessions()) {
    store.delete("session", session.id);
    try {
      await upstreams.get(session.cluster).revoke(session);
    } catch {}
  }
  await browser.close();
  await new Promise((resolve) => httpsServer.close(resolve));
  store.close();
}
