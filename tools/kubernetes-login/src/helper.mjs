#!/usr/bin/env node
import { readFileSync, lstatSync, realpathSync } from "node:fs";
import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRemoteJWKSet } from "jose";
import { CredentialStore } from "./credentials.mjs";
import {
  boundedJson,
  Failure,
  https,
  identifier,
  newKey,
  now,
  random,
  requireValue,
  secret,
  signRequest,
  verifyIdentity,
} from "./security.mjs";

export function loadConfig(path, id) {
  const stat = lstatSync(path);
  requireValue(
    stat.isFile() &&
      !stat.isSymbolicLink() &&
      (stat.mode & 0o022) === 0 &&
      (stat.uid === 0 || stat.uid === process.getuid?.()),
    "untrusted_configuration",
  );
  const text = readFileSync(path, "utf8");
  requireValue(text.length <= 65536, "configuration_too_large");
  const config = JSON.parse(text),
    cluster = config.clusters?.find((c) => c.id === id);
  requireValue(cluster, "unknown_cluster");
  identifier(cluster.id);
  requireValue(
    https(cluster.broker).href === cluster.broker + "/",
    "invalid_broker_origin",
  );
  https(cluster.issuer);
  https(cluster.server);
  requireValue(
    https(cluster.jwksUri).origin === https(cluster.issuer).origin,
    "untrusted_jwks",
  );
  requireValue(
    typeof cluster.clientId === "string" && cluster.clientId.length > 0,
    "invalid_client",
  );
  return cluster;
}
export function validateExecInfo(value, cluster) {
  requireValue(
    typeof value === "string" && value.length <= 65536,
    "missing_exec_info",
  );
  let info;
  try {
    info = JSON.parse(value);
  } catch {
    throw new Failure("invalid_exec_info");
  }
  requireValue(
    info.apiVersion === "client.authentication.k8s.io/v1" &&
      info.kind === "ExecCredential" &&
      typeof info.spec?.interactive === "boolean" &&
      info.spec?.cluster?.server === cluster.server &&
      info.spec.cluster["insecure-skip-tls-verify"] !== true,
    "cluster_binding_failed",
  );
  requireValue(
    (info.spec.cluster["certificate-authority-data"] ?? "") ===
      (cluster.certificateAuthorityData ?? ""),
    "cluster_ca_binding_failed",
  );
  return info;
}
export function execCredential(token, expiration) {
  return {
    apiVersion: "client.authentication.k8s.io/v1",
    kind: "ExecCredential",
    status: {
      token,
      expirationTimestamp: new Date(expiration * 1000).toISOString(),
    },
  };
}
export function kubeconfig(
  cluster,
  configPath,
  account,
  command = fileURLToPath(import.meta.url),
) {
  return {
    apiVersion: "v1",
    kind: "Config",
    clusters: [
      {
        name: cluster.id,
        cluster: {
          server: cluster.server,
          ...(cluster.certificateAuthorityData
            ? { "certificate-authority-data": cluster.certificateAuthorityData }
            : {}),
        },
      },
    ],
    users: [
      {
        name: cluster.id + "-" + account,
        user: {
          exec: {
            apiVersion: "client.authentication.k8s.io/v1",
            command,
            args: [
              "exec",
              "--config",
              configPath,
              "--cluster",
              cluster.id,
              "--account",
              account,
            ],
            interactiveMode: "IfAvailable",
            provideClusterInfo: true,
          },
        },
      },
    ],
    contexts: [
      {
        name: cluster.id,
        context: { cluster: cluster.id, user: cluster.id + "-" + account },
      },
    ],
    "current-context": cluster.id,
  };
}
export class Helper {
  constructor(cluster, store, options = {}) {
    this.cluster = cluster;
    this.store = store;
    this.transport = options.transport ?? fetch;
    this.open = options.open ?? openBrowser;
    this.diagnostic =
      options.diagnostic ?? ((line) => process.stderr.write(line + "\n"));
    this.keys =
      options.keySet ??
      createRemoteJWKSet(new URL(cluster.jwksUri), { timeoutDuration: 10000 });
  }
  async post(path, body, key, signal) {
    const proof = await signRequest(
      key.privateJwk,
      key.publicJwk,
      this.cluster.broker,
      path,
      body,
    );
    const response = await this.transport(this.cluster.broker + path, {
      method: "POST",
      redirect: "error",
      signal: signal
        ? AbortSignal.any([signal, AbortSignal.timeout(20000)])
        : AbortSignal.timeout(20000),
      headers: { "Content-Type": "application/json", "Asterius-Proof": proof },
      body: JSON.stringify(body),
    });
    const data = await boundedJson(response);
    if (!response.ok)
      throw new Failure(
        [
          "session_expired",
          "refresh_in_progress",
          "transaction_expired",
          "broker_busy",
        ].includes(data.error)
          ? data.error
          : "broker_request_failed",
        response.status,
      );
    return { status: response.status, data };
  }
  async login(interactive, signal) {
    requireValue(interactive, "login_required_run_interactively");
    const key = await newKey(),
      transactionSecret = random();
    let transaction;
    try {
      const { data } = await this.post(
        "/v1/transactions",
        { cluster: this.cluster.id, secret: transactionSecret },
        key,
        signal,
      );
      transaction = secret(data.transaction);
      const url = this.cluster.broker + "/login/" + transaction;
      requireValue(data.browserUrl === url, "untrusted_login_url");
      this.diagnostic(
        "Open " +
          url +
          " and confirm terminal reference " +
          transaction.slice(0, 12) +
          ".",
      );
      await this.open(url);
      const deadline = Date.now() + 300000;
      while (Date.now() < deadline) {
        if (signal?.aborted) throw new Failure("login_cancelled");
        const response = await this.post(
          "/v1/poll",
          { transaction, secret: transactionSecret },
          key,
          signal,
        );
        if (response.status === 200) {
          const claims = await verifyIdentity(
            response.data.idToken,
            this.keys,
            this.cluster,
            undefined,
            this.cluster.subject,
          );
          secret(response.data.handle);
          requireValue(
            response.data.expiration === claims.exp &&
              response.data.subject === claims.sub,
            "identity_binding_failed",
          );
          const session = {
            ...key,
            handle: response.data.handle,
            subject: claims.sub,
          };
          try {
            await this.store.set(session);
          } catch {
            this.diagnostic(
              "OS credential store unavailable: credentials remain in memory; the next invocation requires browser login.",
            );
          }
          return {
            session,
            token: response.data.idToken,
            expiration: claims.exp,
          };
        }
        requireValue(response.status === 202, "invalid_poll_response");
        await new Promise((resolve, reject) => {
          const abort = () => {
            clearTimeout(timer);
            reject(new Failure("login_cancelled"));
          };
          const timer = setTimeout(() => {
            signal?.removeEventListener("abort", abort);
            resolve();
          }, 1000);
          signal?.addEventListener("abort", abort, { once: true });
        });
      }
      throw new Failure("login_expired");
    } catch (error) {
      if (transaction)
        try {
          await this.post(
            "/v1/cancel",
            { transaction, secret: transactionSecret },
            key,
          );
        } catch {}
      throw error;
    }
  }
  async credential(interactive, signal) {
    let session;
    try {
      session = await this.store.get();
    } catch {
      this.diagnostic(
        "OS credential store unavailable: using an in-memory login.",
      );
    }
    if (session) {
      try {
        secret(session.handle);
        requireValue(
          session.privateJwk?.d &&
            session.publicJwk &&
            !session.publicJwk.d &&
            typeof session.subject === "string" &&
            (!this.cluster.subject || this.cluster.subject === session.subject),
          "invalid_stored_credential",
        );
        let result;
        for (let attempt = 0; attempt < 3; attempt++) {
          try {
            result = await this.post(
              "/v1/credential",
              { handle: session.handle },
              session,
              signal,
            );
            break;
          } catch (error) {
            if (error.code !== "refresh_in_progress") throw error;
            await new Promise((resolve) => setTimeout(resolve, 1000));
          }
        }
        requireValue(result, "refresh_in_progress");
        const claims = await verifyIdentity(
          result.data.idToken,
          this.keys,
          this.cluster,
          undefined,
          session.subject,
        );
        requireValue(
          result.data.expiration === claims.exp &&
            result.data.subject === claims.sub,
          "identity_binding_failed",
        );
        return { session, token: result.data.idToken, expiration: claims.exp };
      } catch (error) {
        if (error.code !== "session_expired") throw error;
        try {
          await this.store.clear();
        } catch {
          throw new Failure("credential_erase_failed");
        }
      }
    }
    return this.login(interactive, signal);
  }
  async logout() {
    let session;
    try {
      session = await this.store.get();
      await this.store.clear();
    } catch {
      throw new Failure("credential_erase_failed");
    }
    if (session)
      await this.post("/v1/logout", { handle: session.handle }, session);
    this.diagnostic(
      "Local credentials erased; broker session invalidated. Existing Kubernetes ID tokens expire within five minutes.",
    );
  }
}
function openBrowser(url) {
  const command =
    process.platform === "darwin"
      ? "/usr/bin/open"
      : process.platform === "linux"
        ? "/usr/bin/xdg-open"
        : undefined;
  if (!command) return;
  const child = spawn(command, [url], { stdio: "ignore", detached: true });
  child.on("error", () => {});
  child.unref();
}
export async function main(args = process.argv.slice(2)) {
  const [action, ...rest] = args;
  requireValue(
    ["exec", "login", "logout", "kubeconfig"].includes(action),
    "usage_exec_login_logout_kubeconfig",
  );
  const values = {};
  for (let i = 0; i < rest.length; i += 2) {
    requireValue(
      ["--config", "--cluster", "--account"].includes(rest[i]) &&
        rest[i + 1] &&
        !values[rest[i]],
      "invalid_arguments",
    );
    values[rest[i]] = rest[i + 1];
  }
  const cluster = loadConfig(values["--config"], values["--cluster"]),
    account = identifier(values["--account"] ?? "default");
  if (action === "kubeconfig") {
    process.stdout.write(
      JSON.stringify(
        kubeconfig(cluster, resolve(values["--config"]), account),
        null,
        2,
      ) + "\n",
    );
    return;
  }
  const helper = new Helper(cluster, new CredentialStore(cluster, account));
  if (action === "logout") {
    await helper.logout();
    return;
  }
  const controller = new AbortController();
  process.once("SIGINT", () => controller.abort());
  process.once("SIGTERM", () => controller.abort());
  const interactive =
    action === "login"
      ? true
      : validateExecInfo(process.env.KUBERNETES_EXEC_INFO, cluster).spec
          .interactive;
  const result = await helper.credential(interactive, controller.signal);
  if (action === "exec")
    process.stdout.write(
      JSON.stringify(execCredential(result.token, result.expiration)) + "\n",
    );
  else process.stderr.write("Kubernetes login ready.\n");
}
if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === realpathSync(process.argv[1])
)
  main().catch((error) => {
    process.stderr.write(
      "asterius-kube: " +
        (error instanceof Failure ? error.code : "connection_failed") +
        "\n",
    );
    process.exitCode = 1;
  });
