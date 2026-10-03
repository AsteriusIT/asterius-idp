#!/usr/bin/env node
import { createServer } from "node:http";
import {
  readFileSync,
  lstatSync,
  mkdirSync,
  openSync,
  writeFileSync,
  closeSync,
  unlinkSync,
} from "node:fs";
import { dirname, isAbsolute } from "node:path";
import { Store } from "./store.mjs";
import { Broker } from "./broker.mjs";
import { Upstream } from "./upstream.mjs";
import { Failure, https, identifier, requireValue } from "./security.mjs";
async function main() {
  requireValue(process.argv.length === 3, "usage_broker_config");
  const path = process.argv[2],
    stat = lstatSync(path);
  requireValue(
    stat.isFile() &&
      !stat.isSymbolicLink() &&
      (stat.mode & 0o077) === 0 &&
      stat.uid === process.getuid?.(),
    "unsafe_broker_configuration",
  );
  const text = readFileSync(path, "utf8");
  requireValue(text.length <= 65536, "configuration_too_large");
  const config = JSON.parse(text);
  requireValue(
    https(config.origin).href === config.origin + "/",
    "invalid_broker_origin",
  );
  requireValue(
    Array.isArray(config.clusters) &&
      config.clusters.length > 0 &&
      config.clusters.length <= 100,
    "invalid_clusters",
  );
  const upstreams = new Map(),
    audiences = new Set();
  for (const cluster of config.clusters) {
    identifier(cluster.id);
    requireValue(!upstreams.has(cluster.id), "duplicate_cluster");
    const audience = JSON.stringify([cluster.issuer, cluster.clientId]);
    requireValue(!audiences.has(audience), "duplicate_cluster_audience");
    audiences.add(audience);
    upstreams.set(cluster.id, await Upstream.create(cluster));
  }
  requireValue(
    typeof config.database === "string" && isAbsolute(config.database),
    "absolute_database_required",
  );
  mkdirSync(dirname(config.database), { recursive: true, mode: 0o700 });
  requireValue(
    (lstatSync(dirname(config.database)).mode & 0o077) === 0,
    "unsafe_storage_directory",
  );
  const lockPath = config.database + ".lock";
  let lock;
  try {
    lock = openSync(lockPath, "wx", 0o600);
  } catch {
    throw new Failure("broker_already_running_or_stale_lock");
  }
  writeFileSync(lock, String(process.pid));
  closeSync(lock);
  const store = new Store(
      config.database,
      Buffer.from(config.storageKey, "base64"),
    ),
    broker = new Broker(config.origin, store, upstreams);
  requireValue(
    Number.isInteger(config.port) &&
      config.port >= 1024 &&
      config.port <= 65535,
    "invalid_port",
  );
  const server = createServer((req, res) => broker.handle(req, res));
  server.requestTimeout = 20000;
  server.headersTimeout = 10000;
  server.maxHeadersCount = 40;
  server.listen(config.port, "127.0.0.1", () =>
    process.stderr.write(
      "Kubernetes broker listening on loopback; HTTPS reverse proxy required.\n",
    ),
  );
  process.once("SIGTERM", () =>
    server.close(() => {
      store.close();
      unlinkSync(lockPath);
      process.exit(0);
    }),
  );
}
main().catch((error) => {
  process.stderr.write(
    "asterius-kube-broker: " +
      (error instanceof Failure ? error.code : "startup_failed") +
      "\n",
  );
  process.exitCode = 1;
});
