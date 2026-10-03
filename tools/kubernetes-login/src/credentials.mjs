import { spawn } from "node:child_process";
import { Failure, hash, requireValue } from "./security.mjs";

function command(executable, args, input = "") {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { stdio: ["pipe", "pipe", "pipe"] }),
      chunks = [];
    let bytes = 0,
      errorBytes = 0;
    const timer = setTimeout(() => {
      child.kill();
      reject(new Failure("credential_store_unavailable"));
    }, 10000);
    child.on("error", () => {
      clearTimeout(timer);
      reject(new Failure("credential_store_unavailable"));
    });
    child.stdout.on("data", (chunk) => {
      bytes += chunk.length;
      if (bytes > 16384) {
        child.kill();
        return;
      }
      chunks.push(chunk);
    });
    child.stderr.on("data", (chunk) => {
      errorBytes += chunk.length;
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (
        bytes > 16384 ||
        (code !== 0 &&
          !(
            code === 1 &&
            errorBytes === 0 &&
            ["lookup", "clear"].includes(args[0])
          ))
      )
        reject(new Failure("credential_store_unavailable"));
      else resolve(Buffer.concat(chunks).toString("utf8").trim());
    });
    child.stdin.on("error", () => {});
    child.stdin.end(input);
  });
}
// secret-tool supplies the secret on stdin. There is deliberately no file fallback.
export class CredentialStore {
  constructor(cluster, account, runner = command, platform = process.platform) {
    this.runner = runner;
    this.platform = platform;
    this.id = hash(
      JSON.stringify({
        broker: cluster.broker,
        issuer: cluster.issuer,
        client: cluster.clientId,
        cluster: cluster.id,
        server: cluster.server,
        account,
      }),
    );
  }
  async run(action, input) {
    requireValue(this.platform === "linux", "credential_store_unavailable");
    return this.runner(
      "/usr/bin/secret-tool",
      [
        action,
        ...(action === "store"
          ? ["--label=Asterius Kubernetes broker session"]
          : []),
        "application",
        "asterius-kubernetes",
        "partition",
        this.id,
      ],
      input,
    );
  }
  async get() {
    const value = await this.run("lookup");
    if (!value) return undefined;
    try {
      return JSON.parse(value);
    } catch {
      throw new Failure("invalid_stored_credential");
    }
  }
  async set(value) {
    await this.run("store", JSON.stringify(value));
  }
  async clear() {
    await this.run("clear");
  }
}
