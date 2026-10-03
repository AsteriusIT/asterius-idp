import { DatabaseSync } from "node:sqlite";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, lstatSync } from "node:fs";
import { dirname } from "node:path";
import { Failure, now, requireValue } from "./security.mjs";
// Broker-local state, not an IdP identity database. Sealed rows bind table/id AAD.
export class Store {
  constructor(path, key) {
    requireValue(
      Buffer.isBuffer(key) && key.length === 32,
      "invalid_storage_key",
    );
    this.key = key;
    if (path !== ":memory:") {
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
      requireValue(
        (lstatSync(dirname(path)).mode & 0o077) === 0,
        "unsafe_storage_directory",
      );
      try {
        requireValue(!lstatSync(path).isSymbolicLink(), "unsafe_storage_file");
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
    }
    this.db = new DatabaseSync(path);
    if (path !== ":memory:") chmodSync(path, 0o600);
    this.db.exec(
      `PRAGMA busy_timeout=5000; PRAGMA journal_mode=DELETE; CREATE TABLE IF NOT EXISTS records(kind TEXT NOT NULL,id TEXT NOT NULL,phase TEXT NOT NULL,expires INTEGER NOT NULL,data TEXT NOT NULL,PRIMARY KEY(kind,id)); CREATE TABLE IF NOT EXISTS proofs(id TEXT PRIMARY KEY,expires INTEGER NOT NULL);`,
    );
    // Interrupted exchanges/refreshes are ambiguous and must never be replayed.
    this.db
      .prepare(
        "DELETE FROM records WHERE phase IN ('exchanging','refreshing') OR expires<=?",
      )
      .run(now());
  }
  seal(kind, id, value) {
    const iv = randomBytes(12),
      cipher = createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(Buffer.from(`${kind}:${id}`));
    const ciphertext = Buffer.concat([
      cipher.update(JSON.stringify(value)),
      cipher.final(),
    ]);
    return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString(
      "base64",
    );
  }
  open(kind, id, sealed) {
    try {
      const bytes = Buffer.from(sealed, "base64"),
        decipher = createDecipheriv(
          "aes-256-gcm",
          this.key,
          bytes.subarray(0, 12),
        );
      decipher.setAAD(Buffer.from(`${kind}:${id}`));
      decipher.setAuthTag(bytes.subarray(12, 28));
      return JSON.parse(
        Buffer.concat([
          decipher.update(bytes.subarray(28)),
          decipher.final(),
        ]).toString(),
      );
    } catch {
      throw new Failure("storage_integrity_failed", 503);
    }
  }
  put(kind, id, phase, expires, value) {
    this.db.prepare("DELETE FROM records WHERE expires<=?").run(now());
    this.db
      .prepare(
        "INSERT INTO records VALUES(?,?,?,?,?) ON CONFLICT(kind,id) DO UPDATE SET phase=excluded.phase,expires=excluded.expires,data=excluded.data",
      )
      .run(
        kind,
        id,
        phase,
        expires,
        this.seal(kind, id, {
          ...value,
          recordPhase: phase,
          absoluteExpires: expires,
        }),
      );
  }
  get(kind, id) {
    const row = this.db
      .prepare("SELECT * FROM records WHERE kind=? AND id=?")
      .get(kind, id);
    if (!row || row.expires <= now()) {
      this.delete(kind, id);
      return undefined;
    }
    const value = this.open(kind, id, row.data);
    requireValue(
      value.recordPhase === row.phase && value.absoluteExpires === row.expires,
      "storage_integrity_failed",
      503,
    );
    return { ...value, phase: row.phase, expires: row.expires };
  }
  claim(kind, id, phase, next) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const value = this.get(kind, id);
      if (!value || value.phase !== phase) {
        this.db.exec("ROLLBACK");
        return false;
      }
      this.put(kind, id, next, value.expires, value);
      this.db.exec("COMMIT");
      return true;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }
  delete(kind, id) {
    this.db.prepare("DELETE FROM records WHERE kind=? AND id=?").run(kind, id);
  }
  useProof(id, expires) {
    this.db.prepare("DELETE FROM proofs WHERE expires<=?").run(now());
    try {
      this.db.prepare("INSERT INTO proofs VALUES(?,?)").run(id, expires);
      return true;
    } catch {
      return false;
    }
  }
  sessions() {
    return this.db
      .prepare("SELECT id,data FROM records WHERE kind='session'")
      .all()
      .map((row) => ({
        id: row.id,
        ...this.open("session", row.id, row.data),
      }));
  }
  close() {
    this.db.close();
  }
}
