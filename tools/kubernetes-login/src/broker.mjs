import { jwtVerify } from "jose";
import {
  boundedJson,
  escapeHtml,
  Failure,
  fields,
  hash,
  identifier,
  now,
  random,
  requireValue,
  secret,
  verifyRequest,
} from "./security.mjs";

const headers = {
  "Cache-Control": "no-store",
  Pragma: "no-cache",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "Content-Security-Policy":
    "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
};
function reply(res, status, body, type = "application/json", extra = {}) {
  res.writeHead(status, { ...headers, "Content-Type": type, ...extra });
  res.end(type === "application/json" ? JSON.stringify(body) : body);
}
async function body(req, json = true) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    requireValue(size <= 16384, "request_too_large", 413);
    chunks.push(chunk);
  }
  const value = Buffer.concat(chunks).toString("utf8");
  if (!json) return new URLSearchParams(value);
  try {
    return JSON.parse(value);
  } catch {
    throw new Failure("invalid_json");
  }
}
const cookie = (req, id) =>
  String(req.headers.cookie ?? "")
    .split(";")
    .some((v) => v.trim() === `asterius_${id}=` + req.browserSecret);
const html = (title, content) =>
  `<!doctype html><html lang="en"><meta charset="utf-8"><title>${escapeHtml(title)}</title><body><h1>${escapeHtml(title)}</h1>${content}</body></html>`;
export class Broker {
  constructor(origin, store, upstreams) {
    this.origin = origin;
    this.store = store;
    this.upstreams = upstreams;
    this.pending = new Map();
  }
  upstream(cluster) {
    const value = this.upstreams.get(cluster);
    requireValue(value, "unknown_cluster", 404);
    return value;
  }
  callback(cluster) {
    return this.origin + "/callback/" + cluster;
  }
  async revoke(session) {
    try {
      await this.upstream(session.cluster).revoke(session);
    } catch {
      /* Local invalidation still prevents future issuance. No raw errors or tokens logged. */
    }
  }
  async session(body, path, req) {
    fields(body, ["handle"]);
    const id = hash(secret(body.handle)),
      session = this.store.get("session", id);
    requireValue(session, "session_expired", 401);
    await verifyRequest(
      req.headers["asterius-proof"],
      this.origin,
      path,
      body,
      session.thumbprint,
      this.store,
    );
    if (session.lastUsed + 900 <= now()) {
      this.store.delete("session", id);
      await this.revoke(session);
      throw new Failure("session_expired", 401);
    }
    const current = this.store.get("session", id);
    requireValue(current, "session_expired", 401);
    return { id, session: current };
  }
  async transaction(body, path, req) {
    fields(body, ["transaction", "secret"]);
    const id = secret(body.transaction),
      transaction = this.store.get("transaction", id);
    requireValue(
      transaction && transaction.secretHash === hash(secret(body.secret)),
      "transaction_expired",
      401,
    );
    await verifyRequest(
      req.headers["asterius-proof"],
      this.origin,
      path,
      body,
      transaction.thumbprint,
      this.store,
    );
    return { id, transaction };
  }
  async handle(req, res) {
    try {
      const url = new URL(req.url, this.origin),
        path = url.pathname;
      requireValue(
        req.headers.host === new URL(this.origin).host,
        "untrusted_host",
        400,
      );
      if (req.method === "POST" && path === "/v1/transactions") {
        const data = await body(req);
        fields(data, ["cluster", "secret"]);
        identifier(data.cluster);
        secret(data.secret);
        this.upstream(data.cluster);
        // All state creation requires key possession, with replay rejection.
        const thumbprint = await verifyRequest(
            req.headers["asterius-proof"],
            this.origin,
            path,
            data,
            undefined,
            this.store,
          ),
          id = random();
        requireValue(
          this.store.db
            .prepare(
              "SELECT count(*) n FROM records WHERE kind='transaction' AND expires>?",
            )
            .get(now()).n < 1000,
          "broker_busy",
          429,
        );
        this.store.put("transaction", id, "created", now() + 300, {
          cluster: data.cluster,
          secretHash: hash(data.secret),
          thumbprint,
        });
        return reply(res, 201, {
          transaction: id,
          browserUrl: this.origin + "/login/" + id,
          expiresIn: 300,
        });
      }
      if (req.method === "GET" && path.startsWith("/login/")) {
        const id = secret(path.slice(7)),
          transaction = this.store.get("transaction", id);
        requireValue(transaction, "transaction_expired", 410);
        requireValue(
          this.store.claim("transaction", id, "created", "exchanging"),
          "transaction_already_started",
          409,
        );
        try {
          const flow = await this.upstream(transaction.cluster).begin(
              this.callback(transaction.cluster),
            ),
            browserSecret = random();
          requireValue(
            this.store.get("transaction", id)?.phase === "exchanging",
            "transaction_expired",
            401,
          );
          this.store.put(
            "transaction",
            id,
            "authorizing",
            transaction.expires,
            { ...transaction, ...flow, browserSecret },
          );
          this.store.put(
            "state",
            hash(flow.state),
            "active",
            transaction.expires,
            { transaction: id },
          );
          return reply(res, 303, "", "text/plain", {
            Location: flow.authorize,
            "Set-Cookie": `asterius_${id}=${browserSecret}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=300`,
          });
        } catch (error) {
          this.store.delete("transaction", id);
          throw error;
        }
      }
      if (req.method === "GET" && path.startsWith("/callback/")) {
        requireValue(
          [...url.searchParams.keys()].every((k) =>
            [
              "code",
              "state",
              "iss",
              "error",
              "error_description",
              "error_uri",
            ].includes(k),
          ) &&
            [...url.searchParams.keys()].every(
              (k) => url.searchParams.getAll(k).length === 1,
            ),
          "invalid_callback",
        );
        const state = secret(url.searchParams.get("state")),
          record = this.store.get("state", hash(state));
        requireValue(record, "invalid_state", 401);
        const id = record.transaction,
          transaction = this.store.get("transaction", id);
        requireValue(
          transaction && transaction.cluster === path.slice(10),
          "invalid_state",
          401,
        );
        req.browserSecret = transaction.browserSecret;
        requireValue(cookie(req, id), "browser_binding_failed", 401);
        requireValue(
          url.searchParams.get("iss") ===
            this.upstream(transaction.cluster).cluster.issuer,
          "issuer_mismatch",
          401,
        );
        requireValue(
          this.store.claim("transaction", id, "authorizing", "exchanging"),
          "callback_already_used",
          409,
        );
        this.store.delete("state", hash(state));
        if (url.searchParams.has("error")) {
          this.store.delete("transaction", id);
          return reply(
            res,
            400,
            html("Login cancelled", "Start a new login from your terminal."),
            "text/html",
          );
        }
        try {
          const tokens = await this.upstream(transaction.cluster).exchange(
              transaction,
              url.searchParams.get("code"),
              this.callback(transaction.cluster),
            ),
            confirmation = random();
          if (this.store.get("transaction", id)?.phase !== "exchanging") {
            await this.revoke({ ...transaction, ...tokens });
            throw new Failure("transaction_expired", 401);
          }
          this.store.put("transaction", id, "confirming", transaction.expires, {
            ...transaction,
            ...tokens,
            confirmation,
          });
          return reply(
            res,
            200,
            html(
              "Confirm Kubernetes login",
              `<p>Cluster: ${escapeHtml(transaction.cluster)}</p><p>Account subject: ${escapeHtml(tokens.subject)}</p><p>Terminal reference: ${escapeHtml(id.slice(0, 12))}</p><form method="post" action="/confirm/${id}"><input type="hidden" name="confirmation" value="${confirmation}"><button name="decision" value="approve">Approve this terminal</button><button name="decision" value="cancel">Cancel</button></form>`,
            ),
            "text/html",
          );
        } catch (error) {
          this.store.delete("transaction", id);
          throw error;
        }
      }
      if (req.method === "POST" && path.startsWith("/confirm/")) {
        const id = secret(path.slice(9)),
          transaction = this.store.get("transaction", id),
          form = await body(req, false);
        requireValue(
          transaction && transaction.phase === "confirming",
          "transaction_expired",
          410,
        );
        req.browserSecret = transaction.browserSecret;
        requireValue(
          req.headers.origin === this.origin &&
            cookie(req, id) &&
            form.getAll("confirmation").length === 1 &&
            form.get("confirmation") === transaction.confirmation,
          "browser_binding_failed",
          401,
        );
        requireValue(
          this.store.claim("transaction", id, "confirming", "confirmed"),
          "confirmation_already_used",
          409,
        );
        if (form.get("decision") !== "approve") {
          this.store.delete("transaction", id);
          await this.revoke(transaction);
          return reply(
            res,
            200,
            html("Login cancelled", "Return to your terminal."),
            "text/html",
          );
        }
        return reply(
          res,
          200,
          html(
            "Login approved",
            "Return to your terminal. Close this browser tab.",
          ),
          "text/html",
          {
            "Set-Cookie": `asterius_${id}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`,
          },
        );
      }
      if (req.method === "POST" && ["/v1/poll", "/v1/cancel"].includes(path)) {
        const data = await body(req),
          { id, transaction } = await this.transaction(data, path, req);
        if (path === "/v1/cancel") {
          this.store.delete("transaction", id);
          if (transaction.refreshToken) await this.revoke(transaction);
          return reply(res, 200, { cancelled: true });
        }
        if (transaction.phase !== "confirmed")
          return reply(res, 202, { pending: true });
        requireValue(
          this.store.claim("transaction", id, "confirmed", "delivered"),
          "result_already_collected",
          409,
        );
        if (transaction.expiration <= now() + 30) {
          this.store.delete("transaction", id);
          await this.revoke(transaction);
          throw new Failure("login_expired", 401);
        }
        const handle = random();
        this.store.put("session", hash(handle), "active", now() + 28800, {
          cluster: transaction.cluster,
          thumbprint: transaction.thumbprint,
          dpop: transaction.dpop,
          refreshToken: transaction.refreshToken,
          idToken: transaction.idToken,
          expiration: transaction.expiration,
          subject: transaction.subject,
          sid: transaction.sid,
          nonce: transaction.nonce,
          lastUsed: now(),
        });
        this.store.delete("transaction", id);
        return reply(res, 200, {
          handle,
          idToken: transaction.idToken,
          expiration: transaction.expiration,
          subject: transaction.subject,
        });
      }
      if (
        req.method === "POST" &&
        ["/v1/credential", "/v1/logout"].includes(path)
      ) {
        const data = await body(req),
          { id, session } = await this.session(data, path, req);
        if (path === "/v1/logout") {
          this.store.delete("session", id);
          await this.revoke(session);
          return reply(res, 200, { loggedOut: true });
        }
        const work = this.pending.get(id);
        if (work) return reply(res, 200, await work);
        if (session.phase !== "active")
          throw new Failure("session_expired", 401);
        if (session.expiration > now() + 30) {
          this.store.put("session", id, "active", session.expires, {
            ...session,
            lastUsed: now(),
          });
          return reply(res, 200, {
            idToken: session.idToken,
            expiration: session.expiration,
            subject: session.subject,
          });
        }
        requireValue(
          this.store.claim("session", id, "active", "refreshing"),
          "refresh_in_progress",
          409,
        );
        const refresh = (async () => {
          try {
            const tokens = await this.upstream(session.cluster).refresh(
              session,
            );
            if (this.store.get("session", id)?.phase !== "refreshing") {
              await this.revoke({ ...session, ...tokens });
              throw new Failure("session_expired", 401);
            }
            this.store.put("session", id, "active", session.expires, {
              ...session,
              ...tokens,
              sid: tokens.sid ?? session.sid,
              lastUsed: now(),
            });
            return {
              idToken: tokens.idToken,
              expiration: tokens.expiration,
              subject: tokens.subject,
            };
          } catch (error) {
            this.store.delete("session", id);
            await this.revoke(session);
            throw error;
          }
        })();
        this.pending.set(id, refresh);
        try {
          return reply(res, 200, await refresh);
        } finally {
          this.pending.delete(id);
        }
      }
      if (req.method === "POST" && path.startsWith("/backchannel/")) {
        const cluster = identifier(path.slice(13)),
          upstream = this.upstream(cluster),
          form = await body(req, false);
        let payload;
        try {
          ({ payload } = await jwtVerify(
            form.get("logout_token"),
            upstream.keySet,
            {
              algorithms: ["ES256"],
              issuer: upstream.cluster.issuer,
              audience: upstream.cluster.clientId,
              typ: "logout+jwt",
              requiredClaims: ["iat", "jti", "events"],
              maxTokenAge: 300,
            },
          ));
        } catch {
          throw new Failure("invalid_logout", 400);
        }
        requireValue(
          payload.nonce === undefined &&
            (typeof payload.sid === "string" ||
              typeof payload.sub === "string") &&
            payload.events?.[
              "http://schemas.openid.net/event/backchannel-logout"
            ] &&
            typeof payload.events[
              "http://schemas.openid.net/event/backchannel-logout"
            ] === "object" &&
            !Array.isArray(
              payload.events[
                "http://schemas.openid.net/event/backchannel-logout"
              ],
            ) &&
            Object.keys(
              payload.events[
                "http://schemas.openid.net/event/backchannel-logout"
              ],
            ).length === 0 &&
            typeof payload.jti === "string" &&
            payload.iat <= now() + 5,
          "invalid_logout",
        );
        if (
          this.store.useProof(
            hash("logout:" + cluster + ":" + payload.jti),
            now() + 300,
          )
        ) {
          for (const session of this.store.sessions())
            if (
              session.cluster === cluster &&
              (!payload.sid || session.sid === payload.sid) &&
              (!payload.sub || session.subject === payload.sub)
            )
              this.store.delete("session", session.id);
          for (const row of this.store.db
            .prepare("SELECT id FROM records WHERE kind='transaction'")
            .all()) {
            const transaction = this.store.get("transaction", row.id);
            if (transaction?.cluster === cluster)
              this.store.delete("transaction", row.id);
          }
        }
        return reply(res, 200, {});
      }
      throw new Failure("not_found", 404);
    } catch (error) {
      reply(res, error instanceof Failure ? error.status : 503, {
        error: error instanceof Failure ? error.code : "broker_unavailable",
      });
    }
  }
}
