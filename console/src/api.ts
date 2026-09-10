/**
 * The one place the console talks to the server.
 *
 * Every request is same-origin and relative to the entry document, which is
 * always `…/admin/`: the console routes on the fragment (see `routes.ts`), so
 * the document URL never moves and a relative URL keeps whatever tenant prefix
 * the deployment is reached through. `connect-src 'self'` means nothing else
 * is reachable from here anyway — a third-party call is a CSP violation, not a
 * network request.
 */

/** Where the admin API sits, relative to the entry document. */
const API_BASE = 'api/v1/';

/** The header the synchroniser token travels in (`crates/admin-api/src/csrf.rs`). */
const CSRF_HEADER = 'X-CSRF-Token';

/**
 * The header a `POST` is made at-most-once by
 * (`crates/admin-api/src/idempotency.rs`).
 *
 * Required on every `POST` this API serves, not optional: the server refuses a
 * creation without one. `PUT` and `DELETE` are idempotent by their own
 * definition (RFC 9110 §9.2.2) and carry none.
 */
const IDEMPOTENCY_HEADER = 'Idempotency-Key';

/**
 * A fresh key for one attempt.
 *
 * `crypto.randomUUID` and not a counter or a timestamp: the key is what makes a
 * retried request run once, so two tabs of the same console must never produce
 * the same one. It is available on every browser this console supports, and
 * only over a secure context — which the console always is, being served by
 * this server.
 */
function idempotencyKey(): string {
  return crypto.randomUUID();
}

/** Who the session belongs to, as `GET /session` describes it. */
export interface Session {
  readonly tenant: string;
  readonly user: string;
  readonly roles: readonly string[];
  readonly csrf_token: string;
}

/** A refusal from the API, carrying the status the console has to act on. */
export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }

  /** Whether this is the "you are not signed in" refusal. */
  get isUnauthenticated(): boolean {
    return this.status === 401;
  }
}

/**
 * What the server said, when it says anything.
 *
 * The admin API answers a refusal with `{"error": {"code", "message"}}`
 * (`crates/admin-api/src/error.rs`), and the message is written for a person —
 * "rotate to replace it rather than retiring the key the tenant signs with" is
 * an instruction, and throwing it away in favour of "POST failed" would leave
 * an operator with a red box and no next step. Anything that is not that
 * envelope falls back to naming the request, because a body this console did
 * not recognise is not text to render.
 */
async function refusalMessage(response: Response, method: string, path: string): Promise<string> {
  const fallback = `${method} ${path} failed (${response.status})`;
  try {
    const body = (await response.json()) as { error?: { message?: unknown } };
    const message = body.error?.message;
    return typeof message === 'string' && message.length > 0 ? message : fallback;
  } catch {
    return fallback;
  }
}

async function request(path: string, init: RequestInit): Promise<unknown> {
  const response = await fetch(API_BASE + path, {
    ...init,
    // The session cookie is the credential. `same-origin` rather than
    // `include`: there is no other origin to send it to.
    credentials: 'same-origin',
    redirect: 'error',
    headers: { Accept: 'application/json', ...(init.headers ?? {}) },
  });

  if (!response.ok) {
    throw new ApiError(response.status, await refusalMessage(response, init.method ?? 'GET', path));
  }
  return (await response.json()) as unknown;
}

/** Reads a resource. */
export async function read(path: string): Promise<unknown> {
  return request(path, { method: 'GET' });
}

/**
 * Changes something.
 *
 * The token is required rather than optional, and the method is not: a
 * state-changing route refuses `GET` in the router itself (ADR-0009), so a
 * mutation that forgot its verb would be refused by the server as well as by
 * this signature.
 */
export async function mutate(
  path: string,
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE',
  session: Session,
  body?: unknown,
): Promise<unknown> {
  const headers: Record<string, string> = { [CSRF_HEADER]: session.csrf_token };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }
  if (method === 'POST') {
    headers[IDEMPOTENCY_HEADER] = idempotencyKey();
  }
  return request(path, {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

/** Who is signed in, or an {@link ApiError} with status 401 if nobody is. */
export async function loadSession(): Promise<Session> {
  const document = (await read('session')) as Session;
  return document;
}
