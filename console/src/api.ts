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
    throw new ApiError(response.status, `${init.method ?? 'GET'} ${path} failed`);
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
