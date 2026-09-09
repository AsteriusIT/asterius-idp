/**
 * The steps every spec shares: get a browser to a login page.
 *
 * Nothing here fakes the client. The callback host resolves to the loopback
 * (`environment.ts`), so the authorization response cannot leave the machine
 * and the browser still has to perform the navigation for the test to see it.
 */
import type { APIRequestContext } from '@playwright/test';
import { BASE_URL, REDIRECT_URI } from './environment.js';
import { discover, pushAuthorizationRequest, registerClient } from './authorization.js';

/** What a started flow gave us, and what the assertions need back. */
export interface StartedFlow {
  /** Where to send the browser. */
  readonly authorizationUrl: string;
  /** The `state` the response must echo. */
  readonly state: string;
  /** The client's one registered callback. */
  readonly redirectUri: string;
}

/**
 * Registers a client, pushes a request, and returns the URL a browser opens.
 *
 * Fresh per test. Reusing one pushed request would mean the second test
 * exercised the replay path rather than the flow: RFC 9126 §2.2 makes a
 * `request_uri` single-use.
 */
export async function startAuthorization(
  api: APIRequestContext,
  responseMode?: string,
): Promise<StartedFlow> {
  const discovery = await discover(api, BASE_URL);
  const client = await registerClient(api, discovery, REDIRECT_URI);
  const state = `sweep-${crypto.randomUUID()}`;
  return {
    authorizationUrl: await pushAuthorizationRequest(api, discovery, client, state, responseMode),
    state,
    redirectUri: REDIRECT_URI,
  };
}
