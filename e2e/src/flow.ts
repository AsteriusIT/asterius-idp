/**
 * The steps every spec shares: get a browser to a login page, and stop the
 * authorization response from leaving the machine.
 */
import type { APIRequestContext, BrowserContext } from '@playwright/test';
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
export async function startAuthorization(api: APIRequestContext): Promise<StartedFlow> {
  const discovery = await discover(api, BASE_URL);
  const client = await registerClient(api, discovery, REDIRECT_URI);
  const state = `sweep-${crypto.randomUUID()}`;
  return {
    authorizationUrl: await pushAuthorizationRequest(api, discovery, client, state),
    state,
    redirectUri: REDIRECT_URI,
  };
}

/**
 * Answers for the client's callback, without a network.
 *
 * The redirect URI names a host that resolves nowhere on purpose, and this is
 * what makes the last hop observable: the browser really navigates, so the
 * `code` really travels through a `Location` header, and the test reads it from
 * the address bar rather than from a response body it fetched itself.
 */
export async function interceptCallback(context: BrowserContext): Promise<void> {
  const pattern = `${new URL(REDIRECT_URI).origin}/**`;
  await context.route(pattern, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'text/html; charset=utf-8',
      body: '<!doctype html><html lang="en"><head><title>client callback</title></head><body><p id="callback">back at the client</p></body></html>',
    });
  });
}
