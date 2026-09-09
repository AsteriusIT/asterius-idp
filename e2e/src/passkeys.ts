/**
 * What a passkey ceremony needs that the rest of the sweep does not.
 *
 * Two things: a tenant whose issuer names a host, and an authenticator. Both
 * are arranged here so `tests/passkey-ceremony.spec.ts` reads as the ceremony
 * and nothing else.
 *
 * # The tenant, and why it is a second one
 *
 * `ast-kb0`. The RP ID is the issuer's host with the port removed, so the
 * sweep tenant — `https://127.0.0.1:{port}/t/e2e` — cannot run a ceremony at
 * all: an IP literal is not a domain and Chromium refuses before any
 * authenticator is consulted. The fixture answers with a second tenant on
 * `localhost` and leaves the first one exactly where it was, because the
 * reason it is on a literal (a name that may resolve to `::1` first is a way
 * for a run to fail for a reason unrelated to the code) still holds.
 *
 * That reason is answered rather than ignored, in two places. The browser is
 * pinned to the loopback by `--host-resolver-rules` in `playwright.config.ts`,
 * so the origin of the ceremony is a name that cannot go anywhere else. And
 * `scripts/browser-tests.sh` will not start the sweep until
 * `https://localhost:{port}/readyz` has answered, so a name resolving away
 * from the bound socket is a precondition failure with a sentence attached
 * rather than a browser timeout in an unrelated test.
 *
 * Addressing this tenant at `127.0.0.1` by path is not the way out, and it is
 * worth saying why: `tenancy::resolve` refuses a request whose `Host` is not
 * one the tenant answers to, because otherwise `https://anything/t/x/token`
 * would mint tokens claiming an issuer the request never reached. The name is
 * the tenant's address, for this harness exactly as for a browser.
 */
import type { APIRequestContext, CDPSession, Page } from '@playwright/test';
import { REDIRECT_URI, WEBAUTHN_BASE_URL } from './environment.js';
import { discover, pushAuthorizationRequest, registerClient } from './authorization.js';
import type { StartedFlow } from './flow.js';

/**
 * Starts an authorization request on the tenant a ceremony can run on.
 *
 * The same three steps as `flow.ts`, against the other origin: a tenant
 * routed by host is reached at its host and nowhere else, so there is nothing
 * to rewrite. Fresh per call, for the reason `flow.ts` gives — RFC 9126 §2.2
 * makes a `request_uri` single-use, so a reused one would test the replay path.
 */
export async function startWebauthnAuthorization(api: APIRequestContext): Promise<StartedFlow> {
  const discovery = await discover(api, WEBAUTHN_BASE_URL);
  const client = await registerClient(api, discovery, REDIRECT_URI);
  const state = `passkey-${crypto.randomUUID()}`;
  return {
    authorizationUrl: await pushAuthorizationRequest(api, discovery, client, state),
    state,
    redirectUri: REDIRECT_URI,
  };
}

/** One credential, as Chromium's virtual authenticator reports it. */
export interface VirtualCredential {
  readonly credentialId: string;
  readonly isResidentCredential: boolean;
  readonly rpId?: string;
  readonly signCount: number;
}

/** A virtual authenticator, for as long as the page that owns it lives. */
export interface VirtualAuthenticator {
  /** Everything it currently holds. */
  credentials(): Promise<VirtualCredential[]>;
  /**
   * Whether the device answers a ceremony as though somebody had touched it.
   *
   * The one control this spec needs, and it needs it because the login page
   * asks for conditional mediation as soon as it loads. With presence
   * simulated, *that* ceremony completes on its own and the sign-in happens
   * without the button ever being pressed — a pass, but for a path the test
   * did not choose, and a race with the click besides. Switching presence off
   * parks the autofill ceremony where it belongs (waiting for a user) so the
   * button press is unambiguously what signs in.
   */
  simulatePresence(on: boolean): Promise<void>;
  /** Detaches it, so a later navigation cannot silently keep using it. */
  remove(): Promise<void>;
}

/**
 * Plugs a virtual authenticator into a page, over CDP.
 *
 * It is deliberately the plainest platform authenticator that can satisfy this
 * server: `ctap2` with resident keys, because a username-less sign-in asks for
 * a discoverable credential and gets nothing from an authenticator that cannot
 * store one, and user verification because `relying_party()` sets `uv=required`
 * and an assertion that proved only presence is refused.
 *
 * The authenticator belongs to the DevTools session, which belongs to the page.
 * A second page is a second authenticator holding nothing — which is why the
 * spec proves persistence by navigating, not by opening another tab.
 */
export async function attachVirtualAuthenticator(page: Page): Promise<VirtualAuthenticator> {
  const session: CDPSession = await page.context().newCDPSession(page);
  await session.send('WebAuthn.enable');
  const { authenticatorId } = await session.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      // Nobody is going to touch this device, so it answers as though somebody
      // had. Without it every ceremony below would wait for a gesture that
      // cannot arrive and fail as a timeout.
      automaticPresenceSimulation: true,
    },
  });

  return {
    async credentials() {
      const { credentials } = await session.send('WebAuthn.getCredentials', { authenticatorId });
      return credentials as unknown as VirtualCredential[];
    },
    async simulatePresence(on: boolean) {
      await session.send('WebAuthn.setAutomaticPresenceSimulation', {
        authenticatorId,
        enabled: on,
      });
    },
    async remove() {
      await session.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
      await session.detach();
    },
  };
}
