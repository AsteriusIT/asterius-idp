/**
 * What `scripts/browser-tests.sh` hands this suite.
 *
 * Every value has a default matching that script's own defaults, so a developer
 * who already has a server and a seeded tenant can run `npx playwright test`
 * directly. Nothing here invents a value the script does not also know: a
 * second source of truth for the port is how a harness starts passing against
 * the wrong server.
 */

/** Reads a variable, or its documented default. */
function fromEnv(name: string, fallback: string): string {
  const value = process.env[name];
  return value === undefined || value === '' ? fallback : value;
}

/** Where the server under test is listening, as the browser addresses it. */
export const BASE_URL = fromEnv('E2E_BASE_URL', 'https://127.0.0.1:9444');

/** The username seeded by `e2e/fixtures/seed.sql`. */
export const USERNAME = fromEnv('E2E_USERNAME', 'sweep@example.test');

/** Its password. A fixture credential, and only ever that. */
export const PASSWORD = fromEnv('E2E_PASSWORD', 'correct horse battery staple');

/**
 * The host the client's callback answers on.
 *
 * A `.test` name, which RFC 6761 §6.2 reserves and no resolver will ever
 * answer for, pointed at the loopback by the `--host-resolver-rules` argument
 * in `playwright.config.ts`. So the browser really performs the last hop over
 * the network — the assertion this suite exists for — while an authorization
 * code can never leave the machine, whatever else breaks.
 */
export const CALLBACK_HOST = fromEnv('E2E_CALLBACK_HOST', 'rp.example.test');

/**
 * Where the authorization response lands.
 *
 * Cross-origin from the server under test, and deliberately so: `form-action`
 * on the consent page governs the redirect that carries the code, and a
 * same-origin callback is exactly the case that passed while the flow was
 * broken for every real client (`ast-jsq`). The port is the server's, because
 * the resolver rule maps the name to the loopback: what answers there is the
 * server itself, with a 404. That is enough to be a callback — the assertion
 * is the URL the browser arrived at, not what was served at it.
 *
 * Not a Playwright `route`: interception is never offered the redirect hop of a
 * form submission, so a callback faked that way would report a DNS failure
 * where the browser was in fact willing to navigate.
 */
export const REDIRECT_URI = fromEnv(
  'E2E_REDIRECT_URI',
  `https://${CALLBACK_HOST}:${new URL(BASE_URL).port}/cb`,
);

/** The `__Host-` cookie the interaction endpoints set. */
export const INTERACTION_COOKIE = '__Host-asterius_ix';

/**
 * The WebAuthn tenant's origin, which is a *name* and not an address.
 *
 * `ast-kb0`: the RP ID this server derives is the issuer's host with the port
 * removed, and `127.0.0.1` is not a domain — Chromium refuses such a ceremony
 * before any authenticator is consulted. `e2e/fixtures/asterius.toml.in`
 * therefore carries a second tenant on `localhost`, which browsers accept as
 * an RP ID and which the run certificate already names in its SAN. The sweep
 * tenant keeps its literal, for the reason that fixture gives.
 *
 * The browser is pinned to the loopback for this name by
 * `--host-resolver-rules` in `playwright.config.ts`, and
 * `scripts/browser-tests.sh` refuses to start the sweep until this origin has
 * answered `/readyz` — so the `::1`-first hazard the fixture names is a
 * precondition with a sentence attached rather than a mystery. See
 * `passkeys.ts` for why addressing the tenant at `127.0.0.1` is not an option.
 */
export const WEBAUTHN_BASE_URL = fromEnv('E2E_WEBAUTHN_BASE_URL', 'https://localhost:9444');

/** The RP ID a credential registered on that tenant is scoped to. */
export const WEBAUTHN_RP_ID = new URL(WEBAUTHN_BASE_URL).hostname;
