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
