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
 * Where the authorization response lands.
 *
 * A host that resolves nowhere, on purpose: the test intercepts it. A real host
 * would make the suite depend on the internet and would send an authorization
 * code to somebody else's server the first time the interception broke.
 */
export const REDIRECT_URI = fromEnv('E2E_REDIRECT_URI', 'https://rp.example.test/cb');

/** The `__Host-` cookie the interaction endpoints set. */
export const INTERACTION_COOKIE = '__Host-asterius_ix';
