/**
 * Two suites, because `ast-ndk.6` asks for both.
 *
 *  - **no-js**: JavaScript disabled at the browser, which is the property
 *    `crates/web/src/source_audit.rs` asserts from the source side. This is
 *    where the whole login → consent → redirect flow runs.
 *  - **js**: JavaScript enabled, which is the only configuration in which
 *    `script-src 'nonce-…' 'strict-dynamic'` is exercised at all, and the only
 *    one in which a page can observe `securitypolicyviolation` itself.
 *
 * Both run the CSP sweep and both run the negative proof, so a regression in
 * the gate is caught in whichever configuration it appears.
 *
 * No retries. A flaky browser test that passes on the second attempt is a
 * defect that has been hidden, and this suite exists to find the defects a
 * source-level assertion cannot see.
 */
import { defineConfig, devices } from '@playwright/test';
import { CALLBACK_HOST, WEBAUTHN_RP_ID } from './src/environment.js';

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  // One server, one database, one seeded user: parallel workers would race
  // each other's interactions rather than test anything.
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  timeout: 30_000,
  expect: { timeout: 5_000 },
  reporter: process.env.CI ? [['github'], ['list']] : [['list']],
  use: {
    // The server under test terminates TLS with a certificate generated for
    // this run. Trusting it is what lets the browser treat the origin as
    // secure, which is the precondition for a `__Host-` cookie existing at all.
    ignoreHTTPSErrors: true,
    launchOptions: {
      // The client's callback host resolves to the loopback and nowhere else.
      // The last hop is then a real cross-origin navigation the browser either
      // performs or refuses — which is the whole subject of `ast-jsq` — with no
      // way for a code to leave the machine. Interception cannot stand in for
      // it: Playwright is never offered the redirect hop of a form submission.
      //
      // The WebAuthn tenant's name is mapped for a different reason: it is a
      // real name the browser really connects to, and the server bound one
      // address. Pinning it is how `ast-kb0` answers the `::1`-first hazard
      // `e2e/fixtures/asterius.toml.in` names, rather than hoping for a
      // resolution order.
      args: [
        `--host-resolver-rules=MAP ${CALLBACK_HOST} 127.0.0.1,MAP ${WEBAUTHN_RP_ID} 127.0.0.1`,
      ],
    },
    trace: process.env.CI ? 'retain-on-failure' : 'off',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'no-js',
      use: { ...devices['Desktop Chrome'], javaScriptEnabled: false },
      // The passkey sign-in spec is about what the script does when it runs.
      // What it does when it does *not* run is asserted in `no-js-flow`, on
      // the same page, which is where that belongs: a browser without script
      // must see no passkey button at all.
      // The console spec is ignored here for the same reason: an admin console
      // *is* script, and what a browser without it sees is the `<noscript>`
      // block, which `crates/admin-api/src/console.rs` asserts from the
      // template side.
      // The key-rotation spec drives the console, so it belongs to the same
      // exclusion. The accessibility sweep is excluded for a different reason
      // (`ast-rna`): axe-core is itself script, injected into the page and run
      // there, so a browser that will not run script cannot analyse anything.
      testIgnore: [
        '**/passkey-signin.spec.ts',
        '**/passkey-ceremony.spec.ts',
        '**/console.spec.ts',
        '**/key-rotation.spec.ts',
        '**/accessibility.spec.ts',
      ],
    },
    {
      name: 'js',
      use: { ...devices['Desktop Chrome'], javaScriptEnabled: true },
      // The flow itself is the no-JS suite's subject. Running it again with
      // script enabled would assert the same server behaviour twice and double
      // the slowest job in the sweep.
      testIgnore: ['**/no-js-flow.spec.ts'],
    },
  ],
});
