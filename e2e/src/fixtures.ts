/**
 * The `test` every spec here imports.
 *
 * It differs from Playwright's in one way that matters: a
 * Content-Security-Policy violation fails the test that provoked it, whether or
 * not the test thought to look. A sweep whose CSP assertion is a line somebody
 * has to remember to write is a sweep that stops covering the page added next
 * week.
 *
 * The opt-out exists for exactly one test — the negative proof, which has to
 * provoke a violation to show that provoking one fails.
 */
import { test as base } from '@playwright/test';
import { CspWatcher } from './csp.js';

interface Options {
  /** Set by the negative proof, and by nothing else. */
  allowCspViolations: boolean;
}

interface Fixtures {
  /** Everything the browser refused during this test. */
  csp: CspWatcher;
}

export const test = base.extend<Options & Fixtures>({
  allowCspViolations: [false, { option: true }],

  csp: [
    async ({ context, javaScriptEnabled, allowCspViolations }, use, testInfo) => {
      const watcher = await CspWatcher.attach(context, javaScriptEnabled !== false);
      await use(watcher);
      if (!allowCspViolations) {
        watcher.assertClean(testInfo.title);
      }
    },
    { auto: true },
  ],
});

export { expect } from '@playwright/test';
