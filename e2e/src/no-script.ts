/**
 * The allowlist of pages that may need JavaScript, and the assertion that
 * every other page may not (`ast-ndk.4`).
 *
 * The product rule is that the pages work without JavaScript. The rule has
 * exactly three exceptions and each one is here, with the control a browser
 * that will not run script presses instead. `crates/web/src/source_audit.rs`
 * keeps the same list from the source side — one entry per template, with the
 * markup that still works when the script does not run — and this is its
 * browser-side half: the audit proves what the template *contains*, and only a
 * browser can prove what is left to press when the script is never fetched.
 *
 * Two properties, and they are not the same claim:
 *
 *  * a page outside the list that carries a `<script>` fails, whichever page it
 *    is and whoever added it — the no-JS project sweeps the reachable pages in
 *    `tests/no-js-allowlist.spec.ts` and calls this on each;
 *  * a page *on* the list still shows a real, enabled control with script off,
 *    so being on the list buys a script and never an excuse.
 *
 * Keep this list, `SCRIPTED_TEMPLATES` in the source audit, and the table in
 * `e2e/README.md` in step. A fourth scripted page is a decision, not a detail.
 */
import { expect, type Page } from '@playwright/test';

/** What being on the allowlist permits, and what it does not excuse. */
export interface ScriptedPage {
  /** How many `<script>` elements this page may carry. */
  readonly scripts: number;
  /** Why the page cannot be written without one. */
  readonly reason: string;
  /**
   * The control a browser with script off presses instead, as a selector.
   *
   * Per page rather than shared: the passkey page's answer is a link to the
   * password path and the form-post page's is its own submit button, and a
   * test that accepted either for both would pass for a passkey page that had
   * quietly lost its link.
   */
  readonly withoutScript: string;
}

/**
 * Every page this server serves that may carry a `<script>`.
 *
 * Keyed by the template in `crates/web/templates/`, so a reader can hold this
 * list and the source audit's side by side.
 */
export const SCRIPT_ALLOWLIST: Readonly<Record<string, ScriptedPage>> = {
  'login.html': {
    scripts: 1,
    reason:
      '`navigator.credentials.get()` is a JavaScript API, so a passkey sign-in — and the ' +
      'conditional mediation that offers one from the browser\'s own username dropdown — ' +
      'cannot be run from markup. The bootstrap is what reveals the passkey button, which ' +
      'stays hidden without it because it could do nothing on its own.',
    withoutScript: 'form button[type="submit"]',
  },
  'passkey.html': {
    scripts: 1,
    reason:
      '`navigator.credentials.create()` is a JavaScript API, so a WebAuthn registration ' +
      'ceremony cannot be run from markup. With scripting off the page shows no button, ' +
      'says why, and offers the password path.',
    withoutScript: 'a[href]',
  },
  'form_post.html': {
    scripts: 1,
    reason:
      'a form cannot submit itself: no HTML attribute does it and `<noscript>` renders ' +
      'rather than acts, so the auto-submission clients expect of `response_mode=form_post` ' +
      'is one inline line. The button under it is the same control, pressed by hand.',
    withoutScript: 'form#form-post button[type="submit"]',
  },
};

/**
 * Fails unless this page carries no more script than the allowlist permits.
 *
 * `template` is the file the page was rendered from. An unknown name is not an
 * error: it is the ordinary case, and the budget for it is zero.
 */
export async function expectWithinScriptAllowlist(page: Page, template: string): Promise<void> {
  const permitted = SCRIPT_ALLOWLIST[template]?.scripts ?? 0;
  expect(
    await page.locator('script').count(),
    permitted === 0
      ? `${template} carries a script and is not on the allowlist in e2e/src/no-script.ts. ` +
          'Pages must work without JavaScript; adding one to that list is a decision to ' +
          'record there, in crates/web/src/source_audit.rs and in e2e/README.md.'
      : `${template} carries more script than the allowlist permits`,
  ).toBe(permitted);
}

/**
 * Fails unless an allowlisted page still offers its scriptless control.
 *
 * For the no-JS project: with script enabled the bootstrap may have replaced
 * what it draws, and this is a claim about the browser that never ran it.
 */
export async function expectUsableWithoutScript(page: Page, template: string): Promise<void> {
  const entry = SCRIPT_ALLOWLIST[template];
  expect(entry, `${template} is not on the allowlist`).toBeDefined();
  await expect(
    page.locator(entry?.withoutScript ?? 'nothing').first(),
    `${template} shows nothing a browser without script can use`,
  ).toBeVisible();
}
