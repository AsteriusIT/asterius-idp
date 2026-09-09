/**
 * Collecting Content-Security-Policy violations from a real browser.
 *
 * `crates/web/src/source_audit.rs` proves that no template in the tree contains
 * a `<script>` it did not declare. That is a property of the source. Whether a
 * browser, holding the header we actually send, *refuses* something is a
 * property of the running system, and only a browser can report it.
 *
 * Two independent listeners, because neither is sufficient on its own:
 *
 *  - **Console messages.** Chromium logs every refusal ("Refused to load the
 *    script ... because it violates the following Content Security Policy
 *    directive") to the console, from the renderer rather than from page
 *    script. This is the only channel that works when JavaScript is disabled,
 *    which is the suite this repository cares most about.
 *  - **`securitypolicyviolation` events.** The specified channel, and the one
 *    that carries the structured detail (`violatedDirective`, `blockedURI`).
 *    It needs script to observe it, so it is attached only to the JS suite.
 *
 * A watcher is deliberately not silent about what it saw: `assertClean` prints
 * every violation, because "one page in the sweep broke" is useless without
 * knowing which page and which directive.
 */
import type { BrowserContext, ConsoleMessage, Page } from '@playwright/test';

/** One refusal, as the browser described it. */
export interface CspViolation {
  /** Where the browser was when it refused. */
  readonly url: string;
  /** How we heard about it. */
  readonly channel: 'console' | 'securitypolicyviolation';
  /** The directive that refused, when the channel carries one. */
  readonly directive?: string;
  /** What was refused, when the channel carries it. */
  readonly blocked?: string;
  /** The full text, for a failure message somebody has to read. */
  readonly detail: string;
}

/**
 * Chromium's wording for every CSP refusal. Matching on "Content Security
 * Policy" rather than on "Refused to" keeps report-only and directive-specific
 * phrasings in scope, and nothing else in this server's pages says it.
 */
const CONSOLE_PATTERN = /content security policy/i;

/** Whether a console message is a CSP refusal. */
export function isCspConsoleMessage(message: Pick<ConsoleMessage, 'type' | 'text'>): boolean {
  return message.type() === 'error' && CONSOLE_PATTERN.test(message.text());
}

/** The shape the in-page listener reports. */
interface ReportedViolation {
  readonly violatedDirective: string;
  readonly blockedURI: string;
  readonly documentURI: string;
  readonly sample: string;
}

/** Accumulates every violation a context reports, across every page in it. */
export class CspWatcher {
  private readonly violations: CspViolation[] = [];

  private constructor() {}

  /**
   * Starts watching a context.
   *
   * Attached to the *context* rather than to a page so that a navigation to a
   * new page, or a popup, cannot escape the sweep by being somewhere the
   * listener was never installed.
   */
  static async attach(context: BrowserContext, javaScriptEnabled: boolean): Promise<CspWatcher> {
    const watcher = new CspWatcher();

    const listen = (page: Page) => {
      page.on('console', (message) => {
        if (isCspConsoleMessage(message)) {
          watcher.violations.push({
            url: page.url(),
            channel: 'console',
            detail: message.text(),
          });
        }
      });
    };
    context.on('page', listen);
    context.pages().forEach(listen);

    if (javaScriptEnabled) {
      await context.exposeBinding(
        '__asteriusReportCspViolation',
        ({ page }, reported: ReportedViolation) => {
          watcher.violations.push({
            url: page.url(),
            channel: 'securitypolicyviolation',
            directive: reported.violatedDirective,
            blocked: reported.blockedURI,
            detail:
              `${reported.violatedDirective} refused ${reported.blockedURI}` +
              (reported.sample ? ` (sample: ${reported.sample})` : '') +
              ` on ${reported.documentURI}`,
          });
        },
      );
      // Injected through the DevTools protocol, so it runs before the document
      // and is not itself subject to the policy it is observing.
      await context.addInitScript(() => {
        document.addEventListener('securitypolicyviolation', (event) => {
          const report = (
            window as unknown as {
              __asteriusReportCspViolation?: (violation: ReportedViolation) => void;
            }
          ).__asteriusReportCspViolation;
          report?.({
            violatedDirective: event.violatedDirective,
            blockedURI: event.blockedURI,
            documentURI: event.documentURI,
            sample: event.sample,
          });
        });
      });
    }

    return watcher;
  }

  /** Everything seen so far. */
  reported(): readonly CspViolation[] {
    return this.violations;
  }

  /** Forgets what has been seen. Used by the negative proof. */
  reset(): void {
    this.violations.length = 0;
  }

  /**
   * Fails if the browser refused anything.
   *
   * Throws rather than using `expect` so that the same call is usable both as
   * the assertion of the sweep and as the subject of the negative proof, which
   * has to catch it.
   */
  assertClean(where: string): void {
    if (this.violations.length === 0) {
      return;
    }
    const lines = this.violations.map(
      (violation) => `  - [${violation.channel}] ${violation.url}: ${violation.detail}`,
    );
    throw new Error(
      `${this.violations.length} Content-Security-Policy violation(s) during ${where}:\n${lines.join('\n')}`,
    );
  }
}
