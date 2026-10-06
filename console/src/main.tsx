/**
 * The entry the server names in the document it renders.
 *
 * The mount point is written by the server template, not by a bundler's
 * `index.html`: there is no `index.html` in this build at all, because a
 * static one cannot carry the per-response CSP nonce (ADR-0009).
 *
 * # The nonce and Base UI
 *
 * Base UI's CSPProvider receives the entry document's nonce for runtime style
 * elements. Fonts and application CSS remain bundled same-origin assets.
 *
 * The nonce is taken from the entry script's **IDL** property rather than from
 * an attribute. A browser blanks the `nonce` *content attribute* after parsing
 * precisely so that an injection which can read the DOM cannot read the nonce
 * out of it (CSP Level 3 §5.2, "nonce hiding"), while `element.nonce` keeps
 * the value for script that is already running. Reading it this way is what
 * keeps that protection: nothing is added to the document that an attacker
 * could scrape.
 */
import { StrictMode } from 'react';
import { CSPProvider } from '@base-ui/react/csp-provider';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { NavigationGuard } from './navigation-guard';
import { startTheme } from './theme';
// The tokens first, then Tailwind (whose theme maps onto them), then the
// console's own rules: Vite concatenates the entry's stylesheets in import
// order into the one hashed file the document links, and a rule that reads a
// custom property declared after it reads nothing.
import './tokens.css';
import './fonts.css';
import './tailwind.css';
import './styles.css';
import './enterprise.css';

/** The id the entry document puts on its one script element. */
const ENTRY_SCRIPT_ID = 'console-entry';

const entry = document.getElementById(ENTRY_SCRIPT_ID);
const nonce = entry instanceof HTMLScriptElement ? (entry.nonce ?? '') : '';

// Menus can move focus on hover. Track input modality so those moves do not
// borrow a keyboard outline from the previously focused menu container.
const setInputMode = (mode: 'pointer' | 'keyboard') => {
  if (document.documentElement.dataset.consoleInputMode !== mode) {
    document.documentElement.dataset.consoleInputMode = mode;
  }
};
setInputMode('pointer');
document.addEventListener('pointerdown', () => setInputMode('pointer'), { capture: true, passive: true });
document.addEventListener('pointermove', () => setInputMode('pointer'), { capture: true, passive: true });
document.addEventListener('keydown', event => {
  if (!['Control', 'Alt', 'Meta', 'Shift'].includes(event.key)) setInputMode('keyboard');
}, true);

// Before React renders, so a browser that remembered "dark" does not paint a
// light frame first.
startTheme();

const mount = document.getElementById('console');
if (mount) {
  createRoot(mount).render(
    <StrictMode>
      <CSPProvider nonce={nonce}><NavigationGuard><App /></NavigationGuard></CSPProvider>
    </StrictMode>,
  );
}
