/**
 * The entry the server names in the document it renders.
 *
 * The mount point is written by the server template, not by a bundler's
 * `index.html`: there is no `index.html` in this build at all, because a
 * static one cannot carry the per-response CSP nonce (ADR-0009).
 *
 * # The nonce, and the one library that needs it (`ast-gore`)
 *
 * `style-src 'nonce-…'` refuses any `<style>` element that does not carry this
 * response's nonce. Almost nothing in this bundle creates one — React writes
 * inline styles through the CSSOM (`node.style.setProperty`), which `style-src`
 * does not govern, so Radix's positioned layers need nothing from us — but
 * `react-remove-scroll`, which is how Radix stops the page scrolling behind a
 * modal, injects one stylesheet the first time a dialog opens. It reads its
 * nonce from `get-nonce`, so this is where it is given one.
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
import { createRoot } from 'react-dom/client';
import { setNonce } from 'get-nonce';
import { App } from './App';
import { startTheme } from './theme';
// The tokens first, then Tailwind (whose theme maps onto them), then the
// console's own rules: Vite concatenates the entry's stylesheets in import
// order into the one hashed file the document links, and a rule that reads a
// custom property declared after it reads nothing.
import './tokens.css';
import './tailwind.css';
import './styles.css';

/** The id the entry document puts on its one script element. */
const ENTRY_SCRIPT_ID = 'console-entry';

const entry = document.getElementById(ENTRY_SCRIPT_ID);
const nonce = entry instanceof HTMLScriptElement ? (entry.nonce ?? '') : '';
if (nonce !== '') {
  setNonce(nonce);
}

// Before React renders, so a browser that remembered "dark" does not paint a
// light frame first.
startTheme();

const mount = document.getElementById('console');
if (mount) {
  createRoot(mount).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
