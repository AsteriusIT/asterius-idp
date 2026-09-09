/**
 * The entry the server names in the document it renders.
 *
 * The mount point is written by the server template, not by a bundler's
 * `index.html`: there is no `index.html` in this build at all, because a
 * static one cannot carry the per-response CSP nonce (ADR-0009).
 */
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import './styles.css';

const mount = document.getElementById('console');
if (mount) {
  createRoot(mount).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
