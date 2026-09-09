/**
 * `response_mode=form_post`, which `ast-2vk.14` asks a browser to confirm
 * auto-submits without script.
 *
 * It cannot be confirmed yet, because nothing produces such a response. The
 * discovery document advertises `form_post` (`crates/oidc/src/metadata.rs`) and
 * the CSP seam for it exists (`Policy::with_form_post_to`, `ast-gxh.5`), but
 * `response_mode` is read nowhere in `crates/server` or `crates/oidc` outside
 * that metadata line: the authorization response is always a 303 with a query.
 * There is no URL at which a browser could be shown the page, so there is
 * nothing here to drive.
 *
 * Left as a `fixme` with the assertion spelled out rather than as a comment
 * somewhere: it is what the test should say the day the response mode lands,
 * and a named skip appears in every run instead of being forgotten.
 *
 * Worth writing down while it is fresh, because it is the counter-intuitive
 * part: a form cannot auto-submit without script. `<noscript>` cannot submit
 * anything, and there is no HTML attribute that does. A no-JS `form_post`
 * response is therefore a page with a real submit button the user presses,
 * plus — for the overwhelmingly common scripted case — a nonced inline script
 * that presses it for them. Which is to say `form_post` is the second page in
 * the tree that needs an entry in `SCRIPTED_TEMPLATES`, and the sweep should
 * assert both halves: that the button works with script disabled, and that the
 * script submits and provokes no violation with script enabled.
 */
import { test } from '../src/fixtures.js';

test.fixme(
  'a form_post response submits to the client, with and without script',
  async () => {},
);
