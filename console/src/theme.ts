/**
 * Light, dark, and who chooses (`ast-gore` (2)).
 *
 * Until this bead the console followed `prefers-color-scheme`, so an
 * administrator whose operating system was dark got a dark console they had
 * never asked for and could not turn off. The browser's setting is now not
 * consulted at all:
 *
 *  - **light is the default**, for a first visit and for a browser that
 *    remembers nothing;
 *  - the toggle in the sidebar writes the choice to `localStorage`, so the
 *    second visit opens in the scheme the first one ended in;
 *  - the whole switch is the `dark` class on `<html>` (`tokens.css`), which is
 *    also what `@custom-variant dark` in `tailwind.css` reads.
 *
 * There is deliberately no "system" value. A third state that means "ask the
 * browser" is how the console got dark in the first place, and a setting with
 * three values where two are wanted is a setting somebody lands on by mistake.
 *
 * # Why `localStorage` and not the server
 *
 * A colour scheme is a property of *this browser*, not of the account: the
 * same administrator on a projector wants the light one. Storing it server-side
 * would also mean a new admin API call, and `ast-gore` changes no API.
 * A browser that refuses storage (private mode, a policy) still gets a working
 * toggle for the length of the visit — every write is guarded.
 */

/** The two schemes, and there is no third. */
export type Theme = 'light' | 'dark';

/** Where the choice is remembered. Namespaced, because the origin is shared. */
const STORAGE_KEY = 'asterius.console.theme';

/** What a first visit gets. */
export const DEFAULT_THEME: Theme = 'light';

/** The listeners of {@link subscribe}, called when the scheme changes. */
const listeners = new Set<() => void>();

let current: Theme = DEFAULT_THEME;

/** Reads the remembered choice, or the default when there is not one. */
function remembered(): Theme {
  try {
    return window.localStorage.getItem(STORAGE_KEY) === 'dark' ? 'dark' : DEFAULT_THEME;
  } catch {
    // A browser that refuses storage is a browser that gets the default.
    return DEFAULT_THEME;
  }
}

/** Puts the class where `tokens.css` and Tailwind's `dark:` both look for it. */
function paint(theme: Theme): void {
  document.documentElement.classList.toggle('dark', theme === 'dark');
}

/**
 * Applies the remembered scheme, once, as early as the bundle runs.
 *
 * Called from `main.tsx` before React renders, so that a dark browser does not
 * paint a light frame first.
 */
export function startTheme(): void {
  current = remembered();
  paint(current);
}

/** The scheme in force. */
export function themeNow(): Theme {
  return current;
}

/** Sets the scheme, remembers it, and tells everyone who is watching. */
export function setTheme(theme: Theme): void {
  current = theme;
  paint(theme);
  try {
    window.localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // Unremembered is still applied: the visit works, the next one starts light.
  }
  for (const listener of listeners) {
    listener();
  }
}

/** Subscribes to scheme changes, in the shape `useSyncExternalStore` wants. */
export function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}
