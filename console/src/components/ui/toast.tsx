/**
 * Toasts, and why they are not Sonner (`ast-gore` (5)).
 *
 * shadcn's toast of choice is Sonner, and Sonner cannot be served under this
 * console's policy. It ships its stylesheet *inside its JavaScript* and
 * inserts it at import time:
 *
 * ```js
 * function __insertCSS(code) { … let style = document.createElement('style')
 *   head.appendChild(style); style.appendChild(document.createTextNode(code)) }
 * ```
 *
 * `style-src 'nonce-…'` (ADR-0009) refuses a `<style>` element that carries no
 * nonce, and the library offers no way to give it one. The measured result —
 * recorded in `docs/console/README.md` — is one CSP violation per load *and*
 * an unstyled toast, so the component would be both broken and noisy. The
 * alternative was widening `style-src` for the console's route, which is a
 * worse trade for a notification strip than writing the strip.
 *
 * So this is the strip: the same call shape a screen would have written
 * against Sonner (`toast.success('Saved')`), a stack drawn with the console's
 * own Tailwind classes, and nothing injected at runtime.
 *
 * # Why no toast carries a role
 *
 * The strip is one polite live region and the toasts inside it are ordinary
 * elements: `aria-live`, and deliberately **not** `role="status"` on each one.
 * That is `Skeleton`'s rule (`ui.tsx`) applied a second time, and the first
 * run of the sweep after this file was written is what proved it was the same
 * rule — `getByRole('status')` started matching two elements on every screen
 * that had just saved something, because the toast had become a second status
 * beside the one the screen meant. The role is what an automated reader
 * searches for to tell a saved change from a refused one; `aria-live` is the
 * part that does the announcing, and it is the part a toast needs.
 *
 * A refusal is therefore never *only* a toast: it is shown at the field or the
 * panel it belongs to, by `Message`, which does carry `role="alert"`.
 *
 * Nothing here dismisses itself while it is being read: the timer stops on
 * hover and on focus inside the strip (WCAG 2.2 §2.2.1), and every toast keeps
 * a dismiss button, so nothing depends on the timer at all.
 */
import { useCallback, useEffect, useRef, useSyncExternalStore } from 'react';
import type { JSX, ReactNode } from 'react';
import { CheckIcon, InfoIcon, TriangleAlertIcon, XIcon } from 'lucide-react';
import { cn } from '@/lib/utils';

/** What a toast is about; the same three tones the inline `Message` has. */
export type ToastTone = 'success' | 'error' | 'info';

/** One toast on screen. */
export interface Toast {
  readonly id: number;
  readonly tone: ToastTone;
  readonly title: string;
  readonly description?: string | undefined;
}

/** How long an undisturbed toast stays. Long enough to read two lines. */
const LIFETIME_MS = 6000;

let toasts: readonly Toast[] = [];
let nextId = 1;
const listeners = new Set<() => void>();

function publish(next: readonly Toast[]): void {
  toasts = next;
  for (const listener of listeners) {
    listener();
  }
}

function push(tone: ToastTone, title: string, description?: string): number {
  const id = nextId;
  nextId += 1;
  publish([...toasts, { id, tone, title, description }]);
  return id;
}

/** Removes one toast, whether it was dismissed or it expired. */
export function dismissToast(id: number): void {
  publish(toasts.filter((toast) => toast.id !== id));
}

/**
 * Raising a toast, in the shape a screen calls it.
 *
 * Deliberately not a hook: an outcome is raised from inside a promise
 * continuation, where the rules of hooks do not reach, and a screen that had
 * to thread a context through every handler would be a screen that stops
 * bothering.
 */
export const toast = {
  success: (title: string, description?: string): number => push('success', title, description),
  error: (title: string, description?: string): number => push('error', title, description),
  info: (title: string, description?: string): number => push('info', title, description),
};

/** For tests and for the shell: everything currently on screen. */
function snapshot(): readonly Toast[] {
  return toasts;
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** The strip itself. Mounted once, by the shell. */
export function Toaster(): JSX.Element {
  const items = useSyncExternalStore(subscribe, snapshot, snapshot);
  const paused = useRef(false);

  return (
    <div
      // One live region for the strip, and no role on it or on the toasts
      // inside it. See the module docs.
      aria-live="polite"
      className="pointer-events-none fixed inset-x-0 bottom-0 z-50 m-0 flex flex-col items-center gap-2 p-4 sm:inset-x-auto sm:right-0 sm:items-end"
      onMouseEnter={() => {
        paused.current = true;
      }}
      onMouseLeave={() => {
        paused.current = false;
      }}
      onFocusCapture={() => {
        paused.current = true;
      }}
      onBlurCapture={() => {
        paused.current = false;
      }}
    >
      {items.map((item) => (
        <ToastItem key={item.id} toast={item} paused={paused} />
      ))}
    </div>
  );
}

const MARKS: Record<ToastTone, ReactNode> = {
  success: <CheckIcon className="size-4 shrink-0" aria-hidden="true" />,
  error: <TriangleAlertIcon className="size-4 shrink-0" aria-hidden="true" />,
  info: <InfoIcon className="size-4 shrink-0" aria-hidden="true" />,
};

function ToastItem({
  toast: item,
  paused,
}: {
  toast: Toast;
  paused: { current: boolean };
}): JSX.Element {
  const close = useCallback(() => dismissToast(item.id), [item.id]);

  useEffect(() => {
    // A poll rather than a single timeout, so that hovering the strip stops
    // the clock instead of restarting it when the pointer leaves.
    let remaining = LIFETIME_MS;
    const step = 250;
    const timer = window.setInterval(() => {
      if (paused.current) {
        return;
      }
      remaining -= step;
      if (remaining <= 0) {
        window.clearInterval(timer);
        dismissToast(item.id);
      }
    }, step);
    return () => window.clearInterval(timer);
  }, [item.id, paused]);

  return (
    <div
      className={cn(
        'pointer-events-auto flex w-full max-w-sm items-start gap-3 rounded-lg border bg-popover p-3 text-popover-foreground shadow-lg',
        // The tone is a tinted left rule and a mark, never colour alone
        // (WCAG 2.2 §1.4.1).
        item.tone === 'success' && 'border-l-4 border-l-success',
        item.tone === 'error' && 'border-l-4 border-l-destructive',
        item.tone === 'info' && 'border-l-4 border-l-primary',
      )}
    >
      <span
        className={cn(
          'mt-0.5',
          item.tone === 'success' && 'text-success',
          item.tone === 'error' && 'text-destructive',
          item.tone === 'info' && 'text-primary',
        )}
      >
        {MARKS[item.tone]}
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium">{item.title}</p>
        {item.description !== undefined && (
          <p className="mt-0.5 text-sm break-words text-muted-foreground">{item.description}</p>
        )}
      </div>
      <button
        type="button"
        onClick={close}
        className="rounded-sm p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
      >
        <XIcon className="size-4" aria-hidden="true" />
        <span className="sr-only">Dismiss</span>
      </button>
    </div>
  );
}
