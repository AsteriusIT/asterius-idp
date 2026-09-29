import { createContext, useCallback, useContext, useEffect, useId, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { SESSION_EXPIRED } from './api';
import { sameEditor } from './route-state';
import { ConfirmDialog } from './ui';

type Guard = { hasDraft: boolean; register: (id: string, dirty: boolean) => void; leave: (action: () => void) => void };
const Context = createContext<Guard>({ hasDraft: false, register: () => {}, leave: action => action() });

/** Drafts remain in component memory; only their dirty flags enter this registry. */
export function NavigationGuard({ children }: { children: ReactNode }) {
  const dirty = useRef(new Set<string>());
  const [hasDraft, setHasDraft] = useState(false);
  const [pending, setPending] = useState<(() => void) | null>(null);
  const register = useCallback((id: string, value: boolean) => {
    if (value) dirty.current.add(id); else dirty.current.delete(id);
    setHasDraft(dirty.current.size > 0);
  }, []);
  const leave = useCallback((action: () => void) => {
    if (dirty.current.size === 0) action(); else setPending(() => action);
  }, []);
  useEffect(() => {
    const unload = (event: BeforeUnloadEvent) => {
      if (dirty.current.size) event.preventDefault();
    };
    const click = (event: MouseEvent) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      const anchor = event.target instanceof Element ? event.target.closest('a') : null;
      if (!anchor || anchor.target === '_blank' || anchor.hasAttribute('download') || !dirty.current.size) return;
      const url = new URL(anchor.href);
      if (url.href === window.location.href || url.hash === '#content' || sameEditor(window.location.href, url.href)) return;
      event.preventDefault();
      event.stopPropagation();
      leave(() => window.location.assign(url.href));
    };
    let position = typeof window.history.state?.draftPosition === 'number' ? window.history.state.draftPosition : 0;
    window.history.replaceState({ ...window.history.state, draftPosition: position }, '');
    let restoring: (() => void) | null = null;
    const expired = () => { dirty.current.clear(); setHasDraft(false); setPending(null); };
    // Hash changes can also originate from browser Back or programmatic links.
    const hash = (event: HashChangeEvent) => {
      if (!event.oldURL || event.oldURL === event.newURL) return;
      if (restoring) {
        event.stopImmediatePropagation();
        const offer = restoring; restoring = null; offer(); return;
      }
      const target = typeof window.history.state?.draftPosition === 'number'
        ? window.history.state.draftPosition : position + 1;
      window.history.replaceState({ ...window.history.state, draftPosition: target }, '');
      if (!dirty.current.size || sameEditor(event.oldURL, event.newURL)) { position = target; return; }
      event.stopImmediatePropagation();
      const delta = target - position;
      if (delta === 0) return;
      // Restore the actual history entry, not merely its URL, so canceling Back
      // preserves both the draft and the browser's Back/Forward destinations.
      restoring = () => leave(() => window.history.go(delta));
      window.history.go(-delta);
    };
    window.addEventListener(SESSION_EXPIRED, expired);
    window.addEventListener('beforeunload', unload);
    document.addEventListener('click', click, true);
    window.addEventListener('hashchange', hash, true);
    return () => {
      window.removeEventListener(SESSION_EXPIRED, expired);
      window.removeEventListener('beforeunload', unload);
      document.removeEventListener('click', click, true);
      window.removeEventListener('hashchange', hash, true);
    };
  }, [leave]);
  return <Context.Provider value={{ hasDraft, register, leave }}>
    {children}
    {pending && <ConfirmDialog title="Discard unsaved changes?" body="Your changes have not been saved. Keep editing to save them, or discard them to continue." confirmLabel="Discard changes" cancelLabel="Keep editing" busy={false}
      onCancel={() => setPending(null)} onConfirm={() => {
        const action = pending; dirty.current.clear(); setHasDraft(false); setPending(null); action();
      }} />}
  </Context.Provider>;
}

export function useUnsavedChanges(dirty: boolean): (action: () => void) => void {
  const id = useId();
  const { register, leave } = useContext(Context);
  useEffect(() => { register(id, dirty); return () => register(id, false); }, [id, dirty, register]);
  return leave;
}

export function UnsavedNotice() {
  const { hasDraft } = useContext(Context);
  return hasDraft ? <p className="draft-notice" aria-live="polite">Unsaved work — save your changes before leaving this page.</p> : null;
}
