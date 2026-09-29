import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode, type SetStateAction } from 'react';

const ViewMemory = createContext<Map<string, unknown> | null>(null);
/** Search terms stay in this authenticated shell's memory, never URLs or storage. */
export function ViewMemoryProvider({ children }: Readonly<{ children: ReactNode }>) {
  const values = useRef(new Map<string, unknown>());
  return <ViewMemory.Provider value={values.current}>{children}</ViewMemory.Provider>;
}
export function useViewState<T>(key: string, initial: T): [T, (next: SetStateAction<T>) => void] {
  const memory = useContext(ViewMemory);
  const [value, update] = useState<T>(() => memory?.has(key) ? memory.get(key) as T : initial);
  const set = useCallback((next: SetStateAction<T>) => update(current => {
    const resolved = typeof next === 'function' ? (next as (value: T) => T)(current) : next;
    memory?.set(key, resolved);
    return resolved;
  }), [key, memory]);
  return [value, set];
}
export function useListScroll(key: string, ready: boolean) {
  const memory = useContext(ViewMemory);
  useEffect(() => {
    if (!ready) return;
    const content = document.getElementById('content');
    if (!content) return;
    content.scrollTop = Number(memory?.get(`scroll:${key}`) ?? 0);
    const changed = () => memory?.set(`scroll:${key}`, content.scrollTop);
    content.addEventListener('scroll', changed);
    return () => content.removeEventListener('scroll', changed);
  }, [key, ready, memory]);
}
