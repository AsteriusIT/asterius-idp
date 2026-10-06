import { useEffect, useState, type ReactNode } from 'react';
import { Combobox, ComboboxContent, ComboboxInput, ComboboxItem, ComboboxList } from './ui/combobox';
import { Button, Field } from '../ui';

export interface EntityOption { readonly id: string; readonly label: string; readonly description: string }
export interface EntityPage { readonly items: readonly EntityOption[]; readonly nextCursor: string | null }

/** Server search with explicit stable-ID selection; typing never commits a choice. */
export function EntityPicker({ label, value, query, onQueryChange, onChange, search, disabled = false, hint }: {
  label: string; value: EntityOption | null; query: string;
  onQueryChange: (query: string) => void; onChange: (value: EntityOption | null) => void;
  search: (query: string, cursor?: string) => Promise<EntityPage>; disabled?: boolean; hint?: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const [page, setPage] = useState<EntityPage>({ items: [], nextCursor: null });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [retry, setRetry] = useState(0);
  const [cursor, setCursor] = useState<string | undefined>();
  useEffect(() => {
    if (!open || disabled || value !== null) { setLoading(false); return; }
    let active = true;
    setLoading(true); setError(null);
    const timer = window.setTimeout(() => {
      search(query.trim(), cursor).then(result => {
        if (!active) return;
        setPage(previous => ({ items: cursor ? [...new Map([...previous.items, ...result.items].map(item => [item.id, item])).values()] : result.items, nextCursor: result.nextCursor }));
        setLoading(false);
      }, reason => {
        if (!active) return;
        setError(reason instanceof Error ? reason.message : 'The directory could not be searched.'); setLoading(false);
      });
    }, query ? 220 : 0);
    return () => { active = false; window.clearTimeout(timer); };
  }, [query, cursor, open, disabled, value, retry, search]);
  const editQuery = (next: string) => {
    onChange(null); onQueryChange(next); setCursor(undefined);
    setPage({ items: [], nextCursor: null }); setError(null); setLoading(true);
  };
  return <Field label={label} hint={hint}>
    {props => <Combobox modal={false} items={page.items} filter={null} value={value} inputValue={query}
      itemToStringLabel={(item: EntityOption) => item.label} itemToStringValue={(item: EntityOption) => item.id}
      isItemEqualToValue={(item: EntityOption, selected: EntityOption) => item.id === selected.id}
      disabled={disabled} open={open} onOpenChange={setOpen}
      onInputValueChange={(next, details) => { if (details.reason === 'input-change' || details.reason === 'clear-press') editQuery(next); }}
      onValueChange={(selected) => { onChange(selected); if (selected) { onQueryChange(selected.label); setOpen(false); } }}>
      <ComboboxInput {...props} onKeyDown={event => {
        if (event.key === 'Escape' && open) { event.stopPropagation(); setOpen(false); }
      }} autoComplete="off" placeholder="Search username or email" aria-busy={loading} />
      <ComboboxContent>
        <ComboboxList>{(item: EntityOption) => <ComboboxItem key={item.id} value={item}>
          <span className="entity-option-copy"><strong>{item.label}</strong><span>{item.description}</span><small>{item.id}</small></span>
        </ComboboxItem>}</ComboboxList>
        {loading && <p className="entity-picker-status" role="status">Searching users…</p>}
        {error && <div className="entity-picker-status" role="alert"><p>{error}</p><Button small onClick={() => setRetry(count => count + 1)}>Retry search</Button></div>}
        {!loading && !error && page.items.length === 0 && <p className="entity-picker-status" role="status">No matching users. Try another username or email.</p>}
        {!loading && !error && page.nextCursor && <Button small className="entity-picker-more" onClick={() => setCursor(page.nextCursor!)}>Load more matches</Button>}
      </ComboboxContent>
    </Combobox>}
  </Field>;
}
